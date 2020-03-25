// SPDX-License-Identifier: GPL-2.0
/*
 * The Kyber I/O scheduler. Controls latency by throttling queue depths using
 * scalable techniques.
 *
 * Copyright (C) 2017 Facebook
 */

#include <linux/kernel.h>
#include <linux/blkdev.h>
#include <linux/blk-mq.h>
#include <linux/elevator.h>
#include <linux/module.h>
#include <linux/sbitmap.h>
#include <linux/blk-cgroup.h>

#include "blk.h"
#include "blk-mq.h"
#include "blk-mq-debugfs.h"
#include "blk-mq-sched.h"
#include "blk-mq-tag.h"

#define CREATE_TRACE_POINTS
#include <trace/events/kyber.h>

#define KYBER_MIN_WEIGHT		1
#define KYBER_MAX_WEIGHT		1000
#define KYBER_WEIGHT_LEGACY_DFL	100
#define KYBER_MAX_CGROUP		100
#define KYBER_REFILL_TIME		100//ms
#define KYBER_SCALE_FACTOR		16

/*
 * Scheduling domains: the device is divided into multiple domains based on the
 * request type.
 */
enum {
	KYBER_READ,
	KYBER_WRITE,
	KYBER_DISCARD,
	KYBER_OTHER,
	KYBER_NUM_DOMAINS,
};

static const char *kyber_domain_names[] = {
	[KYBER_READ] = "READ",
	[KYBER_WRITE] = "WRITE",
	[KYBER_DISCARD] = "DISCARD",
	[KYBER_OTHER] = "OTHER",
};

enum {
	/*
	 * In order to prevent starvation of synchronous requests by a flood of
	 * asynchronous requests, we reserve 25% of requests for synchronous
	 * operations.
	 */
	KYBER_ASYNC_PERCENT = 75,
};

/*
 * Maximum device-wide depth for each scheduling domain.
 *
 * Even for fast devices with lots of tags like NVMe, you can saturate the
 * device with only a fraction of the maximum possible queue depth. So, we cap
 * these to a reasonable value.
 */
static const unsigned int kyber_depth[] = {
	[KYBER_READ] = 256,
	[KYBER_WRITE] = 128,
	[KYBER_DISCARD] = 64,
	[KYBER_OTHER] = 16,
};

/*
 * Default latency targets for each scheduling domain.
 */
static const u64 kyber_latency_targets[] = {
	[KYBER_READ] = 2ULL * NSEC_PER_MSEC,
	[KYBER_WRITE] = 10ULL * NSEC_PER_MSEC,
	[KYBER_DISCARD] = 5ULL * NSEC_PER_SEC,
};

/*
 * Batch size (number of requests we'll dispatch in a row) for each scheduling
 * domain.
 */
static const unsigned int kyber_batch_size[] = {
	[KYBER_READ] = 16,
	[KYBER_WRITE] = 8,
	[KYBER_DISCARD] = 1,
	[KYBER_OTHER] = 1,
};

/*
 * Requests latencies are recorded in a histogram with buckets defined relative
 * to the target latency:
 *
 * <= 1/4 * target latency
 * <= 1/2 * target latency
 * <= 3/4 * target latency
 * <= target latency
 * <= 1 1/4 * target latency
 * <= 1 1/2 * target latency
 * <= 1 3/4 * target latency
 * > 1 3/4 * target latency
 */
enum {
	/*
	 * The width of the latency histogram buckets is
	 * 1 / (1 << KYBER_LATENCY_SHIFT) * target latency.
	 */
	KYBER_LATENCY_SHIFT = 2,
	/*
	 * The first (1 << KYBER_LATENCY_SHIFT) buckets are <= target latency,
	 * thus, "good".
	 */
	KYBER_GOOD_BUCKETS = 1 << KYBER_LATENCY_SHIFT,
	/* There are also (1 << KYBER_LATENCY_SHIFT) "bad" buckets. */
	KYBER_LATENCY_BUCKETS = 2 << KYBER_LATENCY_SHIFT,
};

/*
 * We measure both the total latency and the I/O latency (i.e., latency after
 * submitting to the device).
 */
enum {
	KYBER_TOTAL_LATENCY,
	KYBER_IO_LATENCY,
};

static const char *kyber_latency_type_names[] = {
	[KYBER_TOTAL_LATENCY] = "total",
	[KYBER_IO_LATENCY] = "I/O",
};

/*
 * Per-cpu latency histograms: total latency and I/O latency for each scheduling
 * domain except for KYBER_OTHER.
 */
struct kyber_cpu_latency {
	atomic_t buckets[KYBER_OTHER][2][KYBER_LATENCY_BUCKETS];
};

/*
 * There is a same mapping between ctx & hctx and kcq & khd,
 * we use request->mq_ctx->index_hw to index the kcq in khd.
 */
struct kyber_ctx_queue {
	/*
	 * Used to ensure operations on rq_list and kcq_map to be an atmoic one.
	 * Also protect the rqs on rq_list when merge.
	 */
	spinlock_t lock;
	struct list_head rq_list[KYBER_MAX_CGROUP][KYBER_NUM_DOMAINS];
} ____cacheline_aligned_in_smp;

struct kyber_fairness_data {
	struct blkcg_policy_data pd;
	unsigned int weight;
};

struct kyber_fairness {
	struct blkg_policy_data pd;
	unsigned int id;
	unsigned int weight;
	s64 next_budget;
	s64 cur_budget;
	bool idle;
	spinlock_t lock;
};

static LIST_HEAD(hctx_head);

struct kyber_fairness_global {
	struct hrtimer timer;
	struct request_queue *q;
	struct task_struct *timer_thread;
	struct kyber_fairness *kf_list[KYBER_MAX_CGROUP];
	atomic_t nr_kf;
	u64 wr_scale;
	u64 num_rq[KYBER_OTHER];
	u64 latency[KYBER_OTHER];
	u64 calc_lat[KYBER_OTHER][KYBER_LATENCY_BUCKETS];
	u64 last_refill_time;
	bool has_work;
};

struct kyber_queue_data {
	struct request_queue *q;

	/*
	 * Each scheduling domain has a limited number of in-flight requests
	 * device-wide, limited by these tokens.
	 */
	struct sbitmap_queue domain_tokens[KYBER_NUM_DOMAINS];

	/*
	 * Async request percentage, converted to per-word depth for
	 * sbitmap_get_shallow().
	 */
	unsigned int async_depth;

	struct kyber_cpu_latency __percpu *cpu_latency;

	/* Timer for stats aggregation and adjusting domain tokens. */
	struct timer_list timer;

	unsigned int latency_buckets[KYBER_OTHER][2][KYBER_LATENCY_BUCKETS];

	unsigned long latency_timeout[KYBER_OTHER];

	int domain_p99[KYBER_OTHER];

	/* Target latencies in nanoseconds. */
	u64 latency_targets[KYBER_OTHER];

	struct kyber_fairness_global *kfg;
};

struct kyber_hctx_data {
	spinlock_t lock;
	struct list_head rqs[KYBER_MAX_CGROUP][KYBER_NUM_DOMAINS];
	unsigned int cur_domain;
	unsigned int batching;
	struct kyber_ctx_queue *kcqs;
	struct sbitmap kcq_map[KYBER_MAX_CGROUP][KYBER_NUM_DOMAINS];
	struct sbq_wait domain_wait[KYBER_NUM_DOMAINS];
	struct sbq_wait_state *domain_ws[KYBER_NUM_DOMAINS];
	atomic_t wait_index[KYBER_NUM_DOMAINS];
	struct kyber_fairness *cur_kf;
};

static struct blkcg_policy blkcg_policy_kyber;

static struct kyber_fairness_data *cpd_to_kfd(struct blkcg_policy_data *cpd)
{
	return cpd ? container_of(cpd, struct kyber_fairness_data, pd) : NULL;
}

static struct kyber_fairness_data *blkcg_to_kfd(struct blkcg *blkcg)
{
	return cpd_to_kfd(blkcg_to_cpd(blkcg, &blkcg_policy_kyber));
}

static struct kyber_fairness *pd_to_kf(struct blkg_policy_data *pd)
{
	return pd ? container_of(pd, struct kyber_fairness, pd) : NULL;
}

struct blkcg_gq *kf_to_blkg(struct kyber_fairness *kf)
{
	return pd_to_blkg(&kf->pd);
}

static struct kyber_fairness *blkg_to_kf(struct blkcg_gq *blkg)
{
	return pd_to_kf(blkg_to_pd(blkg, &blkcg_policy_kyber));
}

static struct kyber_fairness *kf_from_rq(struct request *rq)
{
	if (!rq || !rq->bio)
		return NULL;

	return blkg_to_kf(rq->bio->bi_blkg);
}

static int bio_to_css_id(struct bio *bio)
{
	struct kyber_fairness *kf;

	if (!bio || !bio->bi_blkg)
		return 0;

	kf = blkg_to_kf(bio->bi_blkg);

	return kf ? kf->id : 0;
}

static int kyber_io_set_weight_legacy(struct cgroup_subsys_state *css,
		struct cftype *cftype,
		u64 val)
{
	struct blkcg *blkcg = css_to_blkcg(css);
	struct blkcg_gq *blkg;
	struct kyber_fairness_data *kfd = blkcg_to_kfd(blkcg);
	int ret = -ERANGE;

	if (val < KYBER_MIN_WEIGHT || val > KYBER_MAX_WEIGHT)
		return ret;

	ret = 0;

	spin_lock_irq(&blkcg->lock);
	kfd->weight = (unsigned int)val;
	hlist_for_each_entry(blkg, &blkcg->blkg_list, blkcg_node) {
		struct kyber_fairness *kf = blkg_to_kf(blkg);

		if (kf) {
			spin_lock(&kf->lock);
			kf->weight = kfd->weight;
			spin_unlock(&kf->lock);
		}
	}
	spin_unlock_irq(&blkcg->lock);

	return ret;
}

static ssize_t kyber_io_set_weight(struct kernfs_open_file *of,
		char *buf, size_t nbytes,
		loff_t off)
{
	u64 weight;
	/* First unsigned long found in the file is used */
	int ret = kstrtoull(strim(buf), 0, &weight);

	if (ret)
		return ret;

	ret = kyber_io_set_weight_legacy(of_css(of), NULL, weight);
	return ret ?: nbytes;
}

static int kyber_io_show_weight(struct seq_file *sf, void *v)
{
	struct blkcg *blkcg = css_to_blkcg(seq_css(sf));
	struct kyber_fairness_data *kfd = blkcg_to_kfd(blkcg);
	unsigned int val = 0;

	if (blkcg)
		val = kfd->weight;

	seq_printf(sf, "%u\n", val);

	return 0;
}

static struct cftype kyber_blkg_files[] = {
	{
		.name = "kyber.weight",
		.flags = CFTYPE_NOT_ON_ROOT,
		.seq_show = kyber_io_show_weight,
		.write = kyber_io_set_weight,
	},
	{} /* terminate */
};

static struct cftype kyber_blkcg_legacy_files[] = {
	{
		.name = "kyber.weight",
		.flags = CFTYPE_NOT_ON_ROOT,
		.seq_show = kyber_io_show_weight,
		.write_u64 = kyber_io_set_weight_legacy,
	},
	{} /* terminate */
};

static struct blkcg_policy_data *kyber_cpd_alloc(gfp_t gfp)
{
	struct kyber_fairness_data *kfd;

	kfd = kzalloc(sizeof(*kfd), gfp);
	if (!kfd)
		return NULL;

	return &kfd->pd;
}

static void kyber_cpd_init(struct blkcg_policy_data *cpd)
{
	struct kyber_fairness_data *kfd = cpd_to_kfd(cpd);

	kfd->weight = cgroup_subsys_on_dfl(io_cgrp_subsys) ?
		CGROUP_WEIGHT_DFL : KYBER_WEIGHT_LEGACY_DFL;
}

static void kyber_cpd_free(struct blkcg_policy_data *cpd)
{
	kfree(cpd_to_kfd(cpd));
}

static struct blkg_policy_data *kyber_pd_alloc(gfp_t gfp, int node)
{
	struct kyber_fairness *kf;

	kf = kzalloc_node(sizeof(*kf), gfp, node);
	if (!kf)
		return NULL;

	return &kf->pd;	
}

static void kyber_pd_init(struct blkg_policy_data *pd)
{
	struct blkcg_gq *blkg = pd_to_blkg(pd);
	struct kyber_fairness_data *kfd = blkcg_to_kfd(blkg->blkcg);
	struct kyber_queue_data *kqd = blkg->q->elevator->elevator_data;
	struct kyber_fairness_global *kfg = kqd->kfg;
	struct kyber_fairness *kf = pd_to_kf(pd);

	kf->weight = kfd->weight;
	kf->next_budget = kfd->weight * KYBER_SCALE_FACTOR;
	kf->cur_budget = kf->next_budget;

	kf->id = atomic_inc_return(&kfg->nr_kf);
	kfg->kf_list[kf->id] = kf;
	kf->idle = true;
	spin_lock_init(&kf->lock);
}

struct flush_kcq_data {
	struct kyber_hctx_data *khd;
	unsigned int sched_id;
	unsigned int sched_domain;
	struct list_head *list;
};

static bool flush_busy_kcq(struct sbitmap *sb, unsigned int bitnr, void *data)
{
	struct flush_kcq_data *flush_data = data;
	struct kyber_ctx_queue *kcq = &flush_data->khd->kcqs[bitnr];

	spin_lock(&kcq->lock);
	list_splice_tail_init(&kcq->rq_list[flush_data->sched_id][flush_data->sched_domain],
			flush_data->list);
	sbitmap_clear_bit(sb, bitnr);
	spin_unlock(&kcq->lock);

	return true;
}

static void kyber_flush_busy_kcqs(struct kyber_hctx_data *khd,
		unsigned int sched_id,
		unsigned int sched_domain,
		struct list_head *list)
{
	struct flush_kcq_data data = {
		.khd = khd,
		.sched_id = sched_id,
		.sched_domain = sched_domain,
		.list = list,
	};

	sbitmap_for_each_set(&khd->kcq_map[sched_id][sched_domain],
			flush_busy_kcq, &data);
}

static void kyber_pd_free(struct blkg_policy_data *pd)
{
	struct blkcg_gq *blkg = pd_to_blkg(pd);
	struct kyber_queue_data *kqd;
	struct kyber_fairness *kf;
	struct blk_mq_hw_ctx *hctx;
	struct kyber_hctx_data *khd;
	struct list_head *rqs;
	unsigned int sched_domain, i;

	if (!blkg)
		goto out;

	kqd = blkg->q->elevator->elevator_data;
	if (!kqd)
		goto out;

	kf = blkg_to_kf(blkg);

	queue_for_each_hw_ctx(blkg->q, hctx, i) {
		khd = hctx->sched_data;
		if (khd) {
			spin_lock(&khd->lock);
			for (sched_domain = 0; 
				 sched_domain < KYBER_OTHER; 
				 sched_domain++) {
				rqs = &khd->rqs[kf->id][sched_domain];
				kyber_flush_busy_kcqs(khd, kf->id, sched_domain, rqs);
				list_splice_tail_init(&khd->rqs[kf->id][sched_domain],
						&khd->rqs[0][sched_domain]);
			}
			spin_unlock(&khd->lock);
		}
	}

	atomic_dec(&kqd->kfg->nr_kf);
out:
	kfree(pd_to_kf(pd));
}

static struct blkcg_policy blkcg_policy_kyber = {
	.dfl_cftypes		= kyber_blkg_files,
	.legacy_cftypes		= kyber_blkcg_legacy_files,

	.cpd_alloc_fn		= kyber_cpd_alloc,
	.cpd_init_fn		= kyber_cpd_init,
	.cpd_free_fn		= kyber_cpd_free,

	.pd_alloc_fn		= kyber_pd_alloc,
	.pd_init_fn			= kyber_pd_init,
	.pd_free_fn			= kyber_pd_free,
};

static unsigned int kyber_sched_domain(unsigned int op)
{
	switch (op & REQ_OP_MASK) {
		case REQ_OP_READ:
			return KYBER_READ;
		case REQ_OP_WRITE:
			return KYBER_WRITE;
		case REQ_OP_DISCARD:
			return KYBER_DISCARD;
		default:
			return KYBER_OTHER;
	}
}

static void flush_latency_buckets(struct kyber_queue_data *kqd,
		struct kyber_cpu_latency *cpu_latency,
		unsigned int sched_domain, unsigned int type)
{
	unsigned int *buckets = kqd->latency_buckets[sched_domain][type];
	atomic_t *cpu_buckets = cpu_latency->buckets[sched_domain][type];
	unsigned int bucket;

	for (bucket = 0; bucket < KYBER_LATENCY_BUCKETS; bucket++)
		buckets[bucket] += atomic_xchg(&cpu_buckets[bucket], 0);
}

/*
 * Calculate the histogram bucket with the given percentile rank, or -1 if there
 * aren't enough samples yet.
 */
static int calculate_percentile(struct kyber_queue_data *kqd,
		unsigned int sched_domain, unsigned int type,
		unsigned int percentile)
{
	struct kyber_fairness_global *kfg = kqd->kfg;
	unsigned int *buckets = kqd->latency_buckets[sched_domain][type];
	unsigned int bucket, samples = 0, percentile_samples;
	u64 cur_latency = 0;

	for (bucket = 0; bucket < KYBER_LATENCY_BUCKETS; bucket++) {
		samples += buckets[bucket];
		if (type == KYBER_TOTAL_LATENCY) {
			cur_latency += 
				buckets[bucket] * kfg->calc_lat[sched_domain][bucket];
		}
	}

	kfg->num_rq[sched_domain] = samples ? samples : 1;

	if (!samples)
		return -1;

	if (type == KYBER_TOTAL_LATENCY)
		kfg->latency[sched_domain] = cur_latency;

	/*
	 * We do the calculation once we have 500 samples or one second passes
	 * since the first sample was recorded, whichever comes first.
	 */
	if (!kqd->latency_timeout[sched_domain])
		kqd->latency_timeout[sched_domain] = max(jiffies + HZ, 1UL);
	if (samples < 500 &&
			time_is_after_jiffies(kqd->latency_timeout[sched_domain])) {
		return -1;
	}
	kqd->latency_timeout[sched_domain] = 0;

	percentile_samples = DIV_ROUND_UP(samples * percentile, 100);
	for (bucket = 0; bucket < KYBER_LATENCY_BUCKETS - 1; bucket++) {
		if (buckets[bucket] >= percentile_samples)
			break;
		percentile_samples -= buckets[bucket];
	}
	memset(buckets, 0, sizeof(kqd->latency_buckets[sched_domain][type]));

	trace_kyber_latency(kqd->q, kyber_domain_names[sched_domain],
			kyber_latency_type_names[type], percentile,
			bucket + 1, 1 << KYBER_LATENCY_SHIFT, samples);

	return bucket;
}

static void kyber_resize_domain(struct kyber_queue_data *kqd,
		unsigned int sched_domain, unsigned int depth)
{
	depth = clamp(depth, 1U, kyber_depth[sched_domain]);
	if (depth != kqd->domain_tokens[sched_domain].sb.depth) {
		sbitmap_queue_resize(&kqd->domain_tokens[sched_domain], depth);
		trace_kyber_adjust(kqd->q, kyber_domain_names[sched_domain],
				depth);
	}
}

static void kyber_timer_fn(struct timer_list *t)
{
	struct kyber_queue_data *kqd = from_timer(kqd, t, timer);
	struct kyber_fairness_global *kfg = kqd->kfg;
	unsigned int sched_domain;
	int cpu;
	bool bad = false;

	/* Sum all of the per-cpu latency histograms. */
	for_each_online_cpu(cpu) {
		struct kyber_cpu_latency *cpu_latency;

		cpu_latency = per_cpu_ptr(kqd->cpu_latency, cpu);
		for (sched_domain = 0; sched_domain < KYBER_OTHER; sched_domain++) {
			flush_latency_buckets(kqd, cpu_latency, sched_domain,
					KYBER_TOTAL_LATENCY);
			flush_latency_buckets(kqd, cpu_latency, sched_domain,
					KYBER_IO_LATENCY);
		}
	}

	/*
	 * Check if any domains have a high I/O latency, which might indicate
	 * congestion in the device. Note that we use the p90; we don't want to
	 * be too sensitive to outliers here.
	 */
	for (sched_domain = 0; sched_domain < KYBER_OTHER; sched_domain++) {
		int p90;

		p90 = calculate_percentile(kqd, sched_domain, KYBER_IO_LATENCY,
				90);
		if (p90 >= KYBER_GOOD_BUCKETS)
			bad = true;
	}

	/*
	 * Adjust the scheduling domain depths. If we determined that there was
	 * congestion, we throttle all domains with good latencies. Either way,
	 * we ease up on throttling domains with bad latencies.
	 */
	for (sched_domain = 0; sched_domain < KYBER_OTHER; sched_domain++) {
		unsigned int orig_depth, depth;
		int p99;

		p99 = calculate_percentile(kqd, sched_domain,
				KYBER_TOTAL_LATENCY, 99);
		/*
		 * This is kind of subtle: different domains will not
		 * necessarily have enough samples to calculate the latency
		 * percentiles during the same window, so we have to remember
		 * the p99 for the next time we observe congestion; once we do,
		 * we don't want to throttle again until we get more data, so we
		 * reset it to -1.
		 */
		if (bad) {
			if (p99 < 0)
				p99 = kqd->domain_p99[sched_domain];
			kqd->domain_p99[sched_domain] = -1;
		} else if (p99 >= 0) {
			kqd->domain_p99[sched_domain] = p99;
		}
		if (p99 < 0)
			continue;

		/*
		 * If this domain has bad latency, throttle less. Otherwise,
		 * throttle more iff we determined that there is congestion.
		 *
		 * The new depth is scaled linearly with the p99 latency vs the
		 * latency target. E.g., if the p99 is 3/4 of the target, then
		 * we throttle down to 3/4 of the current depth, and if the p99
		 * is 2x the target, then we double the depth.
		 */
		if (bad || p99 >= KYBER_GOOD_BUCKETS) {
			orig_depth = kqd->domain_tokens[sched_domain].sb.depth;
			depth = (orig_depth * (p99 + 1)) >> KYBER_LATENCY_SHIFT;
			kyber_resize_domain(kqd, sched_domain, depth);
		}
	}

	if (!kfg->latency[KYBER_WRITE] || !kfg->latency[KYBER_READ])
		return;

	kfg->wr_scale = div64_u64(kfg->latency[KYBER_WRITE] * kfg->num_rq[KYBER_READ]
							, kfg->latency[KYBER_READ] * kfg->num_rq[KYBER_WRITE]);
}

static unsigned int kyber_sched_tags_shift(struct request_queue *q)
{
	/*
	 * All of the hardware queues have the same depth, so we can just grab
	 * the shift of the first one.
	 */
	return q->queue_hw_ctx[0]->sched_tags->bitmap_tags.sb.shift;
}

static void kyber_kf_lookup_create(struct request_queue *q)
{
	struct kyber_queue_data *kqd = q->elevator->elevator_data;
	struct kyber_fairness_global *kfg = kqd->kfg;
	struct cgroup_subsys_state *css;
	struct blkcg *blkcg;
	struct blkcg_gq *blkg;
	int id = atomic_read(&kfg->nr_kf);

	rcu_read_lock();
	while (1) {
		css = css_from_id(id, &io_cgrp_subsys);	
		if (!css)
			break;

		blkcg = css_to_blkcg(css);
		blkg = blkg_lookup_create(blkcg, q);
		id++;
	}
	rcu_read_unlock();
}

static struct kyber_fairness *kf_from_list(struct request_queue *q,
		unsigned int id)
{
	struct kyber_queue_data *kqd = q->elevator->elevator_data;
	struct kyber_fairness_global *kfg = kqd->kfg;

	if (!kfg->kf_list[id])
		kyber_kf_lookup_create(q);

	return kfg->kf_list[id];
}

static void kyber_refill_budget(struct request_queue *q)
{
	struct kyber_queue_data *kqd = q->elevator->elevator_data;
	struct kyber_fairness_global *kfg = kqd->kfg;
	struct kyber_fairness *kf;
	u64 spend_time, temp, used = 0, remainder = 0;
	unsigned int active_weight = 0;
	int id, shortened = -1;

	for (id = 0; id <= atomic_read(&kfg->nr_kf); id++) {
		kf = kf_from_list(q, id);

		spin_lock(&kf->lock);
		if (kf->cur_budget != kf->next_budget) {
			used += kf->next_budget - kf->cur_budget;
			if (kf->cur_budget > 0)
				remainder += kf->cur_budget;
			active_weight += kf->weight;
		} else {
			kf->idle = true;
			kf->next_budget = kf->weight * KYBER_SCALE_FACTOR;
			kf->cur_budget = kf->next_budget;
		}
		spin_unlock(&kf->lock);
	}

	if (used) {
		spend_time = ktime_get_ns() - kfg->last_refill_time;
		while (spend_time < KYBER_REFILL_TIME * NSEC_PER_MSEC) {
			spend_time += (10 * NSEC_PER_MSEC);
			shortened++;
		}

		if (shortened < 10) {
			temp = used * KYBER_REFILL_TIME;
			used = div64_u64(temp, KYBER_REFILL_TIME - (10 * shortened));
		} else {
			used *= 10;
		}

		if (used > remainder)
			used -= remainder;
			
		for (id = 0; id <= atomic_read(&kfg->nr_kf); id++) {
			kf = kf_from_list(q, id);

			spin_lock(&kf->lock);
			if (!kf->idle) {
				kf->next_budget = div_u64(used * kf->weight, active_weight);
				kf->cur_budget += kf->next_budget;
				kf->next_budget = kf->cur_budget;
			}
			spin_unlock(&kf->lock);
		}
	}

	kfg->last_refill_time = ktime_get_ns();

	if (kfg->has_work) {
		kfg->has_work = false;
		blk_mq_run_hw_queues(q, true);
	}
}

static int kyber_refill_thread_fn(void *arg)
{
	struct kyber_fairness_global *kfg = arg;

	while (!kthread_should_stop()) {
		kyber_refill_budget(kfg->q);
		set_current_state(TASK_INTERRUPTIBLE);
		io_schedule();
	}

	return 0;
}

static enum hrtimer_restart kyber_refill_fn(struct hrtimer *timer)
{
	struct kyber_fairness_global *kfg = 
		container_of(timer, struct kyber_fairness_global, timer);
	ktime_t ktime = ktime_set(0, KYBER_REFILL_TIME * NSEC_PER_MSEC);

	wake_up_process(kfg->timer_thread);

	hrtimer_start(&kfg->timer, ktime, HRTIMER_MODE_REL);
	return HRTIMER_NORESTART;
}

static struct kyber_queue_data *kyber_queue_data_alloc(struct request_queue *q)
{
	struct kyber_queue_data *kqd;
	unsigned int shift;
	int ret = -ENOMEM;
	int i;

	kqd = kzalloc_node(sizeof(*kqd), GFP_KERNEL, q->node);
	if (!kqd)
		goto err;

	kqd->q = q;

	kqd->cpu_latency = alloc_percpu_gfp(struct kyber_cpu_latency,
			GFP_KERNEL | __GFP_ZERO);
	if (!kqd->cpu_latency)
		goto err_kqd;

	timer_setup(&kqd->timer, kyber_timer_fn, 0);

	for (i = 0; i < KYBER_NUM_DOMAINS; i++) {
		WARN_ON(!kyber_depth[i]);
		WARN_ON(!kyber_batch_size[i]);
		ret = sbitmap_queue_init_node(&kqd->domain_tokens[i],
				kyber_depth[i], -1, false,
				GFP_KERNEL, q->node);
		if (ret) {
			while (--i >= 0)
				sbitmap_queue_free(&kqd->domain_tokens[i]);
			goto err_buckets;
		}
	}

	for (i = 0; i < KYBER_OTHER; i++) {
		kqd->domain_p99[i] = -1;
		kqd->latency_targets[i] = kyber_latency_targets[i];
	}

	shift = kyber_sched_tags_shift(q);
	kqd->async_depth = (1U << shift) * KYBER_ASYNC_PERCENT / 100U;

	return kqd;

err_buckets:
	free_percpu(kqd->cpu_latency);
err_kqd:
	kfree(kqd);
err:
	return ERR_PTR(ret);
}

static struct kyber_fairness_global *kyber_fairness_global_init
		(struct kyber_queue_data *kqd)
{
	struct kyber_fairness_global *kfg;
	struct kyber_fairness *kf;
	struct request_queue *q = kqd->q;
	int bucket, sched_domain;

	kfg = kmalloc_node(sizeof(*kfg), GFP_KERNEL, q->node);
	kfg->q = q;
	atomic_set(&kfg->nr_kf, 0);
	kfg->wr_scale = 2;
	kfg->latency[KYBER_READ] = 1;
	kfg->latency[KYBER_WRITE] = 2;
	kfg->num_rq[KYBER_READ] = 1;
	kfg->num_rq[KYBER_WRITE] = 1;

	for (sched_domain = 0; sched_domain < KYBER_OTHER; sched_domain++) {
		for (bucket = 0; bucket < KYBER_LATENCY_BUCKETS; bucket++) {
			switch (bucket) {
				case 0:
				case 1:
					kfg->calc_lat[sched_domain][bucket] = 
						kqd->latency_targets[sched_domain] >> (2 - bucket);
					break;
				case 2:
					kfg->calc_lat[sched_domain][bucket] = 
						kfg->calc_lat[sched_domain][0] + 
						kfg->calc_lat[sched_domain][1];
					break;
				case 3:
					kfg->calc_lat[sched_domain][bucket] = 
						kqd->latency_targets[sched_domain];
					break;
				case 4:
				case 5:
				case 6:
				case 7:
					kfg->calc_lat[sched_domain][bucket] = 
						kqd->latency_targets[sched_domain] + 
						kfg->calc_lat[sched_domain][bucket-4];
					break;
				default:
					break;
			}
		}
	}

	kfg->last_refill_time = ktime_get_ns();
	kfg->has_work = false;

	hrtimer_init(&kfg->timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
	kfg->timer.function = kyber_refill_fn;

	kf = kzalloc_node(sizeof(*kf), GFP_KERNEL, q->node);

	kf->weight = 100;
	kf->next_budget = kf->weight * KYBER_SCALE_FACTOR;
	kf->cur_budget = kf->next_budget;
	kf->id = 0;
	kf->idle = true;
	spin_lock_init(&kf->lock);

	kfg->kf_list[0] = kf;

	kqd->kfg = kfg;

	return kfg;
}

static int kyber_init_sched(struct request_queue *q, struct elevator_type *e)
{
	struct kyber_queue_data *kqd;
	struct kyber_fairness_global *kfg;
	struct elevator_queue *eq;
	ktime_t ktime = ktime_set(0, KYBER_REFILL_TIME * NSEC_PER_MSEC);
	int ret;

	eq = elevator_alloc(q, e);
	if (!eq)
		return -ENOMEM;

	kqd = kyber_queue_data_alloc(q);
	if (IS_ERR(kqd)) {
		kobject_put(&eq->kobj);
		return PTR_ERR(kqd);
	}

	kfg = kyber_fairness_global_init(kqd);

	blk_stat_enable_accounting(q);

	eq->elevator_data = kqd;
	q->elevator = eq;

	ret = blkcg_activate_policy(q, &blkcg_policy_kyber);
	if (ret) {
		kfree(kqd);
		kobject_put(&eq->kobj);
		return ret;
	}

	kyber_kf_lookup_create(q);

	kqd->kfg->timer_thread = kthread_run(kyber_refill_thread_fn, kqd->kfg, "refill thread");
	hrtimer_start(&kqd->kfg->timer, ktime, HRTIMER_MODE_REL);

	return 0;
}

static void kyber_exit_sched(struct elevator_queue *e)
{
	struct kyber_queue_data *kqd = e->elevator_data;
	struct kyber_fairness_global *kfg = kqd->kfg;
	int i;

	del_timer_sync(&kqd->timer);
	hrtimer_cancel(&kfg->timer);
	kthread_stop(kfg->timer_thread);

	kfree(kfg->kf_list[0]);
	kfree(kqd->kfg);

	for (i = 0; i < KYBER_NUM_DOMAINS; i++)
		sbitmap_queue_free(&kqd->domain_tokens[i]);
	free_percpu(kqd->cpu_latency);

	blkcg_deactivate_policy(kqd->q, &blkcg_policy_kyber);
	kfree(kqd);
}

static void kyber_ctx_queue_init(struct kyber_ctx_queue *kcq)
{
	unsigned int i, j;

	spin_lock_init(&kcq->lock);

	for (i = 0; i < KYBER_MAX_CGROUP; i++)
		for (j = 0; j < KYBER_NUM_DOMAINS; j++)
			INIT_LIST_HEAD(&kcq->rq_list[i][j]);
}

static int kyber_domain_wake(wait_queue_entry_t *wait, unsigned mode, int flags,
		void *key);

static int kyber_init_hctx(struct blk_mq_hw_ctx *hctx, unsigned int hctx_idx)
{
	struct kyber_queue_data *kqd = hctx->queue->elevator->elevator_data;
	struct kyber_hctx_data *khd;
	int i, j;

	khd = kmalloc_node(sizeof(*khd), GFP_KERNEL, hctx->numa_node);
	if (!khd)
		return -ENOMEM;

	khd->kcqs = kmalloc_array_node(hctx->nr_ctx,
			sizeof(struct kyber_ctx_queue),
			GFP_KERNEL, hctx->numa_node);
	if (!khd->kcqs)
		goto err_khd;

	for (i = 0; i < hctx->nr_ctx; i++)
		kyber_ctx_queue_init(&khd->kcqs[i]);

	for (i = 0; i < KYBER_MAX_CGROUP; i++) {
		for (j = 0; j < KYBER_NUM_DOMAINS; j++) {
			INIT_LIST_HEAD(&khd->rqs[i][j]);

			if (sbitmap_init_node(&khd->kcq_map[i][j], hctx->nr_ctx,
						ilog2(8), GFP_KERNEL, hctx->numa_node)) {
				do {
					while (--j >= 0)
						sbitmap_free(&khd->kcq_map[i][j]);
					j = KYBER_NUM_DOMAINS;
				} while (--i >= 1);

				goto err_kcqs;
			}
		}
	}

	spin_lock_init(&khd->lock);

	for (i = 0; i < KYBER_NUM_DOMAINS; i++) {
		khd->domain_wait[i].sbq = NULL;
		init_waitqueue_func_entry(&khd->domain_wait[i].wait,
				kyber_domain_wake);
		khd->domain_wait[i].wait.private = hctx;
		INIT_LIST_HEAD(&khd->domain_wait[i].wait.entry);
		atomic_set(&khd->wait_index[i], 0);
	}

	khd->cur_domain = 0;
	khd->batching = 0;

	khd->cur_kf = kqd->kfg->kf_list[1];

	hctx->sched_data = khd;
	sbitmap_queue_min_shallow_depth(&hctx->sched_tags->bitmap_tags,
			kqd->async_depth);

	return 0;

err_kcqs:
	kfree(khd->kcqs);
err_khd:
	kfree(khd);
	return -ENOMEM;
}

static void kyber_exit_hctx(struct blk_mq_hw_ctx *hctx, unsigned int hctx_idx)
{
	struct kyber_hctx_data *khd = hctx->sched_data;
	int i, j;

	for (i = 0; i < KYBER_MAX_CGROUP; i++)
		for (j = 0; j < KYBER_NUM_DOMAINS; j++)
			sbitmap_free(&khd->kcq_map[i][j]);

	kfree(khd->kcqs);
	kfree(hctx->sched_data);
}

static int rq_get_domain_token(struct request *rq)
{
	return (long)rq->elv.priv[0];
}

static void rq_set_domain_token(struct request *rq, int token)
{
	rq->elv.priv[0] = (void *)(long)token;
}

static void rq_clear_domain_token(struct kyber_queue_data *kqd,
		struct request *rq)
{
	unsigned int sched_domain;
	int nr;

	nr = rq_get_domain_token(rq);
	if (nr != -1) {
		sched_domain = kyber_sched_domain(rq->cmd_flags);
		sbitmap_queue_clear(&kqd->domain_tokens[sched_domain], nr,
				rq->mq_ctx->cpu);
	}
}

static void kyber_limit_depth(unsigned int op, struct blk_mq_alloc_data *data)
{
	/*
	 * We use the scheduler tags as per-hardware queue queueing tokens.
	 * Async requests can be limited at this stage.
	 */
	if (!op_is_sync(op)) {
		struct kyber_queue_data *kqd = data->q->elevator->elevator_data;

		data->shallow_depth = kqd->async_depth;
	}
}

static bool kyber_bio_merge(struct blk_mq_hw_ctx *hctx, struct bio *bio)
{
	struct kyber_hctx_data *khd = hctx->sched_data;
	struct blk_mq_ctx *ctx = blk_mq_get_ctx(hctx->queue);
	struct kyber_ctx_queue *kcq = &khd->kcqs[ctx->index_hw[hctx->type]];
	unsigned int sched_domain = kyber_sched_domain(bio->bi_opf);
	struct list_head *rq_list = &kcq->rq_list[bio_to_css_id(bio)][sched_domain];
	bool merged;

	spin_lock(&kcq->lock);
	merged = blk_mq_bio_list_merge(hctx->queue, rq_list, bio);
	spin_unlock(&kcq->lock);
	blk_mq_put_ctx(ctx);

	return merged;
}

static void kyber_prepare_request(struct request *rq, struct bio *bio)
{
	rq_set_domain_token(rq, -1);
}

static void kyber_insert_requests(struct blk_mq_hw_ctx *hctx,
		struct list_head *rq_list, bool at_head)
{
	struct kyber_hctx_data *khd = hctx->sched_data;
	struct request *rq, *next;

	list_for_each_entry_safe(rq, next, rq_list, queuelist) {
		unsigned int sched_domain = kyber_sched_domain(rq->cmd_flags);
		struct kyber_ctx_queue *kcq = &khd->kcqs[rq->mq_ctx->index_hw[hctx->type]];
		int id = bio_to_css_id(rq->bio);
		struct list_head *head = &kcq->rq_list[id][sched_domain];
		struct kyber_fairness *kf;

		kf = kf_from_list(hctx->queue, id);

		spin_lock(&kf->lock);
		if (kf->idle)
			kf->idle = false;
		spin_unlock(&kf->lock);

		spin_lock(&kcq->lock);
		if (at_head)
			list_move(&rq->queuelist, head);
		else
			list_move_tail(&rq->queuelist, head);
		sbitmap_set_bit(&khd->kcq_map[id][sched_domain],
				rq->mq_ctx->index_hw[hctx->type]);
		blk_mq_sched_request_inserted(rq);
		spin_unlock(&kcq->lock);
	}
}

static void kyber_finish_request(struct request *rq)
{
	struct kyber_queue_data *kqd = rq->q->elevator->elevator_data;

	rq_clear_domain_token(kqd, rq);
}

static void add_latency_sample(struct kyber_cpu_latency *cpu_latency,
		unsigned int sched_domain, unsigned int type,
		u64 target, u64 latency)
{
	unsigned int bucket;
	u64 divisor;

	if (latency > 0) {
		divisor = max_t(u64, target >> KYBER_LATENCY_SHIFT, 1);
		bucket = min_t(unsigned int, div64_u64(latency - 1, divisor),
				KYBER_LATENCY_BUCKETS - 1);
	} else {
		bucket = 0;
	}

	atomic_inc(&cpu_latency->buckets[sched_domain][type][bucket]);
}

static void kyber_completed_request(struct request *rq, u64 now)
{
	struct kyber_queue_data *kqd = rq->q->elevator->elevator_data;
	struct kyber_cpu_latency *cpu_latency;
	unsigned int sched_domain;
	u64 target;

	sched_domain = kyber_sched_domain(rq->cmd_flags);
	if (sched_domain == KYBER_OTHER)
		return;

	cpu_latency = get_cpu_ptr(kqd->cpu_latency);
	target = kqd->latency_targets[sched_domain];
	add_latency_sample(cpu_latency, sched_domain, KYBER_TOTAL_LATENCY,
			target, now - rq->start_time_ns);
	add_latency_sample(cpu_latency, sched_domain, KYBER_IO_LATENCY, target,
			now - rq->io_start_time_ns);
	put_cpu_ptr(kqd->cpu_latency);

	timer_reduce(&kqd->timer, jiffies + HZ / 10);
}

static int kyber_domain_wake(wait_queue_entry_t *wqe, unsigned mode, int flags,
		void *key)
{
	struct blk_mq_hw_ctx *hctx = READ_ONCE(wqe->private);
	struct sbq_wait *wait = container_of(wqe, struct sbq_wait, wait);

	sbitmap_del_wait_queue(wait);
	blk_mq_run_hw_queue(hctx, true);
	return 1;
}

static int kyber_get_domain_token(struct kyber_queue_data *kqd,
		struct kyber_hctx_data *khd,
		struct blk_mq_hw_ctx *hctx)
{
	unsigned int sched_domain = khd->cur_domain;
	struct sbitmap_queue *domain_tokens = &kqd->domain_tokens[sched_domain];
	struct sbq_wait *wait = &khd->domain_wait[sched_domain];
	struct sbq_wait_state *ws;
	int nr;

	nr = __sbitmap_queue_get(domain_tokens);

	/*
	 * If we failed to get a domain token, make sure the hardware queue is
	 * run when one becomes available. Note that this is serialized on
	 * khd->lock, but we still need to be careful about the waker.
	 */
	if (nr < 0 && list_empty_careful(&wait->wait.entry)) {
		ws = sbq_wait_ptr(domain_tokens,
				&khd->wait_index[sched_domain]);
		khd->domain_ws[sched_domain] = ws;
		sbitmap_add_wait_queue(domain_tokens, ws, wait);

		/*
		 * Try again in case a token was freed before we got on the wait
		 * queue.
		 */
		nr = __sbitmap_queue_get(domain_tokens);
	}

	/*
	 * If we got a token while we were on the wait queue, remove ourselves
	 * from the wait queue to ensure that all wake ups make forward
	 * progress. It's possible that the waker already deleted the entry
	 * between the !list_empty_careful() check and us grabbing the lock, but
	 * list_del_init() is okay with that.
	 */
	if (nr >= 0 && !list_empty_careful(&wait->wait.entry)) {
		ws = khd->domain_ws[sched_domain];
		spin_lock_irq(&ws->wait.lock);
		sbitmap_del_wait_queue(wait);
		spin_unlock_irq(&ws->wait.lock);
	}

	return nr;
}

static struct request *
kyber_dispatch_cur_domain(struct kyber_queue_data *kqd,
		struct kyber_hctx_data *khd,
		struct blk_mq_hw_ctx *hctx,
		int cgroup_id)
{
	struct list_head *rqs;
	struct request *rq;
	struct kyber_fairness_global *kfg = kqd->kfg;
	struct kyber_fairness *kf;
	int nr;

	rqs = &khd->rqs[cgroup_id][khd->cur_domain];

	/*
	 * If we already have a flushed request, then we just need to get a
	 * token for it. Otherwise, if there are pending requests in the kcqs,
	 * flush the kcqs, but only if we can get a token. If not, we should
	 * leave the requests in the kcqs so that they can be merged. Note that
	 * khd->lock serializes the flushes, so if we observed any bit set in
	 * the kcq_map, we will always get a request.
	 */

	rq = list_first_entry_or_null(rqs, struct request, queuelist);
	if (rq) {
		nr = kyber_get_domain_token(kqd, khd, hctx);
		if (nr >= 0) {
			goto out;
		} else {
			trace_kyber_throttled(kqd->q,
					kyber_domain_names[khd->cur_domain]);
		}
		goto out;
	} else if (sbitmap_any_bit_set(&khd->kcq_map[cgroup_id][khd->cur_domain])) {
		nr = kyber_get_domain_token(kqd, khd, hctx);
		if (nr >= 0) {
			kyber_flush_busy_kcqs(khd, cgroup_id, khd->cur_domain, rqs);
			rq = list_first_entry(rqs, struct request, queuelist);
			goto out;
		} else {
			trace_kyber_throttled(kqd->q,
					kyber_domain_names[khd->cur_domain]);
		}
		kyber_flush_busy_kcqs(khd, cgroup_id, khd->cur_domain, rqs);
		rq = list_first_entry(rqs, struct request, queuelist);
		goto out;
	}

	/* There were either no pending requests or no tokens. */
	return NULL;

out:
	khd->batching++;
	rq_set_domain_token(rq, nr);
	list_del_init(&rq->queuelist);

	kf = kf_from_rq(rq);

	if (!kf)
		return rq;

	spin_lock(&kf->lock);

	if (op_is_write(req_op(rq)))
		kf->cur_budget -= blk_rq_sectors(rq) * kfg->wr_scale;
	else
		kf->cur_budget -= blk_rq_sectors(rq);

	spin_unlock(&kf->lock);

	return rq;
}

static bool kyber_is_active(int id, struct blk_mq_hw_ctx *hctx)
{
	struct kyber_hctx_data *khd = hctx->sched_data;
	int domain;

	for (domain = 0; domain < KYBER_NUM_DOMAINS; domain++) {
		if (!list_empty_careful(&khd->rqs[id][domain]) ||
			sbitmap_any_bit_set(&khd->kcq_map[id][domain]))
				return true;
	}

	return false;
}

static int kyber_choose_cgroup(struct blk_mq_hw_ctx *hctx)
{
	struct request_queue *q = hctx->queue;
	struct kyber_queue_data *kqd = q->elevator->elevator_data;
	struct kyber_hctx_data *khd = hctx->sched_data;
	struct kyber_fairness_global *kfg = kqd->kfg;
	struct kyber_fairness *kf = khd->cur_kf;
	unsigned int id = kf->id;
	bool throttle = true, reverse = false;

	while (id <= atomic_read(&kfg->nr_kf) && id >= 0) {
		kf = kf_from_list(q, id);

		if (!kyber_is_active(id, hctx))
			goto skip;

		spin_lock(&kf->lock);
		if (kf->cur_budget <= 0) {
			kfg->has_work = true;
			goto next;
		}
		spin_unlock(&kf->lock);

		khd->cur_kf = kf;

		return id;
skip:
		spin_lock(&kf->lock);
		if (!kf->idle && kf->cur_budget > 0)
			throttle = false;
next:
		spin_unlock(&kf->lock);

		if (id == atomic_read(&kfg->nr_kf)) {
			id = khd->cur_kf->id;
			reverse = true;
		}

		if (reverse) id--;
		else		 id++;
	}

	if (throttle && hrtimer_try_to_cancel(&kfg->timer) >= 0)
		kyber_refill_fn(&kfg->timer);

	return -1;
}

static bool kyber_has_work(struct blk_mq_hw_ctx *hctx)
{
	struct request_queue *q = hctx->queue;
	struct kyber_queue_data *kqd = q->elevator->elevator_data;
	struct kyber_hctx_data *khd = hctx->sched_data;
	struct kyber_fairness_global *kfg = kqd->kfg;
	struct kyber_fairness *kf = khd->cur_kf;
	unsigned int cur_id = kf->id, id = kf->id;
	bool reverse = false;

	while (id <= atomic_read(&kfg->nr_kf) && id >= 0) {
		kf = kf_from_list(q, id);

		if (kyber_is_active(id, hctx))
			return true;

		if (id == atomic_read(&kfg->nr_kf)) {
			id = cur_id;
			reverse = true;
		}

		if (reverse) id--;
		else		 id++;
	}

	return false;
}

static struct request *kyber_dispatch_request(struct blk_mq_hw_ctx *hctx)
{
	struct kyber_queue_data *kqd = hctx->queue->elevator->elevator_data;
	struct kyber_hctx_data *khd = hctx->sched_data;
	struct request *rq = NULL;
	int cgroup_id;
	int i;

	spin_lock(&khd->lock);

	cgroup_id = kyber_choose_cgroup(hctx);

	if (cgroup_id < 0)
		goto out;

	/*
	 * First, if we are still entitled to batch, try to dispatch a request
	 * from the batch.
	 */
	if (khd->batching < kyber_batch_size[khd->cur_domain]) {
		rq = kyber_dispatch_cur_domain(kqd, khd, hctx, cgroup_id);
		if (rq)
			goto out;
	}

	/*
	 * Either,
	 * 1. We were no longer entitled to a batch.
	 * 2. The domain we were batching didn't have any requests.
	 * 3. The domain we were batching was out of tokens.
	 *
	 * Start another batch. Note that this wraps back around to the original
	 * domain if no other domains have requests or tokens.
	 */
	khd->batching = 0;
	for (i = 0; i < KYBER_NUM_DOMAINS; i++) {
		if (khd->cur_domain == KYBER_NUM_DOMAINS - 1)
			khd->cur_domain = 0;
		else
			khd->cur_domain++;

		rq = kyber_dispatch_cur_domain(kqd, khd, hctx, cgroup_id);
		if (rq)
			goto out;
	}
out:
	spin_unlock(&khd->lock);

	return rq;
}

#define KYBER_LAT_SHOW_STORE(domain, name)				\
static ssize_t kyber_##name##_lat_show(struct elevator_queue *e,	\
		char *page)			\
{									\
	struct kyber_queue_data *kqd = e->elevator_data;		\
	\
	return sprintf(page, "%llu\n", kqd->latency_targets[domain]);	\
}									\
\
static ssize_t kyber_##name##_lat_store(struct elevator_queue *e,	\
		const char *page, size_t count)	\
{									\
	struct kyber_queue_data *kqd = e->elevator_data;		\
	unsigned long long nsec;					\
	int ret;							\
	\
	ret = kstrtoull(page, 10, &nsec);				\
	if (ret)							\
	return ret;						\
	\
	kqd->latency_targets[domain] = nsec;				\
	\
	return count;							\
}
KYBER_LAT_SHOW_STORE(KYBER_READ, read);
KYBER_LAT_SHOW_STORE(KYBER_WRITE, write);
#undef KYBER_LAT_SHOW_STORE

#define KYBER_LAT_ATTR(op) __ATTR(op##_lat_nsec, 0644, kyber_##op##_lat_show, kyber_##op##_lat_store)
static struct elv_fs_entry kyber_sched_attrs[] = {
	KYBER_LAT_ATTR(read),
	KYBER_LAT_ATTR(write),
	__ATTR_NULL
};
#undef KYBER_LAT_ATTR

#ifdef CONFIG_BLK_DEBUG_FS
#define KYBER_DEBUGFS_DOMAIN_ATTRS(domain, name)			\
static int kyber_##name##_tokens_show(void *data, struct seq_file *m)	\
{									\
	struct request_queue *q = data;					\
	struct kyber_queue_data *kqd = q->elevator->elevator_data;	\
	\
	sbitmap_queue_show(&kqd->domain_tokens[domain], m);		\
	return 0;							\
}									\
\
static void *kyber_##name##_rqs_start(struct seq_file *m, loff_t *pos)	\
__acquires(&khd->lock)							\
{									\
	struct blk_mq_hw_ctx *hctx = m->private;			\
	struct kyber_hctx_data *khd = hctx->sched_data;			\
	\
	spin_lock(&khd->lock);						\
	return seq_list_start(&khd->rqs[1][domain], *pos);		\
}									\
\
static void *kyber_##name##_rqs_next(struct seq_file *m, void *v,	\
		loff_t *pos)						\
{									\
	struct blk_mq_hw_ctx *hctx = m->private;			\
	struct kyber_hctx_data *khd = hctx->sched_data;			\
	\
	return seq_list_next(v, &khd->rqs[1][domain], pos);		\
}									\
\
static void kyber_##name##_rqs_stop(struct seq_file *m, void *v)	\
__releases(&khd->lock)						\
{									\
	struct blk_mq_hw_ctx *hctx = m->private;			\
	struct kyber_hctx_data *khd = hctx->sched_data;			\
	\
	spin_unlock(&khd->lock);					\
}									\
\
static const struct seq_operations kyber_##name##_rqs_seq_ops = {	\
	.start	= kyber_##name##_rqs_start,				\
	.next	= kyber_##name##_rqs_next,				\
	.stop	= kyber_##name##_rqs_stop,				\
	.show	= blk_mq_debugfs_rq_show,				\
};									\
\
static int kyber_##name##_waiting_show(void *data, struct seq_file *m)	\
{									\
	struct blk_mq_hw_ctx *hctx = data;				\
	struct kyber_hctx_data *khd = hctx->sched_data;			\
	wait_queue_entry_t *wait = &khd->domain_wait[domain].wait;	\
	\
	seq_printf(m, "%d\n", !list_empty_careful(&wait->entry));	\
	return 0;							\
}									\

KYBER_DEBUGFS_DOMAIN_ATTRS(KYBER_READ, read)
KYBER_DEBUGFS_DOMAIN_ATTRS(KYBER_WRITE, write)
KYBER_DEBUGFS_DOMAIN_ATTRS(KYBER_DISCARD, discard)
KYBER_DEBUGFS_DOMAIN_ATTRS(KYBER_OTHER, other)
#undef KYBER_DEBUGFS_DOMAIN_ATTRS

static int kyber_async_depth_show(void *data, struct seq_file *m)
{
	struct request_queue *q = data;
	struct kyber_queue_data *kqd = q->elevator->elevator_data;

	seq_printf(m, "%u\n", kqd->async_depth);
	return 0;
}

static int kyber_cur_domain_show(void *data, struct seq_file *m)
{
	struct blk_mq_hw_ctx *hctx = data;
	struct kyber_hctx_data *khd = hctx->sched_data;

	seq_printf(m, "%s\n", kyber_domain_names[khd->cur_domain]);
	return 0;
}

static int kyber_batching_show(void *data, struct seq_file *m)
{
	struct blk_mq_hw_ctx *hctx = data;
	struct kyber_hctx_data *khd = hctx->sched_data;

	seq_printf(m, "%u\n", khd->batching);
	return 0;
}

#define KYBER_QUEUE_DOMAIN_ATTRS(name)	\
{#name "_tokens", 0400, kyber_##name##_tokens_show}
static const struct blk_mq_debugfs_attr kyber_queue_debugfs_attrs[] = {
	KYBER_QUEUE_DOMAIN_ATTRS(read),
	KYBER_QUEUE_DOMAIN_ATTRS(write),
	KYBER_QUEUE_DOMAIN_ATTRS(discard),
	KYBER_QUEUE_DOMAIN_ATTRS(other),
	{"async_depth", 0400, kyber_async_depth_show},
	{},
};
#undef KYBER_QUEUE_DOMAIN_ATTRS

#define KYBER_HCTX_DOMAIN_ATTRS(name)					\
{#name "_rqs", 0400, .seq_ops = &kyber_##name##_rqs_seq_ops},	\
{#name "_waiting", 0400, kyber_##name##_waiting_show}
static const struct blk_mq_debugfs_attr kyber_hctx_debugfs_attrs[] = {
	KYBER_HCTX_DOMAIN_ATTRS(read),
	KYBER_HCTX_DOMAIN_ATTRS(write),
	KYBER_HCTX_DOMAIN_ATTRS(discard),
	KYBER_HCTX_DOMAIN_ATTRS(other),
	{"cur_domain", 0400, kyber_cur_domain_show},
	{"batching", 0400, kyber_batching_show},
	{},
};
#undef KYBER_HCTX_DOMAIN_ATTRS
#endif

static struct elevator_type kyber_sched = {
	.ops = {
		.init_sched = kyber_init_sched,
		.exit_sched = kyber_exit_sched,
		.init_hctx = kyber_init_hctx,
		.exit_hctx = kyber_exit_hctx,
		.limit_depth = kyber_limit_depth,
		.bio_merge = kyber_bio_merge,
		.prepare_request = kyber_prepare_request,
		.insert_requests = kyber_insert_requests,
		.finish_request = kyber_finish_request,
		.requeue_request = kyber_finish_request,
		.completed_request = kyber_completed_request,
		.dispatch_request = kyber_dispatch_request,
		.has_work = kyber_has_work,
	},
#ifdef CONFIG_BLK_DEBUG_FS
	.queue_debugfs_attrs = kyber_queue_debugfs_attrs,
	.hctx_debugfs_attrs = kyber_hctx_debugfs_attrs,
#endif
	.elevator_attrs = kyber_sched_attrs,
	.elevator_name = "kyber",
	.elevator_owner = THIS_MODULE,
};

static int __init kyber_init(void)
{
	int ret;

	ret = blkcg_policy_register(&blkcg_policy_kyber);
	if (ret)
		return ret;

	ret = elv_register(&kyber_sched);
	if (ret) {
		blkcg_policy_unregister(&blkcg_policy_kyber);
		return ret;
	}

	return 0;
}

static void __exit kyber_exit(void)
{
	elv_unregister(&kyber_sched);
	blkcg_policy_unregister(&blkcg_policy_kyber);
}

module_init(kyber_init);
module_exit(kyber_exit);

MODULE_AUTHOR("Omar Sandoval");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Kyber I/O scheduler");
