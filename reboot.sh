#!/bin/bash

make -j31 && make modules_install -j31 && make install -j32 && reboot
