#!/bin/bash
#- https://downloads.raspberrypi.org/raspbian_lite/images/raspbian_lite-2017-08-17/
#- https://blog.agchapman.com/using-qemu-to-emulate-a-raspberry-pi/

/home/huginn/diplomski/qemu_ivankovic/build/qemu-system-arm \
-kernel ./kernel-qemu-4.4.34-jessie \
-append "root=/dev/sda2 panic=1 rootfstype=ext4 rw" \
-hda raspbian-stretch-lite.qcow \
-cpu arm1176 -m 256 \
-M versatilepb \
-no-reboot \
-serial stdio \
-net nic -net user \
-qmp tcp:localhost:4444,server,wait=off \
-nic user,hostfwd=tcp:127.0.0.1:1080-:80 \
-net tap,ifname=vnet0,script=no,downscript=no \
