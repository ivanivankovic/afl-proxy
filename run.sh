#!/bin/bash
/home/huginn/diplomski/qemu_ivankovic/build/qemu-system-arm -s -M versatilepb -cpu arm1176 -d nochain \
  -accel tcg,tb-size=256 \
  -hda 2012-07-15-wheezy-raspbian.img -kernel kernel-qemu -m 192 -append "root=/dev/sda2" \
  -qmp tcp:localhost:4444,server,wait=off \
  -nographic \
  -nic user,hostfwd=tcp:127.0.0.1:1080-:80
