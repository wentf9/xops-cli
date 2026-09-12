#!/bin/sh
set -eu
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
umask 077
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
exec </dev/console >/dev/console 2>&1
mkdir -p /dev/pts /data /tmp
mount -t devpts devpts /dev/pts
for option in $(cat /proc/cmdline); do
    case "$option" in
        xops_phase=*) export XOPS_POWER_PHASE=${option#*=} ;;
        xops_point=*) export XOPS_POWER_POINT=${option#*=} ;;
        xops_operation=*) export XOPS_POWER_OPERATION=${option#*=} ;;
        xops_filesystem=*) filesystem=${option#*=} ;;
    esac
done
filesystem=${filesystem:-ext4}
case "$filesystem" in ext4|xfs|btrfs) ;; *) exit 2 ;; esac
if [ "$filesystem" = xfs ] && [ -f /lab/xfs.ko ]; then
    insmod /lab/xfs.ko
fi
mount -t "$filesystem" /dev/vda /data
cd /lab
if /lab/powercut.test -test.run '^TestVaultPowerCut$' -test.v -test.timeout=55s; then
    sync
    umount /data
    echo XOPS_VM_PHASE_PASSED
else
    echo XOPS_VM_PHASE_FAILED
fi
poweroff -f
