#!/bin/sh
# Run only inside the disposable validation container with /work mounted.
set -eu
umask 077
test -f /.dockerenv
filesystem=${1:-ext4}
case "$filesystem" in ext4|xfs|btrfs) ;; *) exit 2 ;; esac
test -f "/work/native-$filesystem.img"
mkdir -p /mnt/vault-test
mount -o loop "/work/native-$filesystem.img" /mnt/vault-test
trap 'umount /mnt/vault-test' EXIT
test_root=/mnt/vault-test
if [ "$filesystem" = btrfs ]; then
    if [ ! -d /mnt/vault-test/test-volume ]; then
        btrfs subvolume create /mnt/vault-test/test-volume
    fi
    test_root=/mnt/vault-test/test-volume
fi
mkdir -p "$test_root/tmp"
export TMPDIR="$test_root/tmp"
export GOTMPDIR="$TMPDIR"
findmnt /mnt/vault-test
python3 /work/bundle/verify_offline_vault.py --binary /work/bundle/xops --verifier /work/bundle/verifier --require-isolation
python3 /work/bundle/test_offline_vault_drill.py --binary /work/bundle/xops --verifier /work/bundle/verifier
# Only the race test drivers need host glibc. XOps and verifier are static.
mkdir -p /lib64
ln -s /hostlib/ld-linux-x86-64.so.2 /lib64/ld-linux-x86-64.so.2
ln -s /hostlib/libc.so.6 /lib/libc.so.6
ln -s /hostlib/libc.so.6 /usr/lib/libc.so.6
ln -s /hostlib/libresolv.so.2 /usr/lib/libresolv.so.2
export GORACE=atexit_sleep_ms=0
cd /work/bundle/credentialfile
../credentialfile.test -test.v -test.count=1 -test.timeout=240s
cd /work/bundle/kdfhelper
../kdfhelper.test -test.v -test.count=1 -test.timeout=120s
cd /work/bundle/pkg/config
../../config.test -test.v -test.count=1 -test.timeout=240s
cd /work/bundle/cmd
../cmd.test -test.v -test.count=1 -test.timeout=240s
