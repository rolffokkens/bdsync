dd if=/dev/zero of=/tmp/LOCDEV bs=1024 count=1
dd if=/dev/zero of=/tmp/REMDEV bs=1024 count=1
echo test | dd of=/tmp/LOCDEV ibs=1 seek=512 obs=1 conv=notrunc

md5sum /tmp/LOCDEV /tmp/REMDEV

./bdsync --remblocks   -v "./bdsync -s" /tmp/LOCDEV /tmp/REMDEV > /tmp/DEV.bdsync1
./bdsync --hash sha256 -v "./bdsync -s" /tmp/REMDEV /tmp/LOCDEV > /tmp/DEV.bdsync2

./bdsync --patch -v < /tmp/DEV.bdsync1

md5sum /tmp/DEV.bdsync1 /tmp/DEV.bdsync2 /tmp/LOCDEV /tmp/REMDEV
