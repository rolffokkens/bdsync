dd if=/dev/zero of=/tmp/LOCDEV bs=1024 count=1024
dd if=/dev/zero of=/tmp/REMDEV bs=1024 count=1024
echo test | dd of=/tmp/LOCDEV ibs=1 seek=512 obs=1 conv=notrunc

md5sum /tmp/LOCDEV /tmp/REMDEV

./bdsync --fixedsalt --checksum md5 --remblocks   "./bdsync -s -v" /tmp/LOCDEV /tmp/REMDEV > /tmp/DEV.bdsync1
./bdsync --fixedsalt --checksum md5 --hash sha256 "./bdsync -s -v" /tmp/REMDEV /tmp/LOCDEV > /tmp/DEV.bdsync2

./bdsync --patch -v < /tmp/DEV.bdsync1

md5sum /tmp/DEV.bdsync1 /tmp/DEV.bdsync2 /tmp/LOCDEV /tmp/REMDEV
