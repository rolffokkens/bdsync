dd if=/dev/zero of=/tmp/LOCDEV bs=1024 count=1024 2>/dev/null
dd if=/dev/zero of=/tmp/REMDEV bs=1024 count=1024 2>/dev/null
echo test | dd of=/tmp/LOCDEV ibs=1 seek=512 obs=1 conv=notrunc 2>/dev/null

md5sum /tmp/LOCDEV /tmp/REMDEV

./bdsync --fixedsalt --checksum md5 --remdata     "./bdsync -s -v" /tmp/LOCDEV /tmp/REMDEV > /tmp/DEV.bdsync1
./bdsync --fixedsalt --checksum md5 --hash sha256 "./bdsync -s -v" /tmp/REMDEV /tmp/LOCDEV > /tmp/DEV.bdsync2

./bdsync --patch < /tmp/DEV.bdsync1

md5sum /tmp/DEV.bdsync1 /tmp/DEV.bdsync2 /tmp/LOCDEV /tmp/REMDEV
