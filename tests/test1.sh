echo .abcd >/tmp/LOCDEV 
echo .abXd >/tmp/REMDEV 

md5sum /tmp/LOCDEV /tmp/REMDEV

./bdsync --remblocks -v "./bdsync -s" /tmp/LOCDEV /tmp/REMDEV > /tmp/DEV.bdsync
#bdsync "bdsync -s" /tmp/REMDEV /tmp/LOCDEV > /tmp/DEV.bdsync2

./bdsync --patch -v < /tmp/DEV.bdsync

md5sum /tmp/LOCDEV /tmp/REMDEV
