#!/bin/sh

# Example script to sync from LVM on a remote host to a local zvol 
# device on zfs, taking a snapshot on the zfs before the sync takes 
# place.

# Call the script as lvm-to-zfs-sync.sh <volume name> 

# Includes an option to do a baseline transfer against /dev/null to 
# minimise disk reads

# This assumes that volume name exists as a zvol locally and an lvm 
# volume remotely.

# Written by Tim Fletcher <tim@night-shade.org.uk>

# ZFS zpool/zfs holding zvols
localtarget=tank/fs
# LVM device to pull from
remotetarget=/dev/LVM
# Remove username and host
remotehost=root@backup
# Block size to use, zvols work best with 8k I found
blocksize=8192
# Number of local zfs snaps to keep
keep=7

if [ $(id -u) -gt 0 ] ; then
        echo $0 needs to be run as root
        exit 1
fi

baseline()
{
size=$(blockdev --getsize64 /dev/zvol/$localtarget/$dev)
bdsync --diffsize --blocksize=$blocksize --remdata "ssh $remotehost bdsync --server" /dev/null $remotetarget/$dev | pv -s $size | bdsync --patch=/dev/zvol/$localtarget/$dev
}

devcheck()
{
if [ ! -b /dev/zvol/$localtarget/$dev ] ; then
	echo "$localtarget/$dev doesn't exist"
	exit 1
fi
}

snapshot()
{
zfs-auto-snapshot.sh --syslog -p snap --label=bdsync --keep=$keep $localtarget/$dev
}
transfer()
{
bdsync --blocksize=$blocksize --remdata "ssh $remotehost bdsync --server" /dev/zvol/$localtarget/$dev $remotetarget/$dev | pv | sudo bdsync --patch
}

case $1 in
baseline)
        shift
	dev=$1
	devcheck
	baseline
;;
*)
	dev=$1
	devcheck
	snapshot
	transfer
;;
esac
