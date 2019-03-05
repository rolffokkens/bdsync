% BDSYNC(1)
% Rolf Fokkens
% July 2017

# NAME

bdsync – a fast **b**lock **d**evice **sync**hronizing tool

# SYNOPSIS

Client: **bdsync** [--verbose] [--digest=DIGEST] REMSHCMD LOCDEV REMDEV  
Server: **bdsync** --server [--verbose]  
Patch: **bdsync** --patch[=DSTDEV] [--verbose]  

# DESCRIPTION
Bdsync can be used to synchronize block devices over a network. It generates a
"binary patchfile" in an efficient way by comparing checksums of blocks of the
local block device LOCDEV and the remote block device REMDEV.

This binary patchfile can be sent to the remote machine and applied to its
block device REMDEV, after which the local blockdev LOCDEV and the remote block
device REMDEV are synchronized.

Both LOCDEV, REMDEV and DSTDEV can be true block devices, but may be (image)
files as well. When using an image file for DSTDEV (the **--patch** mode),
the **--diffsize** may be used to resize the image file when appropriate.

bdsync was built to do the only thing rsync isn't able to do: synchronize block
devices.

# OPTIONS

**-s**, **--server**
:   Start bdsync as a server. No further arguments are accepted, all controll
is done by standard input and standard output

**-p**, **--patch[=DEVICE]**
:   Make bdsync "patch" a device by applying a bdsync file read from standard
input. The device will be determined from the bdsync data unless an (optional)
device name DEVICE is specified

**-w**, **--warndev**
:   Makes bdsync (in patch mode) warn if the specified device with the --patch
option differs from the device in the patch data

**-v**, **--verbose**
:   Increase the verbosity of bdsync. Can be repeated multiple times.

**-h**, **--hash=DIGEST**
:   Choose any of openssl's digests as a hash for matching blocks on LOCDEV en
REMDEV. Default is md5.

**-b**, **--blocksize=BLOCKSIZE**
:   Set the blocksize in bytes for which hashes are calculated on both LOCDEV
and REMDEV. Default 4096.

**-c**, **--checksum=DIGEST**
:   Choose any of openssl's digests as a checksum for all LOCDEV data. The
checksum will be written to the binary patchfile. Default is none.

**-t**, **--twopass**
:   Makes bdsync first match checksums using large blocks (64 * BLOCKSIZE) and
then match checksums using small blocks (BLOCKSIZE). This may reduce systemcall
overhead and networktraffic when the "binary patchfile" has limited size.

**-r**, **--remdata**
:   Makes bdsync (in client mode) write the remote data to standard output
instead of the local blocks that differs.

**-d**, **--diffsize[=OPTION[,warn]]**
:   Specifies how bdsync (in client mode and patch mode) should handle
different sizes of devices. Possible values for OPTION are **strict**,
**resize** and **minsize**. When **strict** is specified, different sizes for
LOCDEV and REMDEV are not allowed. When resize is specified, different sizes
are accepted and the LOCDEV size is applied to REMDEV in patch mode which is
only supported for (image) files (not devices). When minsize is specified, the
smallest size of both LOCDEV and REMDEV is considered (excess data is ignored).

>   When the **--diffsize** command line option is not specified at all, it
defaults to **--diffsize=strict**. When the **--diffsize** is specified
without any of the additional options, it defaults to **--diffsize=resize**
which is consistent with earlier versions of bdsync.

>   When the additional **warn** option is specified, a warning is issued when
sizes differ.

**-z**, **--zeroblocks**
:   Makes bdsync (in client mode and server mode) identify zero-filled blocks
and optimize hashes for these blocks. This may be usefull for sparse files with
lots of zero filled blocks.

**-F**, **--flushcache**
:   This client option makes both bdsync client and server actively inform the
OS the data is no longer needed after reading it hence reducing OS buffer cache
polution by bdsync. This works especially well when deltas are small, because
in that case bdsync itself won't be reading blocks twice.

**-P**, **--progress**
:   This client option makes the client periodically report progress to stderr during
operation. The format is:

>   `PROGRESS:`**\<pct\>**`%,`**\<diffsize\>**`,`**\<pos\>**`,`**\<size\>**`,`**\<elapsed s\>**`,`**\<remaining s\>**

>   Where: **\<pct\>** is progress in %, **\<diffsize\>** is the current size of the
generated diff, **\<pos\>** is the current position reading LOCDEV, **\<size\>** is the
total size of LOCDEV, **\<elapsed s\>** is the elapsed time in seconds and 
**\<remaining s\>** is an estimate of the remaining time left in seconds.

**-H**, **--help**
:   Display brief help information.

# USAGE
Bdsync assumes a client is connecting to a server. The connection isn't
established by the client itself, but by a remote-shell-command REMSHCMD. This
REMSHCMD can be any kind of command to make a connection: rsh, ssh, netcat..
If using rsh or ssh REMSHCMD should be the full command to make the connection
including the remote bdsync command te be executed in server mode. If using
netcat to make the connection, the remote server mode bdsync command should be
executed by inetd, xinetd etc.

The --verbose option results in verbose output. In Server mode the output will
be sent to syslog. The --verbose option can be repeated raising the verbosity
level.

Bdsync can be initiated like this in its most simple form:

> bdsync "bdsync -s" **`/dev/LOCDEV`****`/dev/REMDEV`** > **DEV.bdsync**

This generates a patchfile **DEV.rsync** containing the blocks in the
**/dev/LOCDEV** device that differ from the blocks in the **/dev/REMDEV**
device which both are local. A more realistic example is this:

> bdsync "ssh **doe**\@**remote** bdsync --server" **/dev/LOCDEV**
**/dev/REMDEV** | gzip > **DEV.bdsync.gz**

When run as **john** at **local** the bdsync client makes an ssh connection to
**remote** as user **doe** and executes a bdsync server by passing it the
--server option. The generated patchfile output is passed on to gzip which
creates a compressed patchfile **DEV.bdsync.gz** on local. The patchfile
contains all blocks in **/dev/LOCDEV** at local that differ from
**/dev/REMDEV** at **remote**.

On the remote machine remote the user doe can apply the patch by executing:

> gzip -d < **DEV.bdsync.gz** | bdsync --patch=**/dev/REMDEV**

The reason to use a binary patch file instead of instantly patching the remote
block device REMDEV is twofold:

* Sending over a complete patchfile allows to synchronize in a consistent way
in case of an interruption (powerloss, network malfunction) since you can
choose to apply the (complete) patchfile or not.

* Compression of the patchfile can easily be done, without introducing
complexity in bdsync itself.

# EXIT STATUS
0 completed successfully  
1 invalid or conflicting parameters supplied  
2 invalid patch format  
3 size mismatch of source and destination blockdevice  
4 protocol error  
5 checksum error  
6 read error  
7 failed to collect randomness  
8 process management error  
9 write error  
10 digest error  
11 transmission error  
12 IO error  
13 connection error  

