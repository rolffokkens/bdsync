bdsync(1)                                                                          bdsync(1)



NAME
       bdsync — a fast block device synchronizing tool

SYNOPSIS
         Client: bdsync [--verbose] REMSHCMD LOCDEV REMDEV
         Server: bdsync --server [--verbose]
         Patch:  bdsync --patch [--verbose] [DSTDEV]

DESCRIPTION
       Bdsync  can  be  used  to  synchronize  block  devices over a network. It generates a
       "binary diff" in an efficient way by comparing MD5 checksums of  32k  blocks  of  the
       local block device LOCDEV and the remote block device REMDEV.

       This  binary  diff  can be sent to the remote machine and applied to its block device
       DSTDEV, after which the local blockdev LOCDEV and the remote block device REMDEV  are
       synchronized.

       bdsync  was  built  to  do  the  only thing rsync isn't able to do: synchronize block
       devices.

USAGE
       Bdsync assumes a client is connecting to a server. The connection  isn't  established
       by  the  client itself, but by a remote-shell-command REMSHCMD.  This REMSHCMD can be
       any kind of command to make a connection: rsh, ssh, netcat..  If  using  rsh  or  ssh
       REMSHCMD  should  be  the  full  command  to make the connection including the remote
       bdsync command te be executed in server mode. If using netcat to make the connection,
       the remote server mode bdsync command should be executed by inetd, xinetd etc.

       The  --verbose  option  results  in verbose output. In Server mode the output will be
       sent to syslog. The --verbose option can be repeated raising the verbosity level.

       Bdsync can be initiated like this in its most simple form:

              bdsync "bdsync -s" /dev/LOCDEV /dev/REMDEV > DEV.bdsync

       This generates a diff DEV.rsync of the /dev/LOCDEV and the /dev/REMDEV devices  which
       both are local. A more realistic example is this:

              bdsync  "ssh  doe@foo.org  bdsync  --server"  /dev/LOCDEV /dev/REMDEV | gzip >
              DEV.bdsync.gz

       This bdsync client makes an ssh connection to foo.org as  user  doe  and  executes  a
       bdsync  client by passing it the --server option. The generated diff output is passed
       on to gzip which creates a compressed diff file DEV.bdsync.gz.

       On the remote machine foo.org the user doe can apply the patch by executing:

              gzip < DEV.bdsync.gz | bdsync --patch /dev/DSTDEV

       The reason to use a binary patch file instead of instantly patching the remote  block
       device REMDEV is twofold:

       o      Sending over a complete diff allows to synchronize in a consistent way in case
              of an interruption (powerloss, network malfunction) since you  can  choose  to
              apply the (complete) diff or not.

       o      Compression  of the diff can easily be done, without introducing complexity in
              bdsync itself.

                                         24 Jun 2012                               bdsync(1)
