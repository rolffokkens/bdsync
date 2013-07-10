//
// bdsync
//
// This software is released under GPL2. More information can be found in the accompanying
// README and the COPYING file
// (c) Rolf Fokkens <rolf@rolffokkens.nl>
//
// Revision History:
// * 0.1 Jun 24 2012 Rolf Fokkens <rolf@rolffokkens.nl>
// - initial package
// * 0.2 Jun 25 2012 Rolf Fokkens <rolf@rolffokkens.nl>
// - added a man page
// * 0.3 Jun 26 2012 Rolf Fokkens <rolf@rolffokkens.nl>
// - fixed endianness
// - fixed implicit 64 bit dependencies, can be compiled 32 bit as well
//

#define _LARGEFILE64_SOURCE

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include <openssl/sha.h>
#include <netdb.h>
#include <sys/socket.h>
#include <stdarg.h>
#include <syslog.h>
#include <errno.h>

/* msg size is stored in a short */
#define MSGMAX 131072
#define ARGMAX 256

#define HASHSIZE 32
#define SALTSIZE 32

#define ARCHVER "BDSYNC 0.2"
#define PROTOVER "0.2"

int isverbose = 0;
void (*vhandler) (char *, va_list);

void verbose_syslog (char *format, va_list ap)
{
    vsyslog (LOG_INFO, format, ap);
};

void verbose_printf (char *format, va_list ap)
{
    vfprintf (stderr, format, ap);
};

void verbose (int level, char * format, ...)
{
    va_list args;

    if (level > isverbose) return;

    va_start (args, format);
    vhandler (format, args);
    va_end (args);
};

void set_blocking(int fd)
{
        int val;

        if ((val = fcntl(fd, F_GETFL)) == -1)
                return;
        if (val & O_NONBLOCK) {
                val &= ~O_NONBLOCK;
                fcntl(fd, F_SETFL, val);
        }
};

int fd_pair(int fd[2])
{
        int ret;

        ret = socketpair(AF_UNIX, SOCK_STREAM, 0, fd);
        // ret = pipe(fd);

        return ret;
};


int init_salt (int saltsize, char *salt)
{
    int fd = open("/dev/urandom", O_RDONLY);

    read (fd, salt, saltsize);

    close(fd);

    return 0;
};

pid_t piped_child(char **command, int *f_in, int *f_out)
{
        pid_t pid;
        int to_child_pipe[2];
        int from_child_pipe[2];

        verbose (2, "opening connection using: %s\n", command[0]);

        if (fd_pair(to_child_pipe) < 0 || fd_pair(from_child_pipe) < 0) {
                verbose (0, "piped_child: %s\n", strerror (errno));
                exit (1);
        }

        pid = fork();
        if (pid == -1) {
                verbose (0, "piped_child: fork: %s\n", strerror (errno));
                exit (1);
        }

        if (pid == 0) {
                if (dup2(to_child_pipe[0], STDIN_FILENO) < 0 ||
                    close(to_child_pipe[1]) < 0 ||
                    close(from_child_pipe[0]) < 0 ||
                    dup2(from_child_pipe[1], STDOUT_FILENO) < 0) {
                        verbose (0, "piped_child: dup2: %s\n", strerror (errno));
                        exit (1);
                }
                if (to_child_pipe[0] != STDIN_FILENO)
                        close(to_child_pipe[0]);
                if (from_child_pipe[1] != STDOUT_FILENO)
                        close(from_child_pipe[1]);
                // umask(orig_umask);
                set_blocking(STDIN_FILENO);
                set_blocking(STDOUT_FILENO);
                execvp(command[0], command);
                verbose (0, "piped_child: execvp: %s\n", strerror (errno));
                exit (1);
        }

        if (close(from_child_pipe[1]) < 0 || close(to_child_pipe[0]) < 0) {
                verbose (0, "piped_child: close: %s\n", strerror (errno));
                exit (1);
        }

        *f_in = from_child_pipe[0];
        *f_out = to_child_pipe[1];

        return pid;
};

pid_t do_command (char *command, int *f_in, int *f_out)
{
    int i, argc = 0;
    char *t, *f, *args[ARGMAX];
    pid_t pid;
    int dash_l_set = 0, in_quote = 0;

    command = strdup (command);

    for (t = f = command; *f; f++) {
        if (*f == ' ') continue;
        /* Comparison leaves rooms for server_options(). */
        if (argc >= ARGMAX) {
            verbose (0, "internal: args[] overflowed in do_command()\n");
            exit (1);
        }
        args[argc++] = t;
        while (*f != ' ' || in_quote) {
            if (!*f) {
                if (in_quote) {
                    verbose (0, "Missing trailing-%c in remote-shell command.\n"
                            , in_quote);
                    exit (1);
                }
                f--;
                break;
            }
            if (*f == '\'' || *f == '"') {
                if (!in_quote) {
                    in_quote = *f++;
                    continue;
                }
                if (*f == in_quote && *++f != in_quote) {
                    in_quote = '\0';
                    continue;
                }
            }
            *t++ = *f++;
        }
        *t++ = '\0';
    }
    pid = piped_child (args, f_in, f_out);

    free (command);

    return pid;
};

char *int2char (char *buf, off64_t val, int bytes)
{
    char *p;

    for (p = buf; bytes; bytes--) {
        *p++ = val & 0xff;
        val >>= 8;
    }
    return buf;
}

off64_t char2int (char *buf, int bytes)
{
    off64_t       ret = 0;
    unsigned char *p = (unsigned char *)buf + bytes;

    for (; bytes; bytes--) {
        ret <<= 8;
        ret |= *--p;
    }
    return ret;
}

enum messages {
    msg_hello = 1
,   msg_devfile
,   msg_size
,   msg_salt
,   msg_gethash
,   msg_hashes
,   msg_max
};

static char *msgstring[] = {
   ""
,  "hello"
,  "devfile"
,  "size"
,  "salt"
,  "gethash"
,  "hashes"
};

int msg_write (int fd, char token, char *buf, size_t len)
{
    u_int32_t tmp = len + 1;
    char      tbuf[sizeof (tmp)];

    verbose (2, "msg_write: msg = %s, len = %d\n", msgstring[token], len);

    if (write (fd, int2char (tbuf, tmp, sizeof (tmp)), sizeof (tmp)) != sizeof (tmp)) {
        exit (1);
    }
    if (write (fd, &token, sizeof (token)) != sizeof (token)) {
        exit (1);
    }
    if (write (fd, buf, len) != len) {
        exit (1);
    }

    return 0;
}

int send_msgstring (int fd, int msg, char *str)
{
    // size_t len = strlen (str);
    // char *buf = malloc (len + 1);

    msg_write (fd, msg, str, strlen (str));
}

int send_hello (int fd, char *hello)
{
    char buf[16];

    sprintf (buf, "%s %s", hello, PROTOVER);

    verbose (1, "send_hello: hello = %s, version = %s\n", hello, PROTOVER);

    send_msgstring (fd, msg_hello, buf);
}

int send_devfile (int fd, char *devfile)
{
    verbose (1, "send_devfile: devfile = %s\n", devfile);

    send_msgstring (fd, msg_devfile, devfile);
}

int send_size (int fd, off64_t devsiz)
{
    char tbuf[sizeof (devsiz)];

    verbose (1, "send_size: devsiz = %lld\n", (long long)devsiz);

    int2char (tbuf, devsiz, sizeof (devsiz));

    return msg_write ( fd, msg_size, tbuf, sizeof (devsiz));
};

char *bytes2str (size_t s, char *p)
{
    char *ret = malloc (2 * s + 1);
    char *tmp = ret;

    while (s) {
        sprintf (tmp, "%02x", *p);
        tmp += 2;
        p++;
        s--;
    }

    return ret;
};

int send_salt (int fd, int saltsize, char *salt)
{
    char *tmp = bytes2str (saltsize, salt);

    verbose (1, "send_salt: salt = %s\n", tmp);

    free (tmp);

    return msg_write ( fd, msg_salt, salt, saltsize);
}

int send_gethash (int fd, off64_t start, off64_t step, int nstep)
{
    off64_t par[3];
    char    tbuf[sizeof (par)];
    char    *cp;
    int     i;

    par[0] = start;
    par[1] = step;
    par[2] = nstep;

    verbose (1, "send_gethash: start=%lld step=%lld nstep=%d\n", (long long)par[0], (long long)par[1], (int)par[2]);

    for (i = 0, cp = tbuf; i < 3; i++, cp += sizeof (par[0])) {
        int2char (cp, par[i], sizeof (par[0]));
    }

    return msg_write (fd, msg_gethash, tbuf, sizeof (par));
};

int send_hashes (int fd, char *buf, size_t siz)
{
    verbose (1, "send_hashes: size=%d\n", (int)siz);

    return msg_write (fd, msg_hashes, buf, siz);
};

void read_all (int fd, char *buf, size_t buflen)
{
    int tmp;

    while (buflen) {
        tmp = read (fd, buf, buflen);
        switch (tmp) {
        case -1:
            verbose (0, "read_all: %s\n", strerror (errno));
            exit (1);
        case 0:
            verbose (0, "read_all: EOF\n");
            exit (1);
        }
        buf    += tmp;
        buflen -= tmp;
    }
};

int msg_read (int fd, char **buf, size_t *buflen, char *token, char **msg, size_t *msglen, int maxlen)
{
    u_int32_t tmp;
    char      tbuf[sizeof(tmp)];
    off64_t   t;

    read_all (fd, tbuf, sizeof (tmp));
    tmp = char2int (tbuf, sizeof (tmp));

    if (tmp > maxlen) {
        exit (1);
    }

    if (*buf && tmp > *buflen) {
        free (*buf);
        *buf = NULL;
    }
    if (!*buf) {
        *buf = (char *)malloc (tmp + 1);
    }
    *msglen = tmp - 1;

    if (tmp <= 1) exit (1);

    read_all (fd, *buf, tmp);

    (*buf)[tmp] = '\0';

    *token = **buf;
    *msg   = (*buf) + 1;

    if (*token < 1 || *token >= msg_max) {
        verbose (0, "Unknown message %d\n", *token);
        exit (1);
    }


    verbose (2, "msg_read: msg = %s, len = %d\n", msgstring[*token], (int)tmp - 1);

    return 0;
};

int parse_msgstring (char *msgbuf, size_t msglen, char **str, size_t minlen)
{
    if (*str || msglen < minlen) exit (1);

    *str = (char *) malloc (msglen + 1);

    memcpy (*str, msgbuf, msglen);
    (*str)[msglen] = 0;

    return 0;
};

int parse_devfile (char *msgbuf, size_t msglen, char **devfile)
{
    int ret;

    ret = parse_msgstring (msgbuf, msglen, devfile, 2);

    verbose (1, "parse_devfile: devfile = %s\n", *devfile);

    return ret;
};

int parse_hello (char *msgbuf, size_t msglen, char **hello)
{
    int ret;
    char *p;

    ret = parse_msgstring (msgbuf, msglen, hello, 0);

    p = strchr (*hello, ' ');
    if (p == NULL) {
        verbose (0, "parse_hello: Missing protocol version '%s'\n", *hello);
        exit (1);
    }

    if (strcmp (p + 1, PROTOVER)) {
        verbose (0, "parse_hello: Bad protocol version %s\n", p + 1);
        exit (1);
    }
    *p = '\0';

    verbose (1, "parse_hello: hello = %s, version = %s\n", *hello, p + 1);

    return ret;
};

int parse_size (char *msgbuf, size_t msglen, off64_t *size)
{
    if (msglen != sizeof (*size)) exit (1);

    *size = char2int (msgbuf, sizeof (*size));

    verbose (1, "parse_size: size = %ld\n", (long)*size);
};

int parse_salt (char **msgbuf, size_t msglen, int *saltsize, char **salt)
{
    int  ret;
    char *tmp;

    *saltsize = msglen;
    *salt     = *msgbuf;
    *msgbuf   = NULL;

    tmp = bytes2str (*saltsize, *salt);

    verbose (1, "parse_salt: salt = %s\n", tmp);

    free (tmp);

    return ret;
};

int parse_gethash ( char *msgbuf, size_t msglen
                  , off64_t *start, off64_t *step, int *nstep)
{
    off64_t par[3];
    int     i;

    if (msglen != sizeof (par)) {
        verbose (0, "parse_gethash: bad message size %d\n", (int)msglen);
        exit (1);
    }

    for (i = 0; i < 3; i++, msgbuf += sizeof (par[0])) {
        par[i] = char2int (msgbuf, sizeof (par[0]));
    }

    *start = par[0];
    *step  = par[1];
    *nstep = par[2];

    verbose (1, "parse_gethash: start=%lld step=%lld nstep=%d\n", (long long)par[0], (long long)par[1], (int)par[2]);

    return 0;
};

int parse_hashes (char **msgbuf, size_t msglen, char **hbuf, int nsteps)
{
    if (msglen != nsteps * HASHSIZE) {
        verbose (0, "parse_hashes: bad size=%lld expected=%lld\n", (long long)msglen, (long long)(nsteps * HASHSIZE));
        exit (1);
    }

    *hbuf   = *msgbuf;
    *msgbuf = NULL;

    verbose (1, "parse_hashes: size=%lld\n", (long long)msglen);
};

int gen_hashes ( int saltsize, char *salt
               , char **retbuf, size_t *retsiz, int fd
               , off64_t start, off64_t step, int nstep)
{
    char       *buf, *fbuf;
    off64_t    nrd;
    SHA256_CTX ctx;

    *retsiz = nstep * HASHSIZE;
    buf     = malloc (nstep * HASHSIZE);
    *retbuf = buf;

    verbose (1, "gen_hashes: start=%lld step=%lld nstep=%d\n"
            , (long long) start, (long long) step, nstep);

    posix_fadvise64 (fd, start, 2 * nstep * step, POSIX_FADV_WILLNEED);

    lseek64 (fd, start, SEEK_SET);

    fbuf    = malloc (step);

    while (nstep) {
        nrd = read (fd, fbuf, step);

        verbose (3, "gen_hashes: read pos=%lld, step=%lld, nrd=%d\n"
                , (long long) start, (long long) step, nrd);

        SHA256_Init (&ctx);
        SHA256_Update (&ctx, fbuf, nrd);
        SHA256_Final (buf, &ctx);
        buf += HASHSIZE;

        if (nrd != step) break;
        nstep--;
        start += step;
    }
    *retsiz = buf - *retbuf;

    free (fbuf);
};

int opendev (char *dev, off64_t *siz, int flags)
{
    char    buf[1 + sizeof (off64_t)];
    off64_t len;
    int     fd;

    fd = open (dev, flags | O_LARGEFILE);
    if (fd == -1) {
        verbose (0, "opendev: %s\n", strerror (errno));
        exit (1);
    }
    *siz = lseek64 (fd, 0, SEEK_END);

    verbose (1, "opendev: opened %s\n", dev);

    return fd;
};

int do_server (void)
{
    char    *buf = NULL, *msg;
    size_t  buflen, msglen;
    char    token;
    int     devfd, nstep;
    int     saltsize = 0;
    off64_t devsiz, start, step;
    char    *hbuf;
    size_t  hsize;
    char    *salt;

    verbose (1, "started\n");

    send_hello (STDOUT_FILENO, "SERVER");

    char *devfile = NULL;
    char *hello   = NULL;

    int  exp = msg_hello;

    for (;;) {
        msg_read (STDIN_FILENO, &buf, &buflen, &token, &msg, &msglen, MSGMAX);

        if (exp) {
            if (token != exp) exit (1);
            exp = 0;
        }

        switch (token) {
        case msg_hello:
            exp = msg_devfile;
            parse_hello (msg, msglen, &hello);
            break;
        case msg_devfile:
            parse_devfile (msg, msglen, &devfile);
            devfd = opendev (devfile, &devsiz, O_RDONLY);
            send_size (STDOUT_FILENO, devsiz);
            break;
        case msg_salt:
            parse_salt (&msg, msglen, &saltsize, &salt);
            break;
        case msg_gethash:
            parse_gethash (msg, msglen, &start, &step, &nstep);
            gen_hashes (saltsize, salt, &hbuf, &hsize, devfd, start, step, nstep);
            send_hashes (STDOUT_FILENO, hbuf, hsize);
            free (hbuf);
            break;
        default:
            exit (1);
            break;
        }
    }
    free (buf);
};

int tcp_connect (char *host, char *service)
{
    struct sockaddr_in6 server;
    struct servent *sp;
    struct hostent *hp;
    int n, s;
    FILE *fp;
    struct addrinfo hints;
    struct addrinfo *aip, *rp;

    hints.ai_family    = AF_UNSPEC;   /* Allow IPv4 or IPv6 */
    hints.ai_socktype  = SOCK_STREAM; /* Datagram socket */
    hints.ai_flags     = AI_PASSIVE;  /* For wildcard IP address */
    hints.ai_protocol  = 0;           /* Any protocol */
    hints.ai_canonname = NULL;
    hints.ai_addr      = NULL;
    hints.ai_next      = NULL;

    n = getaddrinfo (host, service, &hints, &aip);

    if (n != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
        exit (EXIT_FAILURE);
    }

    for (rp = aip; rp != NULL; rp = rp->ai_next) {
        s = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (s == -1) continue;

        if (connect(s, rp->ai_addr, rp->ai_addrlen) == 0) break;

        close(s);
    }

    if (rp == NULL) {
        perror("socket");
        exit(3);
    }

    return s;
}

void check_token (char *f, char token, char expect)
{
    if (token == expect) return;
    verbose (0, "%sUnexpected token=%s, expected=%s\n", f, msgstring[token], msgstring[expect]);
    exit (1);
};

#define HSMALL  4096
#define HLARGE  65536
// #define HSMALL  32768
// #define HLARGE  32768
#define HMAXCNT (((MSGMAX)/HASHSIZE)-1)

int hashmatch ( int saltsize, char *salt
              , int rd_fd, int wr_fd, int devfd
              , off64_t hashstart, off64_t hashend, off64_t hashstep
              , int maxsteps)
{
    int    hashsteps;
    char   *lhbuf = NULL, *rhbuf;
    size_t lhsize, rhsize;
    char   *msg, *mbuf = NULL;
    size_t buflen, msglen;
    char   token;

    verbose (2, "hashmatch: hashstart=%lld hashend=%lld hashstep=%lld maxsteps=%d\n"
            , (long long)hashstart, (long long)hashend, (long long)hashstep, maxsteps);

    for (;;) {
        hashsteps = (hashend + hashstep - 1 - hashstart) / hashstep;
        if (hashsteps > maxsteps) hashsteps = maxsteps;
        if (!hashsteps) break;

        /* Put the other side to work generating hashes */
        send_gethash (wr_fd, hashstart, hashstep, hashsteps);
        /* Generate our own list of hashes */
        gen_hashes (saltsize, salt, &lhbuf, &lhsize, devfd, hashstart, hashstep, hashsteps);

        /* Get the other side's hashes */
        msg_read (rd_fd, &mbuf, &buflen, &token, &msg, &msglen, MSGMAX);
        check_token ("", token, msg_hashes);
        parse_hashes (&msg, msglen, &rhbuf, hashsteps);

        off64_t pos = hashstart;
        char    *lp = lhbuf, *rp = rhbuf;
        int     ns = hashsteps;

        while (ns--) {
            if (bcmp (lp, rp, HASHSIZE)) {
                off64_t tend = pos + hashstep;

                if (tend > hashend) tend = hashend;
// verbose (0, "diff: %lld - %lld\n", (long long)pos, (long long)tend - 1);

                if (hashstep == HSMALL) {
                    /* HSMALL? Then write the data */
                    unsigned short blen = tend - pos;
                    char *fbuf = malloc (blen);

                    verbose ( 1, "diff: %lld - %lld\n"
                            , (long long)pos, (long long)tend - 1);

                    pread (devfd, fbuf, blen, pos);

                    fwrite (&pos,  sizeof (pos),  1, stdout);
                    fwrite (&blen, sizeof (blen), 1, stdout);
                    fwrite (fbuf,  1, blen,          stdout);

                    free (fbuf);
                } else {
                    /* Not HSMALL? Then zoom in on the details (HSMALL) */
                    hashmatch (saltsize, salt, rd_fd, wr_fd, devfd, pos, tend, HSMALL, hashstep/HSMALL);
                }
            }
            lp  += HASHSIZE;
            rp  += HASHSIZE;
            pos += hashstep;
        }
        hashstart += hashsteps * hashstep;

        free (lhbuf);
    }
    free (mbuf);
};

int do_client (char *command, char *ldev, char *rdev)
{
    int     rd_fd, wr_fd;
    char    *mbuf = NULL, *msg;
    size_t  buflen, msglen;
    char    token;
    char    salt[SALTSIZE];
    int     ldevfd, maxsteps, hashsteps;
    off64_t ldevsize, rdevsize;
    off64_t hashnext, hashstep;
    char    *lhbuf = NULL,
            *rhbuf = NULL;
    size_t  lhsize, rhsize;
    unsigned short devlen;
    pid_t   pid;

    init_salt (sizeof (salt), salt);

    ldevfd = opendev (ldev, &ldevsize, O_RDONLY);

    pid = do_command (command, &rd_fd, &wr_fd);

    send_hello (wr_fd, "CLIENT");

    char *devfile = NULL;
    char *hello   = NULL;

    int  exp = msg_hello;

    msg_read (rd_fd, &mbuf, &buflen, &token, &msg, &msglen, MSGMAX);
    check_token ("", token, msg_hello);
    parse_hello (msg, msglen, &hello);
    send_devfile (wr_fd, rdev);

    msg_read (rd_fd, &mbuf, &buflen, &token, &msg, &msglen, MSGMAX);
    check_token ("", token, msg_size);
    parse_size (msg, msglen, &rdevsize);
    if (rdevsize != ldevsize) {
        verbose (0, "Different sizes local=%lld remote=%lld\n", ldevsize, rdevsize);
        exit (1);
    }

    devlen = strlen (rdev);
    printf ("%s\n", ARCHVER);
    fwrite (&rdevsize,  sizeof (rdevsize),  1, stdout);
    fwrite (&devlen,    sizeof (devlen),    1, stdout);
    fwrite (rdev,       1,             devlen, stdout);

    send_salt (wr_fd, sizeof (salt), salt);

    hashmatch (SALTSIZE, salt, rd_fd, wr_fd, ldevfd, 0, ldevsize, HLARGE, HMAXCNT);
    // finish the bdsync archive
    {
        off64_t        pos  = 0;
        unsigned short blen = 0;

        fwrite (&pos,  sizeof (pos),  1, stdout);
        fwrite (&blen, sizeof (blen), 1, stdout);
    }

    free (mbuf);

};

int do_patch (char *dev)
{
    int     devfd, len;
    off64_t devsize, tdevsize;
    int     bufsize = 4096;
    char    *buf = malloc (bufsize);
    off64_t lpos;
    int     bytct = 0, blkct = 0, segct = 0;
    unsigned short devlen;
    char    *devname;

    if (!fgets (buf, bufsize - 1, stdin)) {
        verbose (0, "do_patch: fgets: %s\n", strerror (errno));
        exit (1);
    }
    len = strlen (buf);
    if (buf[len-1] != '\n' || strncmp (buf, "BDSYNC ", 7)) {
        verbose (0, "Bad header\n");
        exit (1);
    }
    if (len-1 != strlen (ARCHVER) || strncmp (buf, ARCHVER, len-1)) {
        verbose (0, "Bad archive version\n");
        exit (1);
    }

    if (   fread (&tdevsize, 1, sizeof (tdevsize), stdin) != sizeof (tdevsize)
        || fread (&devlen,   1, sizeof (devlen),   stdin) != sizeof (devlen)
        || devlen > 16384) {
        verbose (0, "Bad data\n");
        exit (1);
    }
    devname = malloc (devlen + 1);
    if (fread (devname, 1, devlen, stdin) != devlen) {
        verbose (0, "Bad data\n");
        exit (1);
    }
    devname[devlen] = '\0';
    if (dev == NULL) {
        dev = devname;
    } else {
        if (strcmp (dev, devname)) {
            verbose (0, "Warning: different device names parameter=%s data=%s\n", dev, devname);
        }
        free (devname);
    }

    devfd = opendev (dev, &devsize, O_RDWR);

    if (tdevsize != devsize) {
        verbose (0, "Sizes don't match device=%lld input=%lld\n", devsize, tdevsize);
        exit (1);
    }

    lpos = -1;

    for (;;) {
        off64_t        pos;
        unsigned short blen;

        if (   fread (&pos,  1, sizeof (pos),  stdin) != sizeof (pos)
            || fread (&blen, 1, sizeof (blen), stdin) != sizeof (blen)
            || blen < 0 || pos + blen > devsize) {
            verbose (0, "Bad data\n");
            exit (1);
        }
        if (pos == 0 && blen == 0) break;

        bytct += blen;
        blkct++;
        if (pos != lpos) segct++;

        if (bufsize < blen) {
            free (buf);
            bufsize = blen;
            buf = malloc (bufsize);
        }
        if (fread (buf, 1, blen, stdin) != blen) {
            verbose (0, "Bad data\n");
            exit (1);
        }
        verbose (2, "do_patch: write: pos=%lld len=%d\n", (long long)pos, blen);
        if (pwrite (devfd, buf, blen, pos) != blen) {
            verbose (0, "Write error: pos=%lld len=%d\n", (long long)pos, blen);
            exit (1);
        }
        lpos = pos + blen;
    }

    free (buf);
};

static struct option long_options[] = {
      {"server",  no_argument,       0, 's' }
    , {"patch",   optional_argument, 0, 'p' }
    , {"verbose", no_argument,       0, 'v' }
    , {0,         0,                 0,  0  }
};

int main (int argc, char *argv[])
{
    char buf[4096];
    size_t len;

    int  isserver  = 0;
    int  ispatch   = 0;
    char *patchdev = NULL;

    for (;;) {
        int this_option_optind = optind ? optind : 1;
        int option_index = 0;
        int c;

        c = getopt_long ( argc, argv, "sp::v"
                        , long_options, &option_index);

        if (c == -1) break;

        switch (c) {
        case 's':
            isserver = 1;
            break;
        case 'p':
            ispatch  = 1;
            patchdev = (optarg ? optarg : NULL);
            break;
        case 'v':
            isverbose++;
            break;
        case '?':
            return 1;
        }
    }
    vhandler = verbose_printf;

    if (isserver && ispatch) {
        fprintf (stderr, "Contradictive options --server and --patch\n");
        exit (1);
    }

    if (ispatch) {
        if (optind != argc) {
            verbose (0, "Bad number of arguments\n");
            return 1;
        }
        return do_patch (patchdev);
    }

    if (isserver) {
        vhandler = verbose_syslog;
        if (optind != argc) {
            verbose (0, "Bad number of arguments\n");
            return 1;
        }
        return do_server ();
    }

    // client
    if (optind != argc - 3) {
        verbose (0, "Bad number of arguments\n");
        return 1;
    }
    return do_client (argv[optind], argv[optind + 1],argv[optind + 2]);
}
