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
// * 0.6 Jul 14 2013 Rolf Fokkens <rolf@rolffokkens.nl>
// - asynchronous implementation to handle delay
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
#include <poll.h>

/* max total queuing write data
#define MAXWRQUEUE 131072

/* msg size is stored in an int */
#define MSGMAX 131072
#define ARGMAX 256

#define HASHSIZE 32
#define SALTSIZE 32

#define ARCHVER "BDSYNC 0.2"
#define PROTOVER "0.3"

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

void set_nonblocking(int fd)
{
        int val;

        if ((val = fcntl(fd, F_GETFL)) == -1)
                return;
        if (!(val & O_NONBLOCK)) {
                val |= O_NONBLOCK;
                fcntl(fd, F_SETFL, val);
        }
};

struct msg {
    size_t len;
    struct msg *pnxt;
    char   data[];
};

enum qstate {
    qhdr  = 1
,   qdata
};

struct wr_queue {
    size_t len;
    struct msg *phd, *ptl;
    size_t pos; /* refers to write pos in head msg */
    int    wr_fd;
    char   tlen [sizeof (u_int32_t)];
    int    state;
};

struct rd_queue {
    size_t len;
    struct msg *phd, *ptl;
    size_t pos;  /* refers to read pos in head msg */
    int    rd_fd;
    char   tlen [sizeof (u_int32_t)];
    int    state;
};

void init_wr_queue (struct wr_queue *pqueue, int wr_fd)
{
    pqueue->len   = 0;
    pqueue->phd   = NULL;
    pqueue->ptl   = NULL;
    pqueue->pos   = 0;
    pqueue->wr_fd = wr_fd;
    pqueue->state = qhdr;

    set_nonblocking (wr_fd);
}

void init_rd_queue (struct rd_queue *pqueue, int rd_fd)
{
    pqueue->len   = 0;
    pqueue->phd   = NULL;
    pqueue->ptl   = NULL;
    pqueue->pos   = 0;
    pqueue->rd_fd = rd_fd;
    pqueue->state = qhdr;

    set_nonblocking (rd_fd);
}

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

pid_t do_command (char *command, struct rd_queue *prd_queue, struct wr_queue *pwr_queue)
{
    int i, argc = 0;
    char *t, *f, *args[ARGMAX];
    pid_t pid;
    int dash_l_set = 0, in_quote = 0;
    int f_in, f_out;

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

    pid = piped_child (args, &f_in, &f_out);

    free (command);

    init_rd_queue (prd_queue, f_in);
    init_wr_queue (pwr_queue, f_out);

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

int add_wr_queue (struct wr_queue *pqueue, char token, char *buf, size_t len)
{
    struct msg *pmsg;

    verbose (2, "add_wr_queue: msg = %s, len = %d\n", msgstring[token], len);

    pmsg = (struct msg *) malloc (sizeof (struct msg) + len + 1);

    pmsg->len     = len + 1;
    pmsg->data[0] = token;
    memcpy (pmsg->data + 1, buf, len);
    pmsg->pnxt    = NULL;

    if (pqueue->ptl) {
        pqueue->ptl->pnxt = pmsg;
    } else {
        pqueue->phd = pmsg;
    }
    pqueue->ptl  = pmsg;
    pqueue->len += (sizeof (pqueue->tlen) + len + 1);
}

int flush_wr_queue (struct wr_queue *pqueue)
{
    size_t retval = 0, len, tmp;
    struct msg *phd;
    char   *pwr;

    verbose (3, "flush_wr_queue: len = %lld\n",  (long long)pqueue->len);

    while ((phd = pqueue->phd) != NULL) {
        if (pqueue->state == qhdr) {
            len = sizeof (pqueue->tlen) - pqueue->pos;
            if (len == 0) {
                pqueue->state = qdata;
                pqueue->pos   = 0;
                continue;
            }
            if (pqueue->pos == 0) {
                int2char (pqueue->tlen, phd->len, sizeof (pqueue->tlen));
            }
            pwr = pqueue->tlen + pqueue->pos;
        } else {
            len = phd->len - pqueue->pos;
            if (len == 0) {
                verbose (2, "flush_wr_queue: msg = %s, len = %d\n", msgstring[phd->data[0]], phd->len);

                pqueue->state = qhdr;
                pqueue->pos   = 0;
                pqueue->phd   = phd->pnxt;
                if (phd->pnxt == NULL) pqueue->ptl = NULL;
                free (phd);
                continue;
            }
            pwr = phd->data + pqueue->pos;
        }

        tmp = write (pqueue->wr_fd, pwr, len);
        if (tmp == 0) break;
        if (tmp == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) break;
            verbose (0, "flush_wr_queue: %s\n", strerror (errno));
            exit (1);
        }
        retval      += tmp;
        pqueue->pos += tmp;

        verbose (3, "flush_wr_queue: len = %lld\n",  (long long int)(pqueue->len - retval));
    }
    pqueue->len -= retval;

    return retval;
}

int fill_rd_queue (struct rd_queue *pqueue)
{
    char      *prd;
    size_t retval = 0, len, tmp;

    verbose (3, "fill_rd_queue: len = %lld\n",  (long long)pqueue->len);

    for (;;) {
        if (pqueue->state == qhdr) {
            len = sizeof (pqueue->tlen) - pqueue->pos;
            if (len == 0) {
                struct msg *pmsg;
                len = char2int ((char *)pqueue->tlen, sizeof (pqueue->tlen));
                if (len > MSGMAX) {
                    verbose (0, "fill_rd_queue: bad msg size %d\n", (int)len);
                    exit (1);
                }

                pmsg       = malloc (sizeof (struct msg) + len + 1);
                pmsg->pnxt = NULL;
                pmsg->len  = len;

                if (pqueue->ptl) {
                    pqueue->ptl->pnxt = pmsg;
                } else {
                    pqueue->phd = pmsg;
                }
                pqueue->ptl   = pmsg;
                pqueue->state = qdata;
                pqueue->pos   = 0;
                continue;
            }
            prd = (char *)(pqueue->tlen) + pqueue->pos;
        } else {
            len = pqueue->ptl->len - pqueue->pos;
            if (len == 0) {
                verbose (2, "fill_rd_queue: msg = %s, len = %d\n", msgstring[pqueue->ptl->data[0]], (int)pqueue->ptl->len);

                pqueue->state = qhdr;
                pqueue->pos   = 0;

                continue;
            }
            prd = pqueue->ptl->data + pqueue->pos;

        }
        tmp = read (pqueue->rd_fd, prd, len);
        if (tmp == 0) {
            verbose (0, "fill_rd_queue: EOF\n");
            exit (1);
        }
        if (tmp == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) break;
            verbose (0, "fill_rd_queue: %s\n", strerror (errno));
            exit (1);
        }
        pqueue->pos += tmp;
        if (pqueue->state == qdata) retval += tmp;

        verbose (3, "fill_rd_queue: len = %lld\n",  (long long)(pqueue->len - retval));
    }
    pqueue->len += retval;

    return retval;
}

int get_rd_queue (struct wr_queue *pwr_queue, struct rd_queue *prd_queue, char *token, char **msg, size_t *msglen)
{
    struct pollfd pfd[2];
    struct msg    *phd;
    int           tmp, nfd;

    while (prd_queue->state != qhdr || prd_queue->phd == NULL) {
        pfd[0].fd     = prd_queue->rd_fd;
        pfd[0].events = POLLIN;

        pfd[1].fd     = pwr_queue->wr_fd;
        pfd[1].events = (pwr_queue->phd ? POLLOUT: 0);

        tmp = poll (pfd, 2, -1);

        verbose (3, "get_rd_queue: poll %d\n", tmp);

        if (pfd[0].revents & POLLIN)  fill_rd_queue (prd_queue);
        if (pfd[1].revents & POLLOUT) flush_wr_queue (pwr_queue);
    }

    phd = prd_queue->phd;

    *token  = phd->data[0];
    *msg    = (char *)malloc (phd->len);
    *msglen = phd->len - 1;
    memcpy (*msg, phd->data + 1, phd->len - 1);

    prd_queue->len -= (sizeof (prd_queue->tlen) + phd->len + 1);
    prd_queue->phd  = phd->pnxt;
    if (phd->pnxt == NULL) prd_queue->ptl = NULL;

    return 0;
}

int send_msgstring (struct wr_queue *pqueue, int msg, char *str)
{
    // size_t len = strlen (str);
    // char *buf = malloc (len + 1);

    add_wr_queue (pqueue, msg, str, strlen (str));
}

int send_hello (struct wr_queue *pqueue, char *hello)
{
    char buf[16];

    sprintf (buf, "%s %s", hello, PROTOVER);

    verbose (1, "send_hello: hello = %s, version = %s\n", hello, PROTOVER);

    send_msgstring (pqueue, msg_hello, buf);
}

int send_devfile (struct wr_queue *pqueue, char *devfile)
{
    verbose (1, "send_devfile: devfile = %s\n", devfile);

    send_msgstring (pqueue, msg_devfile, devfile);
}

int send_size (struct wr_queue *pqueue, off64_t devsiz)
{
    char tbuf[sizeof (devsiz)];

    verbose (1, "send_size: devsiz = %lld\n", (long long)devsiz);

    int2char (tbuf, devsiz, sizeof (devsiz));

    return add_wr_queue (pqueue, msg_size, tbuf, sizeof (devsiz));
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

int send_salt (struct wr_queue *pqueue, int saltsize, char *salt)
{
    char *tmp = bytes2str (saltsize, salt);

    verbose (1, "send_salt: salt = %s\n", tmp);

    free (tmp);

    return add_wr_queue (pqueue, msg_salt, salt, saltsize);
}

int send_gethash (struct wr_queue *pqueue, off64_t start, off64_t step, int nstep)
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

    return add_wr_queue (pqueue, msg_gethash, tbuf, sizeof (par));
};

int send_hashes (struct wr_queue *pqueue, off64_t start, off64_t step, int nstep, char *buf, size_t siz)
{
    off64_t par[3];
    char    *tbuf, *cp;
    int     i;

    par[0] = start;
    par[1] = step;
    par[2] = nstep;

    verbose (1, "send_hashes: size=%d\n", (int)siz);

    tbuf = malloc (sizeof (par) + siz);

    for (i = 0, cp = tbuf; i < 3; i++, cp += sizeof (par[0])) {
        int2char (cp, par[i], sizeof (par[0]));
    }

    memcpy (cp, buf, siz);

    return add_wr_queue (pqueue, msg_hashes, tbuf, sizeof (par) + siz);

    free (tbuf);
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

int parse_hashes ( char *msgbuf, size_t msglen
                 , off64_t *start, off64_t *step, int *nstep, char **hbuf)
{
    off64_t par[3];
    int     i;

    if (msglen < sizeof (par)) {
        verbose (0, "parse_hashes: bad size=%lld minimum=%lld\n", (long long)msglen, (long long)(sizeof (par)));
        exit (1);
    }

    for (i = 0; i < 3; i++, msgbuf += sizeof (par[0])) {
        par[i] = char2int (msgbuf, sizeof (par[0]));
    }

    *start = par[0];
    *step  = par[1];
    *nstep = par[2];

    if (msglen != sizeof (par) + *nstep * HASHSIZE) {
        verbose (0, "parse_hashes: bad size=%lld expected=%lld\n", (long long)msglen, (long long)(sizeof (par) + *nstep * HASHSIZE));
        exit (1);
    }

    *hbuf = malloc (*nstep * HASHSIZE);
    memcpy (*hbuf, msgbuf, *nstep * HASHSIZE);

    verbose (1, "parse_hashes: start=%lld, step=%lld, nstep=%d\n", (long long)*start, (long long)*step, *nstep);
};

int gen_hashes ( struct rd_queue *prd_queue, struct wr_queue *pwr_queue
               , int saltsize, char *salt
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
        flush_wr_queue (pwr_queue);
        fill_rd_queue (prd_queue);

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
    char    *msg;
    size_t  msglen;
    char    token;
    int     devfd, nstep;
    int     saltsize = 0;
    off64_t devsiz, start, step;
    char    *hbuf;
    size_t  hsize;
    char    *salt;
    struct  wr_queue wr_queue;
    struct  rd_queue rd_queue;

    init_wr_queue (&wr_queue, STDOUT_FILENO);
    init_rd_queue (&rd_queue, STDIN_FILENO);

    verbose (1, "started\n");

    send_hello (&wr_queue, "SERVER");

    char *devfile = NULL;
    char *hello   = NULL;

    int  exp = msg_hello;

    for (;;) {
        flush_wr_queue (&wr_queue);
        get_rd_queue (&wr_queue, &rd_queue, &token, &msg, &msglen);

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
            send_size (&wr_queue, devsiz);
            break;
        case msg_salt:
            parse_salt (&msg, msglen, &saltsize, &salt);
            break;
        case msg_gethash:
            parse_gethash (msg, msglen, &start, &step, &nstep);
            gen_hashes (&rd_queue, &wr_queue, saltsize, salt, &hbuf, &hsize, devfd, start, step, nstep);
            send_hashes (&wr_queue, start, step, nstep, hbuf, hsize);
            free (hbuf);
            break;
        default:
            exit (1);
            break;
        }
    }
    free (msg);
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
//#define HMAXCNT (((MSGMAX)/HASHSIZE)-1)
#define HMAXCNT (HLARGE/HSMALL)

int hashmatch ( int saltsize, char *salt
              , size_t devsize
              , struct rd_queue *prd_queue, struct wr_queue *pwr_queue, int devfd
              , off64_t hashstart, off64_t hashend, off64_t hashstep
              , int maxsteps
              , int *hashreqs
              , int recurs)
{
    int     hashsteps;
    char    *rhbuf;
    char    *lhbuf;
    size_t  lhsize, rhsize;
    char    *msg;
    size_t  buflen, msglen;
    char    token;

    off64_t rstart, rstep;
    int     rnstep;


    verbose (2, "hashmatch: recurs=%d hashstart=%lld hashend=%lld hashstep=%lld maxsteps=%d\n"
            , recurs, (long long)hashstart, (long long)hashend, (long long)hashstep, maxsteps);

    while ((hashstart < hashend) || ((recurs == 0) && (*hashreqs != 0))) {
        while ((hashstart < hashend) && (recurs || *hashreqs < 32)) {
            hashsteps = (hashend + hashstep - 1 - hashstart) / hashstep;
            if (hashsteps > maxsteps) hashsteps = maxsteps;
            if (!hashsteps) break;

            /* Put the other side to work generating hashes */
            send_gethash (pwr_queue, hashstart, hashstep, hashsteps);
            hashstart += hashsteps * hashstep;
            (*hashreqs)++;
        }
        verbose (3, "hashmatch: hashreqs=%d\n", *hashreqs);

        if (recurs) break;

        if (*hashreqs == 0) continue;

        /* Get the other side's hashes */
        get_rd_queue (pwr_queue, prd_queue,  &token, &msg, &msglen);
        (*hashreqs)--;

        check_token ("", token, msg_hashes);

        parse_hashes (msg, msglen, &rstart, &rstep, &rnstep, &rhbuf);

        free (msg);

        /* Generate our own list of hashes */
        gen_hashes (prd_queue, pwr_queue, saltsize, salt, &lhbuf, &lhsize, devfd, rstart, rstep, rnstep);

        off64_t pos = rstart;
        char    *lp = lhbuf, *rp = rhbuf;
        int     ns = rnstep;

        while (ns--) {
            if (bcmp (lp, rp, HASHSIZE)) {
                off64_t tend = pos + rstep;

                if (tend > devsize) tend = devsize;

                if (rstep == HSMALL) {
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
                    hashmatch (saltsize, salt, devsize, prd_queue, pwr_queue, devfd, pos, tend, HSMALL, rstep/HSMALL, hashreqs, recurs + 1);
                }
            }
            lp  += HASHSIZE;
            rp  += HASHSIZE;
            pos += rstep;
        }
        free (lhbuf);
    }

    verbose (2, "hashmatch: recurs=%d\n", recurs);
};

int do_client (char *command, char *ldev, char *rdev)
{
    char    *msg;
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
    struct  wr_queue wr_queue;
    struct  rd_queue rd_queue;

    init_salt (sizeof (salt), salt);

    ldevfd = opendev (ldev, &ldevsize, O_RDONLY);

    pid = do_command (command, &rd_queue, &wr_queue);

    send_hello (&wr_queue, "CLIENT");

    char *devfile = NULL;
    char *hello   = NULL;

    int  exp = msg_hello;

    get_rd_queue (&wr_queue, &rd_queue, &token, &msg, &msglen);
    check_token ("", token, msg_hello);
    parse_hello (msg, msglen, &hello);
    send_devfile (&wr_queue, rdev);
    free (msg);

    get_rd_queue (&wr_queue, &rd_queue, &token, &msg, &msglen);
    check_token ("", token, msg_size);
    parse_size (msg, msglen, &rdevsize);
    free (msg);
    if (rdevsize != ldevsize) {
        verbose (0, "Different sizes local=%lld remote=%lld\n", ldevsize, rdevsize);
        exit (1);
    }

    devlen = strlen (rdev);
    printf ("%s\n", ARCHVER);
    fwrite (&rdevsize,  sizeof (rdevsize),  1, stdout);
    fwrite (&devlen,    sizeof (devlen),    1, stdout);
    fwrite (rdev,       1,             devlen, stdout);

    send_salt (&wr_queue, sizeof (salt), salt);

    int hashreqs = 0;

    hashmatch (SALTSIZE, salt, ldevsize, &rd_queue, &wr_queue, ldevfd, 0, ldevsize, HLARGE, HMAXCNT, &hashreqs, 0);

    // finish the bdsync archive
    {
        off64_t        pos  = 0;
        unsigned short blen = 0;

        fwrite (&pos,  sizeof (pos),  1, stdout);
        fwrite (&blen, sizeof (blen), 1, stdout);
    }

    return 0;
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
