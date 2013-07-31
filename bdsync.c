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
// * 0.7 Jul 31 2013 Rolf Fokkens <rolf@rolffokkens.nl>
// - option to generate a checksum for the source data
// - options to choose digests
//

#define _LARGEFILE64_SOURCE

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include <openssl/evp.h>
#include <netdb.h>
#include <sys/socket.h>
#include <stdarg.h>
#include <syslog.h>
#include <errno.h>
#include <poll.h>

#define RDAHEAD (1024*1024)

/* max total queuing write data */
#define MAXWRQUEUE 131072

/* msg size is stored in an int */
#define MSGMAX 131072
#define ARGMAX 256

#define SALTSIZE 32

#define ARCHVER "BDSYNC 0.3"
#define PROTOVER "0.4"

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
,   qeof
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
    int argc = 0;
    char *t, *f, *args[ARGMAX];
    pid_t pid;
    int in_quote = 0;
    int f_in, f_out;

    command = strdup (command);

    for (t = f = command; *f; f++) {
        if (*f == ' ') continue;
        /* Comparison leaves rooms for server_options(). */
        if (argc >= ARGMAX - 1) {
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
    args[argc] = NULL;

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
,   msg_digest
,   msg_gethash
,   msg_hashes
,   msg_done
,   msg_max
};

static char *msgstring[] = {
   ""
,  "hello"
,  "devfile"
,  "size"
,  "digest"
,  "gethash"
,  "hashes"
,  "done"
};

int msg_write (int fd, unsigned char token, char *buf, size_t len)
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

int add_wr_queue (struct wr_queue *pqueue, unsigned char token, char *buf, size_t len)
{
    struct msg *pmsg;

    verbose (2, "add_wr_queue: msg = %s, len = %d\n", msgstring[token], len);

    if (pqueue->state == qeof) {
        verbose (0, "add_wr_queue: EOF\n");
        exit (1);
    }

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

    return 0;
}

int flush_wr_queue (struct wr_queue *pqueue, int wait)
{
    size_t retval = 0, len, tmp;
    struct msg *phd;
    char   *pwr;

    verbose (3, "flush_wr_queue: wait = %d, len = %lld\n",  wait, (long long)pqueue->len);

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
                verbose (3, "flush_wr_queue: msg = %s, len = %d\n", msgstring[(unsigned char)(phd->data[0])], phd->len - 1);

                pqueue->state = qhdr;
                pqueue->pos   = 0;
                pqueue->phd   = phd->pnxt;
                if (phd->pnxt == NULL) pqueue->ptl = NULL;
                free (phd);
                continue;
            }
            pwr = phd->data + pqueue->pos;
        }

        if (wait) {
            struct pollfd pfd;

            pfd.fd     = pqueue->wr_fd;
            pfd.events = POLLOUT;

            tmp = poll (&pfd, 1, -1);

            if (pfd.revents) {
                if (!(pfd.revents & POLLOUT)) {
                    verbose (0, "flush_wr_queue: poll error on fd %d\n", pfd.fd);
                    exit (1);
                }
            }
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

    while (pqueue->state != qeof) {
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
                verbose (3, "fill_rd_queue: msg = %s, len = %d\n", msgstring[(unsigned char)(pqueue->ptl->data[0])], (int)pqueue->ptl->len - 1);

                pqueue->state = qhdr;
                pqueue->pos   = 0;

                continue;
            }
            prd = pqueue->ptl->data + pqueue->pos;

        }
        tmp = read (pqueue->rd_fd, prd, len);
        if (tmp == 0) {
            /* When reading the header at pos 0 it's OK */
            if (pqueue->state == qhdr && pqueue->pos == 0) {
                pqueue->state = qeof;
                verbose (3, "fill_rd_queue: eof\n");
                continue;
            }
            verbose (0, "fill_rd_queue: EOF\n");
            exit (1);
        }
        if (tmp == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) break;
            verbose (0, "fill_rd_queue: %s\n", strerror (errno));
            exit (1);
        }
        pqueue->pos += tmp;
        retval += tmp;

        verbose (3, "fill_rd_queue: len = %lld\n",  (long long)(pqueue->len + retval));
    }
    pqueue->len += retval;

    return retval;
}

struct timeval get_rd_wait = {0, 0};

int get_rd_queue (struct wr_queue *pwr_queue, struct rd_queue *prd_queue, unsigned char *token, char **msg, size_t *msglen)
{
    struct pollfd  pfd[2];
    struct msg     *phd;
    int            tmp, nfd;
    struct timeval tv1, tv2;

    gettimeofday (&tv1, NULL);

    while (    prd_queue->state != qeof
           && (prd_queue->state != qhdr || prd_queue->phd == NULL)) {
        pfd[0].fd     = prd_queue->rd_fd;
        pfd[0].events = POLLIN;

        pfd[1].fd     = pwr_queue->wr_fd;
        pfd[1].events = (pwr_queue->phd ? POLLOUT: 0);

        nfd = (pwr_queue->state == qeof ? 1 : 2);
        tmp = poll (pfd, nfd, -1);

        verbose (3, "get_rd_queue: poll %d\n", tmp);

        if (pfd[0].revents & POLLIN)  fill_rd_queue (prd_queue);
        if (pfd[1].revents) {
            if (pfd[1].revents & POLLOUT) {
                flush_wr_queue (pwr_queue, 0);
            } else {
                if (pfd[1].revents & POLLHUP) {
                    if (pwr_queue->phd == NULL) {
                        pwr_queue->state = qeof;
                        verbose (3, "get_rd_queue: poll pollhup\n");
                    } else {
                        verbose (0, "get_rd_queue: poll POLLHUP\n");
                        exit (1);
                    }
                } else {
                    verbose (0, "get_rd_queue: poll error on fd %d\n", pfd[1].fd);
                    exit (1);
                }
            }
        }
    }

    gettimeofday (&tv2, NULL);

    tv2.tv_sec  -= tv1.tv_sec;
    tv2.tv_usec -= tv1.tv_usec;

    if (tv2.tv_usec < 0) {
        tv2.tv_usec += 1000000;
        tv2.tv_sec  -= 1;
    }

    verbose (2, "get_rd_queue: wait = %d.%06d\n", tv2.tv_sec, tv2.tv_usec);

    get_rd_wait.tv_sec  += tv2.tv_sec;
    get_rd_wait.tv_usec += tv2.tv_usec;

    if (get_rd_wait.tv_usec >= 1000000) {
        get_rd_wait.tv_usec -= 1000000;
        get_rd_wait.tv_sec  += 1;
    }

    phd = prd_queue->phd;

    if (phd == NULL) {
        verbose (0, "get_rd_queue: EOF %d\n", pfd[1].fd);
        exit (1);
    }

    *token  = phd->data[0];
    *msg    = (char *)malloc (phd->len);
    *msglen = phd->len - 1;
    memcpy (*msg, phd->data + 1, phd->len - 1);

    prd_queue->len -= (sizeof (prd_queue->tlen) + phd->len);
    prd_queue->phd  = phd->pnxt;
    if (phd->pnxt == NULL) prd_queue->ptl = NULL;

    verbose (2, "get_rd_queue: msg = %s, len = %d\n", msgstring[*token], *msglen);

    return 0;
}

int send_msgstring (struct wr_queue *pqueue, int msg, char *str)
{
    // size_t len = strlen (str);
    // char *buf = malloc (len + 1);

    return add_wr_queue (pqueue, msg, str, strlen (str));
}

int send_hello (struct wr_queue *pqueue, char *hello)
{
    char buf[16];

    sprintf (buf, "%s %s", hello, PROTOVER);

    verbose (1, "send_hello: hello = %s, version = %s\n", hello, PROTOVER);

    return send_msgstring (pqueue, msg_hello, buf);
}

int send_devfile (struct wr_queue *pqueue, char *devfile)
{
    verbose (1, "send_devfile: devfile = %s\n", devfile);

    return send_msgstring (pqueue, msg_devfile, devfile);
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
        sprintf (tmp, "%02x", (*p & 0x0ff));
        tmp += 2;
        p++;
        s--;
    }

    return ret;
};

int send_digest (struct wr_queue *pqueue, int saltsize, char *salt, char *digest)
{
    char   *tmp = bytes2str (saltsize, salt);
    char   *cp, *buf;
    size_t buflen;
    int    ret;

    if (saltsize > 127) {
        verbose (0, "send_digest: bad saltsize %d\n", saltsize);
        exit (1);
    }

    if (!digest[0]) {
        verbose (0, "send_digest: empty digest\n");
        exit (1);
    }

    verbose (1, "send_digest: salt = %s, digest = %s\n", tmp, digest);

    free (tmp);

    buflen = 1 + saltsize + strlen (digest);
    buf    = malloc (buflen);
    cp     = buf;

    *cp++ = (char) saltsize;
    memcpy (cp, salt, saltsize);
    cp += saltsize;

    memcpy (cp, digest, strlen (digest));

    ret = add_wr_queue (pqueue, msg_digest, buf, buflen);

    free (buf);

    return ret;
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

int send_hashes (struct wr_queue *pqueue, off64_t start, off64_t step, int nstep, unsigned char *buf, size_t siz)
{
    off64_t par[3];
    char    *tbuf, *cp;
    int     ret, i;

    par[0] = start;
    par[1] = step;
    par[2] = nstep;

    verbose (1, "send_hashes: size=%d\n", (int)siz);

    tbuf = malloc (sizeof (par) + siz);

    for (i = 0, cp = tbuf; i < 3; i++, cp += sizeof (par[0])) {
        int2char (cp, par[i], sizeof (par[0]));
    }

    memcpy (cp, buf, siz);

    ret = add_wr_queue (pqueue, msg_hashes, tbuf, sizeof (par) + siz);

    free (tbuf);

    return ret;
};

int send_done (struct wr_queue *pqueue)
{
    char buf[1];

    verbose (1, "send_done\n");

    return add_wr_queue (pqueue, msg_done, buf, 0);
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

int msg_read (int fd, char **buf, size_t *buflen, unsigned char *token, char **msg, size_t *msglen, int maxlen)
{
    u_int32_t tmp;
    char      tbuf[sizeof(tmp)];

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

    return 0;
};

int parse_digest (char *msgbuf, size_t msglen, int *saltsize, char **salt, const EVP_MD **md)
{
    char *tmp;
    char *digest;

    if (msglen < 1) {
        verbose (0, "parse_digest: bad size=%lld\n", (long long)msglen);
        exit (1);
    }

    *saltsize = (int)(*msgbuf++);
    if (msglen < *saltsize + 1) {
        if (msglen < 1) {
            verbose (0, "parse_digest: bad size=%lld, salt size = %d\n", (long long)msglen, *saltsize);
            exit (1);
        }
    }

    *salt = malloc (*saltsize);
    memcpy (*salt, msgbuf, *saltsize);

    msgbuf += *saltsize;
    msglen -= *saltsize + 1;

    if (msglen < 1) {
        verbose (0, "parse_digest: missing digest\n");
        exit (1);
    }

    digest = malloc (msglen + 1);
    memcpy (digest, msgbuf, msglen);
    digest[msglen] = '\0';

    *md = EVP_get_digestbyname (digest);

    if (!*md) {
        verbose (0, "parse_digest: bad digest %s\n", digest);
        exit (1);
    }

    tmp = bytes2str (*saltsize, *salt);
    verbose (1, "parse_digest: salt = %s, digest = %s\n", tmp, digest);

    free (digest);

    free (tmp);

    return 0;
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

int parse_hashes ( int hashsize, char *msgbuf, size_t msglen
                 , off64_t *start, off64_t *step, int *nstep, unsigned char **hbuf)
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

    if (msglen != sizeof (par) + *nstep * hashsize) {
        verbose (0, "parse_hashes: bad size=%lld expected=%lld\n", (long long)msglen, (long long)(sizeof (par) + *nstep * hashsize));
        exit (1);
    }

    *hbuf = malloc (*nstep * hashsize);
    memcpy (*hbuf, msgbuf, *nstep * hashsize);

    verbose (1, "parse_hashes: start=%lld, step=%lld, nstep=%d\n", (long long)*start, (long long)*step, *nstep);

    return 0;
};

int parse_done (char *msgbuf, size_t msglen)
{
    if (msglen != 0) {
        verbose (0, "parse_done: bad size=%lld\n", (long long)msglen);
        exit (1);
    }
    verbose (1, "parse_done\n");

    return 0;
};

int gen_hashes ( const EVP_MD *md, EVP_MD_CTX *cs_ctx
               , struct rd_queue *prd_queue, struct wr_queue *pwr_queue
               , int saltsize, char *salt
               , unsigned char **retbuf, size_t *retsiz, int fd
               , off64_t start, off64_t step, int nstep)
{
    unsigned char *buf, *fbuf;
    off64_t    nrd;
    int        hashsize = EVP_MD_size (md);
    EVP_MD_CTX *ctx;

    *retsiz = nstep * hashsize;
    buf     = malloc (nstep * hashsize);
    *retbuf = buf;

    verbose (1, "gen_hashes: start=%lld step=%lld nstep=%d\n"
            , (long long) start, (long long) step, nstep);

    lseek64 (fd, start, SEEK_SET);

    fbuf    = malloc (step);

    while (nstep) {
        flush_wr_queue (pwr_queue, 0);
        fill_rd_queue (prd_queue);

        nrd = read (fd, fbuf, step);

        verbose (3, "gen_hashes: hash: pos=%lld, len=%d\n"
                , (long long) start, nrd);

        posix_fadvise64 (fd, start + step, RDAHEAD, POSIX_FADV_WILLNEED);

        ctx = EVP_MD_CTX_create();
        EVP_DigestInit_ex (ctx, md, NULL);
        EVP_DigestUpdate (ctx, salt, saltsize);
        EVP_DigestUpdate (ctx, fbuf, nrd);
        EVP_DigestFinal_ex (ctx, buf, NULL);
        EVP_MD_CTX_destroy (ctx);

        if (cs_ctx) {
            verbose (3, "gen_hashes: checksum: pos=%lld, len=%d\n"
                    , (long long) start, nrd);

            EVP_DigestUpdate (cs_ctx, fbuf, nrd);
        }

        buf += hashsize;

        if (nrd != step) break;
        nstep--;
        start += step;
    }
    *retsiz = buf - *retbuf;

    free (fbuf);

    return 0;
};

int opendev (char *dev, off64_t *siz, int flags)
{
    int     fd;

    fd = open (dev, flags | O_LARGEFILE);
    if (fd == -1) {
        verbose (0, "opendev [%s]: %s\n", dev, strerror (errno));
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
    unsigned char token;
    int     devfd, nstep;
    int     saltsize = 0;
    off64_t devsiz, start, step;
    unsigned char    *hbuf;
    size_t  hsize;
    char    *salt;
    struct  wr_queue wr_queue;
    struct  rd_queue rd_queue;
    const EVP_MD *md = NULL;

    init_wr_queue (&wr_queue, STDOUT_FILENO);
    init_rd_queue (&rd_queue, STDIN_FILENO);

    verbose (1, "started\n");

    send_hello (&wr_queue, "SERVER");

    char *devfile = NULL;
    char *hello   = NULL;

    int  exp  = msg_hello;
    int  goon = 1;

    while (goon) {
        flush_wr_queue (&wr_queue, 0);
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
        case msg_digest:
            parse_digest (msg, msglen, &saltsize, &salt, &md);
            break;
        case msg_gethash:
            parse_gethash (msg, msglen, &start, &step, &nstep);
            gen_hashes (md, NULL, &rd_queue, &wr_queue, saltsize, salt, &hbuf, &hsize, devfd, start, step, nstep);
            send_hashes (&wr_queue, start, step, nstep, hbuf, hsize);
            free (hbuf);
            break;
        case msg_done:
            parse_done (msg, msglen);
            send_done (&wr_queue);
            goon = 0;
            break;
        default:
            exit (1);
            break;
        }
    }
    flush_wr_queue (&wr_queue, 1);

    /* destroy md? */

    free (msg);

    return 0;
};

int tcp_connect (char *host, char *service)
{
    int n, s;
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
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(n));
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

void check_token (char *f, unsigned char token, unsigned char expect)
{
    if (token == expect) return;
    verbose (0, "%sUnexpected token=%s, expected=%s\n", f, msgstring[token], msgstring[expect]);
    exit (1);
};

#define HSMALL  4096
#define HLARGE  65536
// #define HSMALL  32768
// #define HLARGE  32768

#define MAXHASHES(hashsize) ((MSGMAX-3*sizeof(off64_t))/hashsize)

int hashmatch ( const EVP_MD *md, EVP_MD_CTX *cs_ctx
              , int saltsize, char *salt
              , size_t devsize
              , struct rd_queue *prd_queue, struct wr_queue *pwr_queue, int devfd
              , off64_t hashstart, off64_t hashend, off64_t hashstep, off64_t nextstep
              , int maxsteps
              , int *hashreqs
              , int recurs)
{
    int     hashsteps;
    unsigned char    *rhbuf;
    unsigned char    *lhbuf;
    size_t  lhsize;
    char    *msg;
    size_t  msglen;
    unsigned char    token;

    off64_t rstart, rstep;
    int     rnstep, hashsize;

    verbose (2, "hashmatch: recurs=%d hashstart=%lld hashend=%lld hashstep=%lld maxsteps=%d\n"
            , recurs, (long long)hashstart, (long long)hashend, (long long)hashstep, maxsteps);

    hashsize = EVP_MD_size (md);

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
        get_rd_queue (pwr_queue, prd_queue, &token, &msg, &msglen);
        (*hashreqs)--;

        check_token ("", token, msg_hashes);

        parse_hashes (hashsize, msg, msglen, &rstart, &rstep, &rnstep, &rhbuf);

        free (msg);

        /* Generate our own list of hashes */
        gen_hashes (md, (rstep == hashstep ? cs_ctx : NULL)
                   , prd_queue, pwr_queue, saltsize, salt, &lhbuf, &lhsize, devfd, rstart, rstep, rnstep);

        off64_t pos = rstart;
        unsigned char    *lp = lhbuf, *rp = rhbuf;
        int     ns = rnstep;

        while (ns--) {
            if (bcmp (lp, rp, hashsize)) {
                off64_t tend = pos + rstep;

                if (tend > devsize) tend = devsize;

                if (rstep == nextstep) {
                    /* HSMALL? Then write the data */
                    unsigned short blen = tend - pos;
                    char *fbuf = malloc (blen);

                    verbose ( 3, "diff: %lld - %lld\n"
                            , (long long)pos, (long long)tend - 1);

                    pread (devfd, fbuf, blen, pos);

                    fwrite (&pos,  sizeof (pos),  1, stdout);
                    fwrite (&blen, sizeof (blen), 1, stdout);
                    fwrite (fbuf,  1, blen,          stdout);

                    free (fbuf);
                } else {
                    /* Not HSMALL? Then zoom in on the details (HSMALL) */
                    int tnstep = rstep / nextstep;
                    if (tnstep > MAXHASHES (hashsize)) tnstep = MAXHASHES (hashsize);
                    hashmatch (md, NULL, saltsize, salt, devsize, prd_queue, pwr_queue, devfd, pos, tend, nextstep, nextstep, tnstep, hashreqs, recurs + 1);
                }
            }
            lp  += hashsize;
            rp  += hashsize;
            pos += rstep;
        }
        free (lhbuf);
    }

    verbose (2, "hashmatch: recurs=%d\n", recurs);

    return 0;
};

int do_client (char *digest, char *checksum, char *command, char *ldev, char *rdev, off64_t hlarge, off64_t hsmall)
{
    char    *msg;
    size_t  msglen;
    unsigned char    token;
    char    salt[SALTSIZE];
    int     ldevfd;
    off64_t ldevsize, rdevsize;
    unsigned short devlen;
    struct  wr_queue wr_queue;
    struct  rd_queue rd_queue;
    int     hashsize, cs_hs;

    const EVP_MD *dg_md, *cs_md;
    EVP_MD_CTX   *cs_ctx;

    dg_md = EVP_get_digestbyname (digest);
    if (!dg_md) {
        fprintf (stderr, "Bad hash %s\n", digest);
        exit (1);
    }

    if (checksum) {
        cs_md  = EVP_get_digestbyname (checksum);
        cs_hs  = EVP_MD_size (cs_md);
        cs_ctx = EVP_MD_CTX_create();
        EVP_DigestInit_ex (cs_ctx, cs_md, NULL);
        if (!cs_md) {
            fprintf (stderr, "Bad checksum %s\n", checksum);
            exit (1);
        }
    } else {
        cs_ctx = NULL;
    }

    hashsize = EVP_MD_size (dg_md);

    init_salt (sizeof (salt), salt);

    ldevfd = opendev (ldev, &ldevsize, O_RDONLY);

    do_command (command, &rd_queue, &wr_queue);

    send_hello (&wr_queue, "CLIENT");

    char *hello   = NULL;

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

    send_digest (&wr_queue, sizeof (salt), salt, digest);

    int hashreqs = 0;

    hashmatch (dg_md, cs_ctx, sizeof (salt), salt, ldevsize, &rd_queue, &wr_queue, ldevfd, 0, ldevsize, hlarge, hsmall, MAXHASHES (hashsize), &hashreqs, 0);

    send_done (&wr_queue);
    get_rd_queue (&wr_queue, &rd_queue,  &token, &msg, &msglen);
    check_token ("", token, msg_done);
    parse_done (msg, msglen);

    // finish the bdsync archive
    {
        off64_t        pos  = 0;
        unsigned short blen = 0;

        fwrite (&pos,  sizeof (pos),  1, stdout);
        fwrite (&blen, sizeof (blen), 1, stdout);
    }
    // write hash if requested
    {
        int len;
        unsigned char *buf;

        if (cs_ctx) {
            int clen = strlen (checksum);
            unsigned char *cp;

            len = cs_hs + 1 + clen + 1;
            buf = malloc (len);
            cp = buf;

            *cp++ = clen;

            memcpy (cp, checksum, clen);
            cp += clen;

            *cp++ = cs_hs;
            EVP_DigestFinal_ex (cs_ctx, cp, NULL);
            EVP_MD_CTX_destroy (cs_ctx);
        } else {
            // when no checksum requested report 0 length checksum name
            buf = malloc (1);
            buf[0] = 0;
            len = 1;
        }

        fwrite (buf, len, 1, stdout);

        free (buf);
    }

    verbose (2, "do_client: get_rd_wait = %d.%06d\n", get_rd_wait.tv_sec, get_rd_wait.tv_usec);

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

    {
        unsigned char c;
        int clen;

        if ((fread (&c, 1, sizeof (c), stdin) != 1) || (c > 127)) {
            verbose (0, "Bad data\n");
            exit (1);
        }
        if (c != 0) {
            clen = c;
            char *checksum = malloc (clen + 1);
            if (fread (checksum, 1, clen, stdin) != clen) {
                verbose (0, "Bad data\n");
                exit (1);
            }
            checksum[clen] = '\0';

            if ((fread (&c, 1, sizeof (c), stdin) != 1) || (c > 127)) {
                verbose (0, "Bad data\n");
                exit (1);
            }
            clen = c;
            char *cval = malloc (clen);
            if (fread (cval, 1, clen, stdin) != clen) {
                verbose (0, "Bad data\n");
                exit (1);
            }
            char *tmp = bytes2str (clen, cval);

            verbose (0, "checksum[%s]: %s\n", checksum, tmp);

            free (tmp);
            free (checksum);
            free (cval);
        }
    }

    free (buf);

    return 0;
};

static struct option long_options[] = {
      {"server",    no_argument,       0, 's' }
    , {"patch",     optional_argument, 0, 'p' }
    , {"verbose",   no_argument,       0, 'v' }
    , {"blocksize", required_argument, 0, 'b' }
    , {"hash",      required_argument, 0, 'd' }
    , {"checksum",  required_argument, 0, 'c' }
    , {0,           0,                 0,  0  }
};

int main (int argc, char *argv[])
{
    char *cp;

    off64_t blocksize = 4096, hlarge, hsmall;
    int  isserver  = 0;
    int  ispatch   = 0;
    char *patchdev = NULL;
    char *hash     = NULL;
    char *checksum = NULL;

    OpenSSL_add_all_digests ();

    for (;;) {
        int option_index = 0;
        int c;

        c = getopt_long ( argc, argv, "sp::vb:h:c:"
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
        case 'b':
            blocksize = strtol (optarg, &cp, 10);
            if (cp == optarg || *cp != '\0') {
                fprintf (stderr, "bad number %s\n", optarg);
                return 1;
            }
            break;
        case 'h':
            hash = optarg;
            break;
        case 'c':
            checksum = optarg;
            break;
        case '?':
            return 1;
        }
    }
    vhandler = verbose_printf;

    hsmall = blocksize;
    // hlarge = 64 * hsmall;
    hlarge = hsmall;

    if (checksum && (strlen (checksum) > 127)) {
        verbose (0, "paramater too long for option --checksum\n");
        exit (1);
    }

    if (isserver && ispatch) {
        fprintf (stderr, "Contradictive options --server and --patch\n");
        exit (1);
    }

    if (ispatch || isserver) {
        if (hash) {
            fprintf (stderr, "Contradictive options --hash and --%s\n", (isserver ? "server" : "patch"));
            exit (1);
        }
        if (checksum) {
            fprintf (stderr, "Contradictive options --checksum and --%s\n", (isserver ? "server" : "patch"));
            exit (1);
        }
    }

    if (ispatch) {
        if (optind != argc) {
            verbose (0, "Bad number of arguments %d\n", argc - optind);
            return 1;
        }
        return do_patch (patchdev);
    }

    if (isserver) {
        vhandler = verbose_syslog;
        if (optind != argc) {
            verbose (0, "Bad number of arguments %d\n", argc - optind);
            return 1;
        }
        return do_server ();
    }

    // client
    if (optind != argc - 3) {
        verbose (0, "Bad number of arguments %d\n", argc - optind);
        return 1;
    }

    if (!hash) hash = "md5";

    return do_client (hash, checksum, argv[optind], argv[optind + 1],argv[optind + 2], hlarge, hsmall);
}
