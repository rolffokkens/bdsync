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

// Brief protocol notes:
//
// Client: msg_hello "CLIENT" PROTOVER
// Server: msg_hello "SERVER" PROTOVER
//
// Client: msg_devfile DEVSIZE DEVFILE
// Server: msg_size DEVSIZE
//
// Client: msg_digests SALTSIZE SALT DIGEST [CHECKSUM]
//
// Client: msg_gethashes
// Server: msg_hashes
//
// Client: msg_getblock
// Server: msg_block
//
// Client: msg_gethashes
// Server: msg_hashes
//
// Client: msg_getchecksum
// Server: msg_checksum
//
// Client: msg_done
// Server: msg_done
//

#define _LARGEFILE64_SOURCE
#define _FILE_OFFSET_BITS 64

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include "bdsync-hash.h"
#include <netdb.h>
#include <sys/socket.h>
#include <stdarg.h>
#include <syslog.h>
#include <errno.h>
#include <poll.h>
#include <sys/wait.h>
#ifdef DBG_MTRACE
# include <mcheck.h>
#endif
#include <malloc.h>

#define RDAHEAD (1024*1024)

/* max total queuing write data */
#define MAXWRQUEUE 131072

/* msg size is stored in an int */
#define MSGMAX 131072
#define ARGMAX 256

#define SALTSIZE 32

#define ARCHVER "BDSYNC 0.3"
#define PROTOVER "0.5"

enum exitcode {
    exitcode_success = 0
,   exitcode_invalid_params = 1
,   exitcode_invalid_patch_format = 2
,   exitcode_diffsize_mismatch = 3
,   exitcode_protocol_error = 4
,   exitcode_checksum_error = 5
,   exitcode_read_error = 6
,   exitcode_source_randomness_error = 7
,   exitcode_process_error = 8
,   exitcode_write_error = 9
,   exitcode_digest_error = 10
,   exitcode_transmission_error = 11
,   exitcode_io_error = 12
,   exitcode_connection_error = 13
};

enum diffsize {
    ds_none   = 0
,   ds_strict = 1
,   ds_resize
,   ds_minsize
,   ds_mask   = 0x7f
,   ds_warn   = 0x80
};

struct context {
    int *blockreqs;
};

typedef int (*async_handler)(struct context *, unsigned char, char *, size_t);

extern int checkzero (void *p, int len);

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
    size_t len, maxlen;
    struct msg *phd, *ptl;
    size_t pos; /* refers to write pos in head msg */
    int    wr_fd;
    char   tlen [sizeof (u_int32_t)];
    int    state;
};

struct rd_queue {
    size_t len, maxlen;
    struct msg *phd, *ptl, *ptmp;
    size_t pos;  /* refers to read pos in head msg */
    int    rd_fd;
    char   tlen [sizeof (u_int32_t)];
    int    state;
};

void init_wr_queue (struct wr_queue *pqueue, int wr_fd)
{
    pqueue->len    = 0;
    pqueue->maxlen = 0;
    pqueue->phd    = NULL;
    pqueue->ptl    = NULL;
    pqueue->pos    = 0;
    pqueue->wr_fd  = wr_fd;
    pqueue->state  = qhdr;

    set_nonblocking (wr_fd);
}

void init_rd_queue (struct rd_queue *pqueue, int rd_fd)
{
    pqueue->len    = 0;
    pqueue->maxlen = 0;
    pqueue->phd    = NULL;
    pqueue->ptl    = NULL;
    pqueue->ptmp   = NULL;
    pqueue->pos    = 0;
    pqueue->rd_fd  = rd_fd;
    pqueue->state  = qhdr;

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

void exitmsg (enum exitcode code, char * format, ...)
{
    va_list args;

    va_start (args, format);
    vhandler (format, args);
    va_end (args);

    exit (code);
};

void dump_mallinfo (void)
{
    struct mallinfo mi;

    mi = mallinfo ();

    verbose (3, "dump_mallinfo: arena=%d, ordblks=%d, smblks=%d, hblks=%d, hblkhd=%d, usmblks=%d, fsmblks=%d, uordblks=%d, fordblks=%d, keepcost=%d\n"
              , mi.arena, mi.ordblks, mi.smblks, mi.hblks, mi.hblkhd, mi.usmblks, mi.fsmblks, mi.uordblks, mi.fordblks, mi.keepcost);
};

void cleanup_wr_queue (struct wr_queue *pqueue)
{
    verbose (3, "cleanup_wr_queue: len=%ld, maxlen=%ld\n", (long)(pqueue->len), (long)(pqueue->maxlen));
};

void cleanup_rd_queue (struct rd_queue *pqueue)
{
    verbose (3, "cleanup_rd_queue: len=%ld, maxlen=%ld\n", (long)(pqueue->len), (long)(pqueue->maxlen));
};

struct zero_hash {
    char             *name;
    off_t            blocksize;
    int              hashsize;
    unsigned char    *hash;
    struct zero_hash *pnxt;
};

struct cs_state {
    char     *name;
    off_t    nxtpos;
    hash_ctx ctx;
    int      hashsize;
};

hash_ctx _init_cs (const char *checksum, int *hs)
{
    hash_alg md;
    hash_ctx ctx;

    md  = hash_getbyname (checksum);

    if (!md) {
        verbose (0, "Bad checksum %s\n", checksum);
        exit (exitcode_checksum_error);
    }

    *hs = hash_getsize (md);
    hash_init (ctx, md);

    return ctx;
}

static struct zero_hash *pzeroes      = NULL;
static off_t            zeroblocksize = 0;
static unsigned char    *zeroblock    = NULL; 

static struct zero_hash *find_zero_hash (const char *name, off_t blocksize, int saltsize, unsigned char *salt)
{
    struct zero_hash *pzh = pzeroes;
    hash_ctx         ctx;
    int              hs;

    verbose (3, "find_zero_hash: name=%s: blocksize=%lld, salt=%p\n", name, blocksize, salt);

    while (pzh) {
        if (!strcmp (pzh->name, name) && pzh->blocksize == blocksize) return pzh;
        pzh = pzh->pnxt;
    }
    if (blocksize > zeroblocksize) {
        if (zeroblock) free (zeroblock);
        zeroblock = calloc (1, blocksize);
        zeroblocksize = blocksize;
    }
    ctx = _init_cs (name, &hs);

    pzh     = pzeroes;
    pzeroes = malloc (sizeof (struct zero_hash));

    pzeroes->pnxt      = pzh;
    pzeroes->name      = strdup (name);
    pzeroes->blocksize = blocksize;
    pzeroes->hashsize  = hs;
    pzeroes->hash      = malloc (hs);

    hash_update (ctx, salt,      saltsize);
    hash_update (ctx, zeroblock, blocksize);
    hash_finish (ctx, pzeroes->hash);

    return pzeroes;
}

struct cs_state *init_checksum (const char *checksum)
{
    hash_ctx        ctx;
    int             hs;
    struct cs_state *state;

    verbose (2, "init_checksum: checksum: %s\n", checksum);

    ctx = _init_cs (checksum, &hs);

    state = malloc (sizeof (*state));

    state->nxtpos   = 0;
    state->ctx      = ctx;
    state->hashsize = hs;
    state->name     = strdup (checksum);

    return state;
}

int vpread (int devfd, void *buf, off_t len, off_t pos, off_t devsize, int flushcache, off_t relpos)
{
    off_t rlen = len;
    int ret    = 0;
    char *cbuf = (char *)buf;

    if (pos + rlen > devsize) {
        rlen = devsize - pos;

        if (rlen < 0) rlen = 0;
    }
    if (rlen) {
        if (relpos > pos) {
            verbose (0, "vpread: pos < relpos: relpos=%lld, pos=%lld", (long long)relpos, (long long) pos);
        }
        ret = pread (devfd, cbuf, rlen, pos);
        if (ret < 0) exitmsg (exitcode_read_error, "vpread: %s\n", strerror (errno));
        if (flushcache) {
            // Use fadvise to release buffer/cache
            posix_fadvise (devfd, pos, rlen, POSIX_FADV_DONTNEED);
            verbose (3, "posix_fadvise: start=%lld end=%lld\n", (long long)pos, (long long)pos+rlen);
        }
    }

    if (rlen < len) memset (cbuf + rlen, 0, len - rlen);

    return ret;
}

int update_checksum (struct cs_state *state, off_t pos, int fd, off_t len, unsigned char *buf, off_t devsize, int flushcache, off_t relpos)
{
    if (!state) return 0;

    verbose (3, "update_checksum: checksum: pos=%lld, len=%d, flushcache=%d\n"
            , (long long) state->nxtpos, len, flushcache);

    if (pos > state->nxtpos) {
        size_t nrd ;
        off_t  len   = pos - state->nxtpos;
        size_t blen  = (len > 32768 ? 32768 : len);
        char   *fbuf = malloc (blen);

        while (len) {
            verbose (3, "update_checksum: checksum: pos=%lld, len=%d\n"
                    , (long long) state->nxtpos, blen);

            nrd = vpread (fd, fbuf, blen, state->nxtpos, devsize, flushcache, relpos);

            if (nrd != blen) {
                exitmsg (exitcode_checksum_error
                        , "update_checksum: nrd (%lld) != blen (%d)\n"
                        , (long long)nrd, (int)blen);
            }

            hash_update (state->ctx, fbuf, blen);

            state->nxtpos += blen;
            len           -= blen;
        }

        free (fbuf);
    }

    if (pos < state->nxtpos) {
        len -= (state->nxtpos - pos);
        pos  = state->nxtpos;
    }

    if (len <= 0) return 0;

    hash_update (state->ctx, buf, len);

    state->nxtpos += len;

    return 0;
};

int fd_pair(int fd[2])
{
        int ret;

        ret = socketpair(AF_UNIX, SOCK_STREAM, 0, fd);
        // ret = pipe(fd);

        return ret;
};


int init_salt (int saltsize, unsigned char *salt, int fixedsalt)
{
    if (fixedsalt) {
        memset (salt, 0, saltsize);
    } else {
        int fd = open("/dev/urandom", O_RDONLY);

        if (read (fd, salt, saltsize) != saltsize) {
            exitmsg (exitcode_source_randomness_error, "piped_child: %s\n", strerror (errno));
        }

        close(fd);
    }
    return 0;
};

pid_t piped_child(char **command, int *f_in, int *f_out)
{
    pid_t pid;
    int   to_child_pipe[2];
    int   from_child_pipe[2];

    verbose (2, "opening connection using: %s\n", command[0]);

    if (fd_pair(to_child_pipe) < 0 || fd_pair(from_child_pipe) < 0) {
            exitmsg (exitcode_process_error, "piped_child: %s\n", strerror (errno));
    }

    pid = fork();
    if (pid == -1) {
            exitmsg (exitcode_process_error, "piped_child: fork: %s\n", strerror (errno));
    }

    if (pid == 0) {
        if (dup2(to_child_pipe[0], STDIN_FILENO) < 0 ||
            close(to_child_pipe[1]) < 0 ||
            close(from_child_pipe[0]) < 0 ||
            dup2(from_child_pipe[1], STDOUT_FILENO) < 0) {
            exitmsg (exitcode_process_error, "piped_child: dup2: %s\n", strerror (errno));
        }
        if (to_child_pipe[0] != STDIN_FILENO)
                close(to_child_pipe[0]);
        if (from_child_pipe[1] != STDOUT_FILENO)
                close(from_child_pipe[1]);
            // umask(orig_umask);
        set_blocking(STDIN_FILENO);
        set_blocking(STDOUT_FILENO);
        execvp(command[0], command);
        exitmsg (exitcode_process_error, "piped_child: execvp: %s\n", strerror (errno));
    }

    if (close(from_child_pipe[1]) < 0 || close(to_child_pipe[0]) < 0) {
        exitmsg (exitcode_process_error, "piped_child: close: %s\n", strerror (errno));
    }

    *f_in = from_child_pipe[0];
    *f_out = to_child_pipe[1];

    return pid;
};

pid_t do_command (char *command, struct rd_queue *prd_queue, struct wr_queue *pwr_queue)
{
    int   argc = 0;
    char  *t, *f, *args[ARGMAX];
    pid_t pid;
    int   in_quote = 0;
    int   f_in, f_out;

    command = strdup (command);

    for (t = f = command; *f; f++) {
        if (*f == ' ') continue;
        /* Comparison leaves rooms for server_options(). */
        if (argc >= ARGMAX - 1) {
            exitmsg (exitcode_invalid_params, "internal: args[] overflowed in do_command()\n");
        }
        args[argc++] = t;
        while (*f != ' ' || in_quote) {
            if (!*f) {
                if (in_quote) {
                    exitmsg (exitcode_invalid_params
                            , "Missing trailing-%c in remote-shell command.\n"
                            , in_quote);
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

char *int2char (char *buf, off_t val, int bytes)
{
    char *p;

    for (p = buf; bytes; bytes--) {
        *p++ = val & 0xff;
        val >>= 8;
    }
    return buf;
}

off_t char2int (char *buf, int bytes)
{
    off_t         ret = 0;
    unsigned char *p = (unsigned char *)buf + bytes;

    for (; bytes; bytes--) {
        ret <<= 8;
        ret |= *--p;
    }
    return ret;
}

enum messages {
    msg_none = 0
,   msg_hello
,   msg_devfile
,   msg_size
,   msg_digests
,   msg_gethashes
,   msg_hashes
,   msg_done
,   msg_getblock
,   msg_block
,   msg_getchecksum
,   msg_checksum
,   msg_max
};

enum hint {
    hint_flushcache = 0
,   hint_relpos
};

static char *msgstring[] = {
   ""
,  "hello"
,  "devfile"
,  "size"
,  "digest"
,  "gethashes"
,  "hashes"
,  "done"
,  "getblock"
,  "block"
,  "getchecksum"
,  "checksum"
};

int msg_write (int fd, unsigned char token, char *buf, size_t len)
{
    u_int32_t tmp = len + 1;
    char      tbuf[sizeof (tmp)];

    verbose (2, "msg_write: msg = %s, len = %d\n", msgstring[token], len);

    if (write (fd, int2char (tbuf, tmp, sizeof (tmp)), sizeof (tmp)) != sizeof (tmp)) {
        exit (exitcode_write_error);
    }
    if (write (fd, &token, sizeof (token)) != sizeof (token)) {
        exit (exitcode_write_error);
    }
    if (write (fd, buf, len) != len) {
        exit (exitcode_write_error);
    }

    return 0;
}

int add_wr_queue (struct wr_queue *pqueue, unsigned char token, char *buf, size_t len)
{
    struct msg *pmsg;

    verbose (2, "add_wr_queue: msg = %s, len = %d\n", msgstring[token], len);

    if (pqueue->state == qeof) {
        verbose (0, "add_wr_queue: EOF\n");
        exit (exitcode_write_error);
    }

    pmsg = (struct msg *) malloc (sizeof (struct msg) + len + 1);

    pmsg->len     = len + 1;
    pmsg->data[0] = token;
    if (len) memcpy (pmsg->data + 1, buf, len);
    pmsg->pnxt    = NULL;

    if (pqueue->ptl) {
        pqueue->ptl->pnxt = pmsg;
    } else {
        pqueue->phd = pmsg;
    }
    pqueue->ptl  = pmsg;
    pqueue->len += (sizeof (pqueue->tlen) + len + 1);
    if (pqueue->len > pqueue->maxlen) pqueue->maxlen = pqueue->len;

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
                    exit (exitcode_write_error);
                }
            }
        }
        tmp = write (pqueue->wr_fd, pwr, len);
        if (tmp == 0) break;
        if (tmp == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) break;
            verbose (0, "flush_wr_queue: %s\n", strerror (errno));
            exit (exitcode_write_error);
        }
        retval      += tmp;
        pqueue->pos += tmp;

        verbose (3, "flush_wr_queue: len = %lld\n",  (long long int)(pqueue->len - retval));
    }
    pqueue->len -= retval;

    return retval;
}

int fill_rd_queue (struct rd_queue *pqueue, async_handler handler, struct context *context)
{
    char   *prd;
    size_t retval = 0, addlen = 0, len, tmp;

    verbose (3, "fill_rd_queue: len = %lld\n",  (long long)pqueue->len);

    while (pqueue->state != qeof) {
        if (pqueue->state == qhdr) {
            len = sizeof (pqueue->tlen) - pqueue->pos;
            if (len == 0) {
                struct msg *pmsg;
                len = char2int ((char *)pqueue->tlen, sizeof (pqueue->tlen));
                if (len > MSGMAX) {
                    verbose (0, "fill_rd_queue: bad msg size %d\n", (int)len);
                    exit (exitcode_read_error);
                }

                pmsg       = malloc (sizeof (struct msg) + len + 1);
                pmsg->pnxt = NULL;
                pmsg->len  = len;

                pqueue->ptmp  = pmsg;
                pqueue->state = qdata;
                pqueue->pos   = 0;
                continue;
            }
            prd = (char *)(pqueue->tlen) + pqueue->pos;
        } else {
            struct msg *pmsg = pqueue->ptmp;

            len = pmsg->len - pqueue->pos;
            if (len == 0) {
                /* Full message present */
                verbose (3, "fill_rd_queue: msg = %s, len = %d\n", msgstring[(unsigned char)(pmsg->data[0])], (int)pmsg->len - 1);

                pqueue->state = qhdr;
                pqueue->pos   = 0;
                pqueue->ptmp  = NULL;

                if (handler) {
                    unsigned char token  = pmsg->data[0];
                    char          *msg   = pmsg->data + 1;
                    size_t        msglen = pmsg->len - 1;

                    if (handler (context, token, msg, msglen)) {
                        /* Handled, no need to queue it */
                        addlen -= (sizeof (pqueue->tlen) + pmsg->len);
                        retval ++;

                        free (pmsg);
                        continue;
                    }
                }

                if (pqueue->ptl) {
                    pqueue->ptl->pnxt = pmsg;
                } else {
                    pqueue->phd       = pmsg;
                }
                pqueue->ptl   = pmsg;
                continue;
            }
            prd = pmsg->data + pqueue->pos;
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
            exit (exitcode_read_error);
        }
        if (tmp == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) break;
            verbose (0, "fill_rd_queue: %s\n", strerror (errno));
            exit (exitcode_read_error);
        }
        pqueue->pos += tmp;
        addlen += tmp;

        verbose (3, "fill_rd_queue: len = %lld\n",  (long long)(pqueue->len + addlen));
    }
    pqueue->len += addlen;
    if (pqueue->len > pqueue->maxlen) pqueue->maxlen = pqueue->len;

    return retval;
}

struct timeval get_rd_wait = {0, 0};

int get_rd_queue (struct wr_queue *pwr_queue, struct rd_queue *prd_queue, unsigned char *token, char **msg, size_t *msglen, async_handler handler, struct context *context)
{
    struct pollfd  pfd[2];
    struct msg     *phd;
    int            tmp, nfd;
    struct timeval tv1, tv2;
    int            async_cnt = 0;

    verbose (3, "get_rd_queue: handler = %d\n", (handler != NULL));

    gettimeofday (&tv1, NULL);

    while (    prd_queue->state != qeof
           && !async_cnt
           && (prd_queue->state != qhdr || prd_queue->phd == NULL)) {
        pfd[0].fd     = prd_queue->rd_fd;
        pfd[0].events = POLLIN;

        pfd[1].fd     = pwr_queue->wr_fd;
        pfd[1].events = (pwr_queue->phd ? POLLOUT: 0);

        nfd = (pwr_queue->state == qeof ? 1 : 2);
        tmp = poll (pfd, nfd, -1);

        verbose (3, "get_rd_queue: poll %d\n", tmp);

        if (pfd[0].revents & POLLIN) async_cnt += fill_rd_queue (prd_queue, handler, context);
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
                        exit (exitcode_read_error);
                    }
                } else {
                    verbose (0, "get_rd_queue: poll error on fd %d\n", pfd[1].fd);
                    exit (exitcode_read_error);
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
        if (async_cnt) {
            *token = msg_none;
            *msg   = NULL;
            verbose (2, "get_rd_queue: msg = -, len = 0\n");
            return 0;
        }
        verbose (0, "get_rd_queue: EOF %d\n", pfd[1].fd);
        exit (exitcode_read_error);
    }

    *token  = phd->data[0];
    *msg    = (char *)malloc (phd->len);
    *msglen = phd->len - 1;
    memcpy (*msg, phd->data + 1, phd->len - 1);

    prd_queue->len -= (sizeof (prd_queue->tlen) + phd->len);
    prd_queue->phd  = phd->pnxt;
    if (phd->pnxt == NULL) prd_queue->ptl = NULL;

    free (phd);

    verbose (2, "get_rd_queue: msg = %s, len = %d\n", msgstring[*token], *msglen);

    return 1;
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

int send_size (struct wr_queue *pqueue, off_t devsize)
{
    char tbuf[sizeof (devsize)];

    verbose (1, "send_size: devsize = %lld\n", (long long)devsize);

    int2char (tbuf, devsize, sizeof (devsize));

    return add_wr_queue (pqueue, msg_size, tbuf, sizeof (devsize));
};

char *bytes2str (size_t s, unsigned char *p)
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

int send_digests (struct wr_queue *pqueue, int saltsize, unsigned char *salt, char *digest, char *checksum)
{
    char       *cp, *buf;
    const char *tchecksum;
    size_t     buflen;
    int        ret;

    if (saltsize > 127) {
        verbose (0, "send_digests: bad saltsize %d\n", saltsize);
        exit (exitcode_digest_error);
    }

    if (!digest[0]) {
        verbose (0, "send_digests: empty digest\n");
        exit (exitcode_digest_error);
    }

    if (isverbose >= 1) {
        char *tmp = bytes2str (saltsize, salt);
        verbose (1, "send_digests: salt = %s, digest = %s, checksum = %s\n"
                  , tmp, digest, (checksum ? checksum : "(none)"));
        free (tmp);
    }

    tchecksum = (checksum ? checksum : "");

    buflen = saltsize + 1 + strlen (digest) + 1 + strlen (tchecksum) + 1;
    buf    = malloc (buflen);
    cp     = buf;

    *cp++ = (char) saltsize;
    memcpy (cp, salt, saltsize);
    cp += saltsize;

    strcpy (cp, digest);
    cp +=  strlen (digest) + 1;

    strcpy (cp, tchecksum);

    ret = add_wr_queue (pqueue, msg_digests, buf, buflen);

    free (buf);

    return ret;
}

int send_gethashes (struct wr_queue *pqueue, off_t start, off_t step, int nstep)
{
    off_t par[3];
    char  tbuf[sizeof (par)];
    char  *cp;
    int   i;

    par[0] = start;
    par[1] = step;
    par[2] = nstep;

    verbose (1, "send_gethashes: start=%lld step=%lld nstep=%d\n", (long long)par[0], (long long)par[1], (int)par[2]);

    for (i = 0, cp = tbuf; i < 3; i++, cp += sizeof (par[0])) {
        int2char (cp, par[i], sizeof (par[0]));
    }

    return add_wr_queue (pqueue, msg_gethashes, tbuf, sizeof (par));
};

int send_hint (struct wr_queue *pqueue, int hint, off_t relpos)
{
    verbose (1, "send_hint: hint=%d, relpos=%lld\n", hint, (long long)relpos);

    return send_gethashes (pqueue, relpos, hint, 0);
};

int send_hashes (struct wr_queue *pqueue, off_t start, off_t step, int nstep, unsigned char *buf, size_t siz)
{
    off_t par[3];
    char  *tbuf, *cp;
    int   ret, i;

    par[0] = start;
    par[1] = step;
    par[2] = nstep;

    verbose (1, "send_hashes: start=%lld step=%lld nstep=%d\n", (long long)par[0], (long long)par[1], (int)par[2]);

    tbuf = malloc (sizeof (par) + siz);

    for (i = 0, cp = tbuf; i < 3; i++, cp += sizeof (par[0])) {
        int2char (cp, par[i], sizeof (par[0]));
    }

    if (buf) memcpy (cp, buf, siz);

    ret = add_wr_queue (pqueue, msg_hashes, tbuf, sizeof (par) + siz);

    free (tbuf);

    return ret;
};

int send_getblock (struct wr_queue *pqueue, off_t pos, off_t len)
{
    off_t par[2];
    char  tbuf[sizeof (par)];
    char  *cp;
    int   i;

    par[0] = pos;
    par[1] = len;

    verbose (1, "send_getblock: pos=%lld len=%lld\n", (long long)pos, (long long)len);

    for (i = 0, cp = tbuf; i < 2; i++, cp += sizeof (par[0])) {
        int2char (cp, par[i], sizeof (par[0]));
    }

    return add_wr_queue (pqueue, msg_getblock, tbuf, sizeof (par));
};

int send_block (struct wr_queue *pqueue, int fd, off_t pos, off_t len)
{
    char *tbuf, *cp;
    int  ret;

    verbose (1, "send_block: pos=%lld len=%lld\n", (long long)pos, (long long)len);

    tbuf = malloc (sizeof (pos) + len);
    cp   = tbuf;

    int2char (cp, pos, sizeof (pos));
    cp += sizeof (pos);

    ret = pread (fd, cp, len, pos);
    if (ret != len) {
        if (len < 0) {
            exitmsg (exitcode_transmission_error, "send_block: pread: %s\n", strerror (errno));
        } else {
            exitmsg (exitcode_transmission_error, "send_block: pread read bad #bytes");
        }
    }

    ret = add_wr_queue (pqueue, msg_block, tbuf, sizeof (pos) + len);

    free (tbuf);

    return ret;
};

int send_getchecksum (struct wr_queue *pqueue)
{
    verbose (1, "send_getchecksum\n");

    return add_wr_queue (pqueue, msg_getchecksum, NULL, 0);
};

int send_checksum (struct wr_queue *pqueue, int len, unsigned char *buf)
{
    if (isverbose >= 1) {
        char *tmp = bytes2str (len, buf);
        verbose (1, "send_checksum: checksum=%s\n", tmp);
        free (tmp);
    }

    return add_wr_queue (pqueue, msg_checksum, (char *)buf, len);
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
            exit (exitcode_read_error);
        case 0:
            verbose (0, "read_all: EOF\n");
            exit (exitcode_read_error);
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
        exit (exitcode_protocol_error);
    }

    if (*buf && tmp > *buflen) {
        free (*buf);
        *buf = NULL;
    }
    if (!*buf) {
        *buf = (char *)malloc (tmp + 1);
    }
    *msglen = tmp - 1;

    if (tmp <= 1) exit (exitcode_protocol_error);

    read_all (fd, *buf, tmp);

    (*buf)[tmp] = '\0';

    *token = **buf;
    *msg   = (*buf) + 1;

    if (*token < 1 || *token >= msg_max) {
        verbose (0, "Unknown message %d\n", *token);
        exit (exitcode_protocol_error);
    }


    verbose (2, "msg_read: msg = %s, len = %d\n", msgstring[*token], (int)tmp - 1);

    return 0;
};

int parse_msgstring (char *msgbuf, size_t msglen, char **str, size_t minlen)
{
    if (*str || msglen < minlen) exit (exitcode_protocol_error);

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
    int  ret;
    char *p;

    ret = parse_msgstring (msgbuf, msglen, hello, 0);

    p = strchr (*hello, ' ');
    if (p == NULL) {
        verbose (0, "parse_hello: Missing protocol version '%s'\n", *hello);
        exit (exitcode_protocol_error);
    }

    if (strcmp (p + 1, PROTOVER)) {
        verbose (0, "parse_hello: Bad protocol version %s\n", p + 1);
        exit (exitcode_protocol_error);
    }
    *p = '\0';

    verbose (1, "parse_hello: hello = %s, version = %s\n", *hello, p + 1);

    return ret;
};

int parse_size (char *msgbuf, size_t msglen, off_t *size)
{
    if (msglen != sizeof (*size)) exit (exitcode_protocol_error);

    *size = char2int (msgbuf, sizeof (*size));

    verbose (1, "parse_size: size = %ld\n", (long)*size);

    return 0;
};

const char *get_string (char **msgbuf, size_t *msglen)
{
    char   *cp = *msgbuf, *ret = *msgbuf;
    size_t len = *msglen;

    while (*cp && len) {
        cp++;
        len--;
    }
    if (!len) return NULL;

    *msgbuf = cp  + 1;
    *msglen = len - 1;

    return ret;
};

int parse_digests (char *msgbuf, size_t msglen, int *saltsize, unsigned char **salt, char **dg_nm, hash_alg *dg_md, struct cs_state **cs_state)
{
    const char *digest, *checksum;

    if (msglen < 1) {
        verbose (0, "parse_digests: bad size=%lld\n", (long long)msglen);
        exit (exitcode_protocol_error);
    }

    *saltsize = (int)(*msgbuf++);
    if (msglen < *saltsize + 1) {
        if (msglen < 1) {
            verbose (0, "parse_digests: bad size=%lld, salt size = %d\n", (long long)msglen, *saltsize);
            exit (exitcode_protocol_error);
        }
    }

    *salt = malloc (*saltsize);
    memcpy (*salt, msgbuf, *saltsize);

    msgbuf += *saltsize;
    msglen -= *saltsize + 1;

    digest   = get_string (&msgbuf, &msglen);
    checksum = get_string (&msgbuf, &msglen);

    if (!digest || !checksum) {
        verbose (0, "parse_digests: missing digest\n");
        exit (exitcode_protocol_error);
    }

    *dg_nm = strdup (digest);
    *dg_md = hash_getbyname (digest);

    if (!*dg_md) {
        verbose (0, "parse_digests: bad digest %s\n", digest);
        exit (exitcode_digest_error);
    }

    *cs_state = (*checksum != '\0' ? init_checksum (checksum) : NULL);

    if (isverbose >= 1) {
        char *tmp = bytes2str (*saltsize, *salt);
        verbose (1, "parse_digests: salt = %s, digest = %s checksum = %s\n"
                , tmp, digest, (*checksum == '\0' ? "(none)" : checksum));
        free (tmp);
    }

    return 0;
};

int parse_gethashes ( char *msgbuf, size_t msglen
                    , off_t *start, off_t *step, int *nstep, int *is_hint)
{
    off_t par[3];
    int   i;

    if (msglen != sizeof (par)) {
        verbose (0, "parse_gethashes: bad message size %d\n", (int)msglen);
        exit (exitcode_protocol_error);
    }

    for (i = 0; i < 3; i++, msgbuf += sizeof (par[0])) {
        par[i] = char2int (msgbuf, sizeof (par[0]));
    }

    *start = par[0];
    *step  = par[1];
    *nstep = par[2];

    *is_hint = (*nstep == 0);

    verbose (1, "parse_gethashes: start=%lld step=%lld nstep=%d is_hint=%d\n", (long long)par[0], (long long)par[1], (int)par[2], *is_hint);

    return 0;
};

int parse_hint (off_t start, off_t step, int devfd, off_t *relpos, int *flushcache)
{
    verbose (1, "parse_hint: start=%lld step=%lld relpos=%lld flushcache=%d\n", (long long)start, (long long) step, (long long)(relpos ? *relpos : -1) , (flushcache ? *flushcache : -1));

    switch (step) {
    case hint_flushcache:
        if (!flushcache) return 0;
        *flushcache = 1;
        break;
    case hint_relpos:
        /* Hint: Release buffer/cache */
        if (!devfd) return 0;
        posix_fadvise (devfd, *relpos, start - *relpos, POSIX_FADV_DONTNEED);
        verbose (3, "posix_fadvise: start=%lld end=%lld\n", (long long)*relpos, (long long)start);
        *relpos = start;
        break;
    }
    return 0;
};

int parse_getblock ( char *msgbuf, size_t msglen
                   , off_t *pos, off_t *len)
{
    off_t par[2];
    int   i;

    if (msglen != sizeof (par)) {
        verbose (0, "parse_getblock: bad message size %d\n", (int)msglen);
        exit (exitcode_protocol_error);
    }

    for (i = 0; i < 2; i++, msgbuf += sizeof (par[0])) {
        par[i] = char2int (msgbuf, sizeof (par[0]));
    }

    *pos = par[0];
    *len = par[1];

    verbose (1, "parse_getblock: pos=%lld len=%lld\n", (long long)par[0], (long long)par[1]);

    return 0;
};

int parse_block ( char *msgbuf, size_t msglen
                , off_t *pos, off_t *len, char **pblock)
{
    /* there should at least 1 byte in the block */
    if (msglen < sizeof (*pos) + 1) {
        verbose (0, "parse_getblock: bad message size %d\n", (int)msglen);
        exit (exitcode_protocol_error);
    }

    *pos    = char2int (msgbuf, sizeof (*pos));
    *len    = msglen - sizeof (*pos);
    *pblock = msgbuf + sizeof (*pos);

    verbose (1, "parse_block: pos=%lld len=%lld\n", (long long)*pos, (long long)*len);

    return 0;
};

int parse_hashes ( int hashsize, char *msgbuf, size_t msglen
                 , off_t *start, off_t *step, int *nstep, unsigned char **hbuf
                 , int *is_hint)
{
    off_t par[3];
    int   i;

    if (msglen < sizeof (par)) {
        verbose (0, "parse_hashes: bad size=%lld minimum=%lld\n", (long long)msglen, (long long)(sizeof (par)));
        exit (exitcode_protocol_error);
    }

    for (i = 0; i < 3; i++, msgbuf += sizeof (par[0])) {
        par[i] = char2int (msgbuf, sizeof (par[0]));
    }

    *start = par[0];
    *step  = par[1];
    *nstep = par[2];

    if (msglen != sizeof (par) + *nstep * hashsize) {
        verbose (0, "parse_hashes: bad size=%lld expected=%lld\n", (long long)msglen, (long long)(sizeof (par) + *nstep * hashsize));
        exit (exitcode_protocol_error);
    }

    if (*nstep) {
        *is_hint = 0;
        *hbuf     = malloc (*nstep * hashsize);
        memcpy (*hbuf, msgbuf, *nstep * hashsize);
    } else {
        *is_hint = 1;
        *hbuf    = NULL;
    }

    verbose (1, "parse_hashes: start=%lld, step=%lld, nstep=%d, is_hint=%d\n", (long long)*start, (long long)*step, *nstep, *is_hint);

    return 0;
};

int parse_getchecksum (char *msgbuf, size_t msglen)
{
    if (msglen != 0) {
        verbose (0, "parse_getchecksum: bad message size %d\n", (int)msglen);
        exit (exitcode_protocol_error);
    }

    return 0;
};

int parse_checksum ( char *msgbuf, size_t msglen
                   , size_t *len, unsigned char **buf)
{
    /* there should at least 1 byte in the cheksum */
    if (msglen <= 1) {
        verbose (0, "parse_checksum: bad message size %d\n", (int)msglen);
        exit (exitcode_protocol_error);
    }

    *len = msglen;
    *buf = malloc (msglen);
    memcpy (*buf, msgbuf, msglen);

    {
        char *tmp = bytes2str (*len, *buf);
        verbose (1, "parse_checksum: checksum = %s\n", tmp);
        free (tmp);
    }

    return 0;
};


int parse_done (char *msgbuf, size_t msglen)
{
    if (msglen != 0) {
        verbose (0, "parse_done: bad size=%lld\n", (long long)msglen);
        exit (exitcode_protocol_error);
    }
    verbose (1, "parse_done\n");

    return 0;
};

int flush_checksum (struct cs_state **state, size_t *len, unsigned char **buf)
{
    if (*state) {
        *len = (*state)->hashsize;
        *buf = malloc (*len);

        hash_finish ((*state)->ctx, *buf);

        if (isverbose >= 2) {
            char *tmp = bytes2str (*len, *buf);
            verbose (2, "flush_checksum: [%s]: %s\n", (*state)->name, tmp);
            free (tmp);
        }

        free ((*state)->name);
        free ((*state));

        *state = NULL;
    } else {
        *buf = NULL;
        *len = 0;
    }

    return 0;
}

int gen_hashes ( hash_alg md
               , struct zero_hash *zh
               , struct cs_state *cs_state
               , struct rd_queue *prd_queue, struct wr_queue *pwr_queue
               , int saltsize, unsigned char *salt
               , unsigned char **retbuf, size_t *retsiz, int fd
               , off_t devsize
               , off_t start, off_t step, int nstep
               , int flushcache, off_t relpos
               , async_handler handler, struct context *context)
{
    unsigned char *buf, *fbuf;
    off_t         nrd;
    int           hashsize = hash_getsize (md);
    hash_ctx      dg_ctx;

    *retsiz = nstep * hashsize;
    buf     = malloc (nstep * hashsize);
    *retbuf = buf;

    verbose (1, "gen_hashes: start=%lld step=%lld nstep=%d flushcache=%d\n"
            , (long long) start, (long long)step, nstep, flushcache);

    fbuf    = malloc (step);

    while (nstep) {
        flush_wr_queue (pwr_queue, 0);
        fill_rd_queue (prd_queue, handler, context);

        nrd = vpread (fd, fbuf, step, start, devsize, flushcache, relpos);

/* Kills performance; really slow syscall:
        posix_fadvise64 (fd, start + step, RDAHEAD, POSIX_FADV_WILLNEED);
*/
        if (zh && checkzero (fbuf, step)) {
            memcpy (buf, zh->hash, zh->hashsize);
        } else {
            hash_init (dg_ctx, md);
            hash_update (dg_ctx, salt, saltsize);
            hash_update (dg_ctx, fbuf, step);
            hash_finish (dg_ctx, buf);
        }

        if (isverbose >= 3) {
            char *tmp = bytes2str (hashsize, buf);
            verbose (3, "gen_hashes: hash: pos=%lld, len=%d, hash=%s\n"
                    , (long long) start, nrd, tmp);
            free (tmp);
        }
        update_checksum (cs_state, start, fd, step, fbuf, devsize, flushcache, relpos);

        buf += hashsize;

        nstep--;
        start  += step;
    }
    *retsiz = buf - *retbuf;

    free (fbuf);

    return 0;
};

int opendev (char *dev, off_t *siz, int flags)
{
    int     fd;

    fd = open (dev, flags | O_LARGEFILE);
    if (fd == -1) {
        verbose (0, "opendev [%s]: %s\n", dev, strerror (errno));
        exit (exitcode_io_error);
    }
    *siz = lseek (fd, 0, SEEK_END);

    verbose (1, "opendev: opened %s\n", dev);

    return fd;
};

enum exitcode do_server (int zeroblocks)
{
    char             *msg;
    size_t           msglen;
    unsigned char    token;
    unsigned char    *buf, *salt = NULL;
    int              devfd = -1, nstep, hint;
    int              saltsize = 0, flushcache = 0;
    off_t            devsize = 0, start, step, relpos = 0;
    size_t           len;
    struct           wr_queue wr_queue;
    struct           rd_queue rd_queue;
    hash_alg         dg_md = hash_null;
    struct cs_state  *cs_state;
    char             *dg_nm = NULL;
    struct zero_hash *zh;

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
        get_rd_queue (&wr_queue, &rd_queue, &token, &msg, &msglen, NULL, NULL);

        if (exp) {
            if (token != exp) exit (exitcode_protocol_error);
            exp = 0;
        }

        switch (token) {
        case msg_hello:
            exp = msg_devfile;
            parse_hello (msg, msglen, &hello);
            free (hello);
            break;
        case msg_devfile:
            parse_devfile (msg, msglen, &devfile);
            devfd = opendev (devfile, &devsize, O_RDONLY);
            send_size (&wr_queue, devsize);
            free (devfile);
            break;
        case msg_digests:
            /* assert (salt == NULL) */
            parse_digests (msg, msglen, &saltsize, &salt, &dg_nm, &dg_md, &cs_state);
            break;
        case msg_gethashes:
            parse_gethashes (msg, msglen, &start, &step, &nstep, &hint);
            if (hint) {
                parse_hint (start, step, devfd, &relpos, &flushcache);
                buf = NULL;
                len = 0;
            } else {
                zh = (zeroblocks ? find_zero_hash (dg_nm, step, saltsize, salt) : NULL);
                gen_hashes (dg_md, zh, cs_state, &rd_queue, &wr_queue, saltsize, salt, &buf, &len, devfd, devsize, start, step, nstep, flushcache, relpos, NULL, NULL);
            }
            send_hashes (&wr_queue, start, step, nstep, buf, len);
            free (buf);
            break;
        case msg_getblock:
            parse_getblock (msg, msglen, &start, &step);
            send_block (&wr_queue, devfd, start, step);
            break;
        case msg_getchecksum:
            parse_getchecksum (msg, msglen);
            flush_checksum (&cs_state, &len, &buf);
            send_checksum (&wr_queue, len, buf);
            free (buf);
            break;
        case msg_done:
            parse_done (msg, msglen);
            send_done (&wr_queue);
            goon = 0;
            break;
        default:
            exit (exitcode_protocol_error);
            break;
        }
        free (msg);
    }
    flush_wr_queue (&wr_queue, 1);

    cleanup_rd_queue (&rd_queue);
    cleanup_wr_queue (&wr_queue);

    free (salt);
    free (dg_nm);

    /* destroy md? */

    dump_mallinfo ();

    return exitcode_success;
};

int tcp_connect (char *host, char *service)
{
    int             n, s;
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
        exit (exitcode_connection_error);
    }

    for (rp = aip; rp != NULL; rp = rp->ai_next) {
        s = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (s == -1) continue;

        if (connect(s, rp->ai_addr, rp->ai_addrlen) == 0) break;

        close(s);
    }

    if (rp == NULL) {
        perror("socket");
        exit(exitcode_connection_error);
    }

    return s;
}

void check_token (char *f, unsigned char token, unsigned char expect)
{
    if (token == expect) return;
    verbose (0, "%sUnexpected token=%s, expected=%s\n", f, msgstring[token], msgstring[expect]);
    exit (exitcode_protocol_error);
};

#define HSMALL  4096
#define HLARGE  65536
// #define HSMALL  32768
// #define HLARGE  32768

#define MAXHASHES(hashsize) ((MSGMAX-3*sizeof(off_t))/hashsize)

int write_block (off_t pos, unsigned short len, char *pblock)
{
    fwrite (&pos, sizeof (pos), 1, stdout);
    fwrite (&len, sizeof (len), 1, stdout);
    fwrite (pblock,  1, len,       stdout);

    return 0;
}

int async_block_write (struct context *ctx, unsigned char token, char *msg, size_t msglen)
{
    char  *pblock;
    off_t pos, len;

    if (token != msg_block) return 0;

    verbose (3, "async_block_write entry\n");

    parse_block (msg, msglen, &pos, &len, &pblock);
    write_block (pos, len, pblock);

    (*(ctx->blockreqs))--;

    verbose (3, "async_block_write exit\n");

    return 1;
}

int hashmatch ( const char *dg_nm
              , hash_alg dg_md
              , struct cs_state *cs_state
              , int remdata
              , int saltsize, unsigned char *salt
              , off_t ldevsize, off_t rdevsize
              , struct rd_queue *prd_queue, struct wr_queue *pwr_queue, int devfd
              , off_t hashstart, off_t hashend, off_t hashstep, off_t nextstep
              , int maxsteps
              , int *hashreqs
              , int *blockreqs
              , int recurs
              , int zeroblocks
              , int flushcache)
{
    int              hashsteps;
    unsigned char    *rhbuf;
    unsigned char    *lhbuf;
    size_t           lhsize;
    char             *msg;
    size_t           msglen;
    unsigned char    token;
    off_t            rstart, rstep, mdevsize, relpos = 0;
    int              rnstep, hashsize, rhint;
    struct zero_hash *zh;
    struct context   context;

    verbose (2, "hashmatch: recurs=%d hashstart=%lld hashend=%lld hashstep=%lld maxsteps=%d devsize=%lld vdevsize=%lld flushcache=%d\n"
            , recurs, (long long)hashstart, (long long)hashend, (long long)hashstep, maxsteps
            , (long long)ldevsize, (long long)rdevsize, flushcache);

    context.blockreqs = blockreqs;

    mdevsize = (rdevsize > ldevsize ? rdevsize : ldevsize);

    hashsize = hash_getsize (dg_md);

    if (recurs == 0 && flushcache) {
        send_hint (pwr_queue, hint_flushcache, 0);
        (*hashreqs)++;
    }

    while (   (hashstart < hashend)
           || ((recurs == 0) && ((*hashreqs != 0) || (*blockreqs != 0)))) {
        while ((hashstart < hashend) && (recurs || *hashreqs < 32)) {
            hashsteps = (hashend + hashstep - 1 - hashstart) / hashstep;
            if (hashsteps > maxsteps) hashsteps = maxsteps;
            if (!hashsteps) break;

            /* Put the other side to work generating hashes */
            send_gethashes (pwr_queue, hashstart, hashstep, hashsteps);
            hashstart += hashsteps * hashstep;
            (*hashreqs)++;
        }
        verbose (3, "hashmatch: hashreqs=%d blockreqs=%d\n", *hashreqs, *blockreqs);

        if (recurs) break;

        token = msg_none;

        /* while we expect msg_hashes or msg_block try to get them ... */
        while (*hashreqs || *blockreqs) {
            /* handle msg_block in async_block_write */
            get_rd_queue (pwr_queue, prd_queue, &token, &msg, &msglen, async_block_write, &context);

            /* when msg_block is handled get_rd_queue may return msg_none */
            if (token != msg_none) break;
        }

        if (token == msg_none) continue;

        check_token ("", token, msg_hashes);
        (*hashreqs)--;

        parse_hashes (hashsize, msg, msglen, &rstart, &rstep, &rnstep, &rhbuf, &rhint);

        free (msg);

        if (rhint) {
            parse_hint (rstart, rstep, devfd, &relpos, &flushcache);
            continue;
        }

        zh = (zeroblocks ? find_zero_hash (dg_nm, rstep, saltsize, salt) : NULL);
        /* Generate our own list of hashes */
        gen_hashes (dg_md, zh, (rstep == hashstep ? cs_state : NULL)
                   , prd_queue, pwr_queue, saltsize, salt, &lhbuf, &lhsize, devfd, ldevsize, rstart, rstep, rnstep
                   , flushcache, relpos
                   , async_block_write, &context);

        off_t         pos = rstart;
        unsigned char *lp = lhbuf, *rp = rhbuf;
        int           ns = rnstep;

        while (ns--) {
            if (bcmp (lp, rp, hashsize)) {
                off_t tend = pos + rstep;

                if (tend > mdevsize) tend = mdevsize;

                if (rstep == nextstep) {
                    /* HSMALL? Then write the data */
                    off_t          len   = tend - pos;
                    off_t          tpos  = pos;
                    unsigned short blen  = (len > 32768 ? 32768 : len);
                    char           *fbuf = malloc (blen);

                    while (len) {
                        if (blen > len) blen = len;

                        verbose ( 3, "diff: %lld - %lld\n"
                                , (long long)tpos, (long long)(tpos + blen - 1));

                        if (remdata) {
                            /* Get the blocks from the server */
                            off_t tlen = rdevsize - pos;
                            if (tlen > blen) tlen = blen;

                            if (tlen > 0) {
                                send_getblock (pwr_queue, tpos, tlen);
                                (*blockreqs)++;
                            }
                        } else {
                            off_t tlen = ldevsize - pos;
                            if (tlen > blen) tlen = blen;

                            if (tlen > 0) {
                                vpread (devfd, fbuf, tlen, tpos, ldevsize, flushcache, relpos);
                                write_block (tpos, tlen, fbuf);
                            }
                        }
                        len  -= blen;
                        tpos += blen;
                    }

                    free (fbuf);
                } else {
                    /* Not HSMALL? Then zoom in on the details (HSMALL) */
                    int tnstep = rstep / nextstep;
                    if (tnstep > MAXHASHES (hashsize)) tnstep = MAXHASHES (hashsize);
                    hashmatch (dg_nm, dg_md, NULL, remdata, saltsize, salt, ldevsize, rdevsize, prd_queue, pwr_queue, devfd, pos, tend, nextstep, nextstep, tnstep, hashreqs, blockreqs, recurs + 1, zeroblocks, flushcache);
                }
            }
            lp  += hashsize;
            rp  += hashsize;
            pos += rstep;
        }
        free (lhbuf);
        free (rhbuf);

        if (!flushcache && recurs == 0) {
            /* The previous large block has been processed so send a release hint */
            send_hint (pwr_queue, hint_relpos, pos);
            (*hashreqs)++;
        }
    }

    verbose (2, "hashmatch: recurs=%d\n", recurs);

    return 0;
};

enum exitcode do_client (char *digest, char *checksum, char *command, char *ldev, char *rdev, off_t hlarge, off_t hsmall, int remdata, int fixedsalt, int diffsize, int zeroblocks, int flushcache)
{
    char            *msg;
    size_t          msglen;
    unsigned char   token;
    unsigned char   salt[SALTSIZE];
    int             ldevfd;
    off_t           ldevsize, rdevsize, mdevsize;
    unsigned short  devlen;
    struct          wr_queue wr_queue;
    struct          rd_queue rd_queue;
    int             hashsize, status;
    hash_alg        dg_md;
    struct cs_state *cs_state;
    pid_t           pid;

    dg_md = hash_getbyname (digest);
    if (!dg_md) {
        fprintf (stderr, "Bad hash %s\n", digest);
        exit (exitcode_invalid_params);
    }

    if (checksum && !remdata) {
        cs_state = init_checksum (checksum);
    } else {
        cs_state = NULL;
    }

    hashsize = hash_getsize (dg_md);

    init_salt (sizeof (salt), salt, fixedsalt);

    ldevfd = opendev (ldev, &ldevsize, O_RDONLY);

    pid = do_command (command, &rd_queue, &wr_queue);

    send_hello (&wr_queue, "CLIENT");

    char *hello   = NULL;

    get_rd_queue (&wr_queue, &rd_queue, &token, &msg, &msglen, NULL, NULL);
    check_token ("", token, msg_hello);
    parse_hello (msg, msglen, &hello);
    send_devfile (&wr_queue, rdev);
    free (msg);
    free (hello);

    get_rd_queue (&wr_queue, &rd_queue, &token, &msg, &msglen, NULL, NULL);
    check_token ("", token, msg_size);
    parse_size (msg, msglen, &rdevsize);
    free (msg);
    if (rdevsize != ldevsize) {
        if (diffsize & ds_warn) {
            verbose (0, "Different sizes local=%lld remote=%lld\n", ldevsize, rdevsize);
        }
        switch (diffsize & ds_mask) {
        case ds_strict:
            exit (exitcode_diffsize_mismatch);
            break;
        case ds_minsize:
            if (rdevsize > ldevsize) {
                rdevsize = ldevsize;
            } else {
                ldevsize = rdevsize;
            }
            break;
        case ds_resize:
            break;
        } 
    }

    mdevsize = (rdevsize > ldevsize ? rdevsize : ldevsize);

    char *tdev = (remdata ? ldev : rdev);

    devlen = strlen (tdev);
    printf ("%s\n", ARCHVER);
    fwrite ((remdata ? &rdevsize : &ldevsize),  sizeof (rdevsize),  1, stdout);
    fwrite (&devlen,                            sizeof (devlen),    1, stdout);
    fwrite (tdev,                               1,             devlen, stdout);

    send_digests (&wr_queue, sizeof (salt), salt, digest, (remdata ? checksum : NULL));

    int hashreqs = 0, blockreqs = 0;

    hashmatch (digest, dg_md, cs_state, remdata, sizeof (salt), salt, ldevsize, rdevsize, &rd_queue, &wr_queue, ldevfd, 0, mdevsize, hlarge, hsmall, MAXHASHES (hashsize), &hashreqs, &blockreqs, 0, zeroblocks, flushcache);

    // finish the bdsync archive
    {
        off_t          pos  = 0;
        unsigned short blen = 0;

        fwrite (&pos,  sizeof (pos),  1, stdout);
        fwrite (&blen, sizeof (blen), 1, stdout);
    }

    // write hash if requested
    if (checksum) {
        size_t        tlen, len, clen;
        unsigned char *buf, *cbuf, *cp;

        if (remdata) {
            send_getchecksum (&wr_queue);
            get_rd_queue (&wr_queue, &rd_queue,  &token, &msg, &msglen, NULL, NULL);
            check_token ("", token, msg_checksum);
            parse_checksum (msg, msglen, &clen, &cbuf);
            free (msg);
        } else {
            flush_checksum (&cs_state, &clen, &cbuf);
        }

        tlen  = strlen (checksum);
        len   = tlen + 1 + clen + 1;

        buf   = malloc (len);
        cp    = buf;

        *cp++ = tlen;
        memcpy (cp, checksum, tlen);
        cp   += tlen;

        *cp++ = clen;
        memcpy (cp, cbuf, clen);
        cp   += clen;

        fwrite (buf, len, 1, stdout);

        free (buf);
    } else {
        fwrite ("", 1, 1, stdout);
    }

    verbose (2, "do_client: get_rd_wait = %d.%06d\n", get_rd_wait.tv_sec, get_rd_wait.tv_usec);

    send_done (&wr_queue);
    get_rd_queue (&wr_queue, &rd_queue,  &token, &msg, &msglen, NULL, NULL);
    check_token ("", token, msg_done);
    parse_done (msg, msglen);
    free (msg);

    if (waitpid (pid, &status, 0) == -1) exitmsg (exitcode_process_error, "waitpid: %s\n", strerror (errno));

    cleanup_rd_queue (&rd_queue);
    cleanup_wr_queue (&wr_queue);

    dump_mallinfo ();

    return WEXITSTATUS(status);
};

enum exitcode do_patch (char *dev, int warndev, int diffsize)
{
    int            devfd, len;
    off_t          devsize, ndevsize;
    int            bufsize = 4096;
    char           *buf = malloc (bufsize);
    off_t          lpos;
    int            bytct = 0, blkct = 0, segct = 0;
    unsigned short devlen;
    char           *devname;

    if (!fgets (buf, bufsize - 1, stdin)) {
        verbose (0, "do_patch: EOF(stdin)\n");
        exit (exitcode_invalid_patch_format);
    }
    len = strlen (buf);
    if (buf[len-1] != '\n' || strncmp (buf, "BDSYNC ", 7)) {
        verbose (0, "ERROR: Bad header\n");
        exit (exitcode_invalid_patch_format);
    }
    if (len-1 != strlen (ARCHVER) || strncmp (buf, ARCHVER, len-1)) {
        verbose (0, "ERROR: Bad archive version\n");
        exit (exitcode_invalid_patch_format);
    }

    if (   fread (&ndevsize, 1, sizeof (ndevsize), stdin) != sizeof (ndevsize)
        || fread (&devlen,   1, sizeof (devlen),   stdin) != sizeof (devlen)
        || devlen > 16384) {
        verbose (0, "ERROR: Bad data (1)\n");
        exit (exitcode_invalid_patch_format);
    }
    devname = malloc (devlen + 1);
    if (fread (devname, 1, devlen, stdin) != devlen) {
        verbose (0, "ERROR: Bad data (2)\n");
        exit (exitcode_invalid_patch_format);
    }
    devname[devlen] = '\0';
    if (dev == NULL) {
        dev = devname;
    } else {
        if (warndev && strcmp (dev, devname)) {
            verbose (0, "Warning: different device names parameter=%s data=%s\n", dev, devname);
        }
        free (devname);
    }

    devfd = opendev (dev, &devsize, O_RDWR);

    if (ndevsize != devsize) {
        if (diffsize & ds_warn) {
            verbose (0, "Different sizes current=%lld patch=%lld\n", devsize, ndevsize);
        }
        switch (diffsize & ds_mask) {
        case ds_strict:
            exit (exitcode_diffsize_mismatch);
            break;
        case ds_resize:
            if (ftruncate (devfd, ndevsize) != 0) {
                verbose (0, "Cannot resize device=%s\n", devname);
                exit (exitcode_diffsize_mismatch);
            }
            devsize = ndevsize;
            break;
        case ds_minsize:
            break;
        }
    }

    lpos = -1;

    for (;;) {
        off_t          pos;
        unsigned short blen;

        if (   fread (&pos,  1, sizeof (pos),  stdin) != sizeof (pos)
            || fread (&blen, 1, sizeof (blen), stdin) != sizeof (blen)
            || blen < 0 || pos + blen > ndevsize) {
            verbose (0, "Bad data (3)\n");
            exit (exitcode_invalid_patch_format);
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
            exit (exitcode_invalid_patch_format);
        }
        verbose (3, "do_patch: write 1: pos=%lld len=%d\n", (long long)pos, blen);

        lpos = pos + blen;

        if (pos + blen > devsize) {
            /* optional check for ds_minsize here? */
            blen = devsize - pos;
        }
        if (blen <= 0) continue;

        verbose (2, "do_patch: write 2: pos=%lld len=%d\n", (long long)pos, blen);
        if (pwrite (devfd, buf, blen, pos) != blen) {
            verbose (0, "Write error: pos=%lld len=%d\n", (long long)pos, blen);
            exit (exitcode_write_error);
        }
    }

    {
        unsigned char c;
        int clen;

        if ((fread (&c, 1, sizeof (c), stdin) != 1) || (c > 127)) {
            verbose (0, "Bad data\n");
            exit (exitcode_invalid_patch_format);
        }
        if (c != 0) {
            clen = c;
            char *checksum = malloc (clen + 1);
            if (fread (checksum, 1, clen, stdin) != clen) {
                verbose (0, "Bad data\n");
                exit (exitcode_invalid_patch_format);
            }
            checksum[clen] = '\0';

            if ((fread (&c, 1, sizeof (c), stdin) != 1) || (c > 127)) {
                verbose (0, "Bad data\n");
                exit (exitcode_invalid_patch_format);
            }
            clen = c;
            unsigned char *cval = malloc (clen);
            if (fread (cval, 1, clen, stdin) != clen) {
                verbose (0, "Bad data\n");
                exit (exitcode_invalid_patch_format);
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

static int parse_diffsize (int diffsize, char *options)
{
    struct ds_map {
        char *string;
        int  id;
    };
    struct ds_map map[] = {
        { "strict",  ds_strict  }
    ,   { "resize",  ds_resize  }
    ,   { "minsize", ds_minsize }
    ,   { "warn",    ds_warn    }
    ,   { NULL,      0          }
    };
    struct ds_map *mp;

    char *cp, *np;

    if (diffsize != ds_none) {
        fprintf (stderr, "double diffsize specification\n");
        return -1;
    }
    if (options == NULL) return ds_resize;

    cp = options;

    while (*cp) {
        np = strchr (cp, ',');
        if (!np) {
            np = strchr (cp, 0);
        };
        for (mp = map; mp->string != NULL; mp++) {
            if (!strncmp (cp, mp->string, np - cp)) break;
        }
        if (mp->string == NULL) {
            fprintf (stderr, "bad diffsize options %s\n", options);
            return -1;
        }
        if (mp->id != ds_warn && (diffsize & ds_mask)) {
            fprintf (stderr, "contradictive diffsize %d options %s\n", diffsize, options);
            return -1;
        }
        diffsize |= mp->id;
        cp = (*np == ',' ? np + 1 : np);
    }
    if ((diffsize & ds_mask) == ds_none) diffsize |= ds_resize;

    return diffsize;
};

static struct option long_options[] = {
      {"server",     no_argument,       0, 's' }
    , {"patch",      optional_argument, 0, 'p' }
    , {"verbose",    no_argument,       0, 'v' }
    , {"blocksize",  required_argument, 0, 'b' }
    , {"hash",       required_argument, 0, 'h' }
    , {"checksum",   required_argument, 0, 'c' }
    , {"twopass",    no_argument,       0, 't' }
    , {"remdata",    no_argument,       0, 'r' }
    , {"fixedsalt",  no_argument,       0, 'f' }
    , {"diffsize",   optional_argument, 0, 'd' }
    , {"zeroblocks", no_argument,       0, 'z' }
    , {"warndev",    no_argument,       0, 'w' }
    , {"flushcache", no_argument,       0, 'F' }
    , {0,            0,                 0,  0  }
};

enum mode {
    mode_patch
,   mode_client
,   mode_server
};

int main (int argc, char *argv[])
{
    off_t blocksize  = 4096, hlarge, hsmall;
    int   isserver   = 0;
    int   ispatch    = 0;
    int   twopass    = 0;
    int   remdata    = 0;
    int   fixedsalt  = 0;
    int   diffsize   = ds_none;
    int   zeroblocks = 0;
    int   warndev    = 0;
    int   flushcache = 0;
    int   mode       = mode_client;
    int   retval     = 1;
    char  *patchdev  = NULL;
    char  *hash      = NULL;
    char  *checksum  = NULL;
    char  *cp;

    for (;;) {
        int option_index = 0;
        int c;

        c = getopt_long ( argc, argv, "sp::vb:h:c:trfd::zw"
                        , long_options, &option_index);

        if (c == -1) break;

        switch (c) {
        case 's':
            isserver = 1;
            mode     = mode_server;
            break;
        case 'p':
            ispatch  = 1;
            mode     = mode_patch;
            patchdev = (optarg ? optarg : NULL);
            break;
        case 'v':
            isverbose++;
            break;
        case 'b':
            blocksize = strtol (optarg, &cp, 10);
            if (cp == optarg || *cp != '\0') {
                fprintf (stderr, "bad number %s\n", optarg);
                return exitcode_invalid_params;
            }
            break;
        case 'h':
            hash = optarg;
            break;
        case 'c':
            checksum = optarg;
            break;
        case 't':
            twopass = 1;
            break;
        case 'r':
            remdata = 1;
            break;
        case 'f':
            fixedsalt = 1;
            break;
        case 'd':
            diffsize = parse_diffsize (diffsize, optarg);
            if (diffsize == -1) return exitcode_invalid_params;
            break;
        case 'z':
            zeroblocks = 1;
            break;
        case 'w':
            warndev = 1;
            break;
        case 'F':
            flushcache = 1;
            break;
        case '?':
            return exitcode_invalid_params;
        }
    }
    vhandler = verbose_printf;

    switch (diffsize & ds_mask) {
    case ds_none:
        diffsize |= ds_strict;
    case ds_strict:
        diffsize |= ds_warn;
        break;
    }

    hsmall = blocksize;
    hlarge = (twopass ? 64 * hsmall : hsmall);

    if (isserver && ispatch) {
        fprintf (stderr, "Contradictive options --server and --patch\n");
        exit (exitcode_invalid_params);
    }

    if (checksum && (strlen (checksum) > 127)) {
        verbose (0, "paramater too long for option --checksum\n");
        exit (exitcode_invalid_params);
    }

    if (warndev && !ispatch) {
        fprintf (stderr, "Options --warndev only valid with --patch\n");
        exit (exitcode_invalid_params);
    }

    if (zeroblocks && ispatch) {
        fprintf (stderr, "Contradictive options --zeroblocks and --patch\n");
        exit (exitcode_invalid_params);
    }

    if (ispatch || isserver) {
        if (hash) {
            fprintf (stderr, "Contradictive options --hash and --%s\n", (isserver ? "server" : "patch"));
            exit (exitcode_invalid_params);
        }
        if (checksum) {
            fprintf (stderr, "Contradictive options --checksum and --%s\n", (isserver ? "server" : "patch"));
            exit (exitcode_invalid_params);
        }
    }

#   ifdef DBG_MTRACE
    mtrace ();
#   endif

    hash_global_init ();

    switch (mode) {
    case mode_patch:
        if (optind != argc) {
            verbose (0, "Bad number of arguments %d\n", argc - optind);
            return exitcode_invalid_params;
        }
        retval = do_patch (patchdev, warndev, diffsize);
        break;
    case mode_server:
        vhandler = verbose_syslog;
        if (optind != argc) {
            verbose (0, "Bad number of arguments %d\n", argc - optind);
            return exitcode_invalid_params;
        }
        retval = do_server (zeroblocks);
        break;
    case mode_client:
        if (optind != argc - 3) {
            verbose (0, "Bad number of arguments %d\n", argc - optind);
            return exitcode_invalid_params;
        }

        if (!hash) hash = "md5";

        retval = do_client (hash, checksum, argv[optind], argv[optind + 1],argv[optind + 2], hlarge, hsmall, remdata, fixedsalt, diffsize, zeroblocks, flushcache);
        break;
    }

    hash_global_cleanup ();

#   ifdef DBG_MTRACE
    muntrace ();
#   endif

    return retval;
}
