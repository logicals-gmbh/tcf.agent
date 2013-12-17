/*******************************************************************************
 * Copyright (c) 2007, 2011 Wind River Systems, Inc. and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 * The Eclipse Public License is available at
 * http://www.eclipse.org/legal/epl-v10.html
 * and the Eclipse Distribution License is available at
 * http://www.eclipse.org/org/documents/edl-v10.php.
 * You may elect to redistribute this code under either of these licenses.
 *
 * Contributors:
 *     Wind River Systems - initial API and implementation
 *******************************************************************************/

/*
 * Asynchronous system call request interface
 */

#ifndef D_asyncreq
#define D_asyncreq

#if ENABLE_AIO
#  include <aio.h>
#endif
#ifdef __SYMBIAN32__
#  include <select.h>
#endif
#include <time.h>
#include <sys/stat.h>
#include <dirent.h>

#include <tcf/framework/link.h>
#include <tcf/framework/events.h>

enum {
    AsyncReqRead,                       /* File read */
    AsyncReqWrite,                      /* File write */
    AsyncReqSeekRead,                   /* File seek and read */
    AsyncReqSeekWrite,                  /* File seek and write */
    AsyncReqRecv,                       /* Socket recv */
    AsyncReqSend,                       /* Socket send */
    AsyncReqRecvFrom,                   /* Socket recvfrom */
    AsyncReqSendTo,                     /* Socket sendto */
    AsyncReqAccept,                     /* Accept socket connections */
    AsyncReqConnect,                    /* Connect to socket */
    AsyncReqConnectPipe,                /* Connect named pipe (Windows) */
    AsyncReqWaitpid,                    /* Wait for process change */
    AsyncReqSelect,                     /* Do select() on file handles */
    AsyncReqClose,                      /* File close */
    AsyncReqCloseDir,                   /* Directory close */
    AsyncReqOpen,                       /* File open */
    AsyncReqStat,                       /* File stat */
    AsyncReqFstat,                      /* File fstat */
    AsyncReqLstat,                      /* File lstat */
    AsyncReqRemove,                     /* File remove */
    AsyncReqOpendir,                    /* Directory open */
    AsyncReqReaddir                     /* Directory read */
};

struct DirFileNode {
    char * path;
    struct stat * statbuf;
#if defined(_WIN32) || defined(__CYGWIN__)
    DWORD win32_attrs;
#endif
};

typedef struct AsyncReqInfo AsyncReqInfo;
struct AsyncReqInfo {
    EventCallBack * done; /* The callback argument is address of AsyncReqInfo */
    void * client_data;
    int type;
    union {
        struct {
            /* In */
            int fd;
            int64_t offset;
            void * bufp;
            size_t bufsz;
            int flags;
            int permission;
            char * file_name;
            struct stat statbuf;
#if defined(_WIN32) || defined(__CYGWIN__)
            DWORD win32_attrs;
#endif
            /* Out */
            ssize_t rval;

#if ENABLE_AIO
            /* Private */
            struct aiocb aio;
#endif
        } fio;
        struct {
            /* In */
            char * path;
            int max_file_per_dir;
            struct DirFileNode *files;
            int eof;

            /* in/Out */
            DIR * dir;
            int rval;
        } dio;
        struct {
            /* In */
            int sock;
            void * bufp;
            size_t bufsz;
            int flags;
            struct sockaddr * addr;
#if defined(_WRS_KERNEL)
            int addrlen;
#else
            socklen_t addrlen;
#endif

            /* Out */
            ssize_t rval;
        } sio;
        struct {
            /* In */
            int sock;
            struct sockaddr * addr;
#if defined(_WRS_KERNEL)
            int addrlen;
#else
            socklen_t addrlen;
#endif

            /* Out */
            int rval;
        } acc;
        struct {
            /* In */
            int sock;
            struct sockaddr * addr;
            socklen_t addrlen;

            /* Out */
            int rval;
        } con;
#if defined(_WIN32) || defined(__CYGWIN__)
        struct {
            /* In */
            HANDLE pipe;

            /* Out */
            BOOL rval;
        } cnp;
#endif
        struct {
            /* In */
            pid_t pid;
            int options;

            /* Out */
            int status;
            pid_t rval;
        } wpid;
        struct {
            /* In */
            int nfds;
            fd_set readfds;
            fd_set writefds;
            fd_set errorfds;
            struct timespec timeout;

            /* Out */
            int rval;
        } select;
    } u;
    int error;                  /* Readable by callback function */
};

extern void async_req_post(AsyncReqInfo * req);

extern void ini_asyncreq(void);

#endif /* D_asyncreq */
