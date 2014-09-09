/*
 * Copyright (c) 2009-2010 Amit Singh. All Rights Reserved.
 * http://osxbook.com
 *
 * TPM Emulator Device Bridge for Mac OS X
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *   1. Redistributions of source code must retain the above copyright notice,
 *      this list of conditions and the following disclaimer.
 *   2. Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR “AS IS” AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO
 * EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/types.h>
#include <sys/fcntl.h>
#include <sys/systm.h>
#include <sys/conf.h>
#include <sys/ioctl.h>
#include <sys/param.h>
#include <sys/unistd.h>
#include <sys/malloc.h>
#include <sys/kpi_socket.h>
#include <sys/kpi_mbuf.h>
#include <sys/un.h>
#include <kern/locks.h>
#include <miscfs/devfs/devfs.h>
#include <mach/mach_types.h>
#include <libkern/OSAtomic.h>
#include "config.h"

/* configurable */

#define TPM_BRIDGE_NAME    "tpm"     /* bridge device file name (/dev/tpm) */
#define TPM_BRIDGE_MODE    0666      /* world readable/writable by default */
#define TPM_BRIDGE_UID     UID_ROOT  /* bridge device file owner ID */
#define TPM_BRIDGE_GID     GID_WHEEL /* bridge device file group ID */

/* buffer */

static char tpm_buffer[TPM_CMD_BUF_SIZE] = { 0 };

/* locking */

static lck_grp_attr_t* tpm_mtx_grp_attr = NULL;
static lck_grp_t*      tpm_mtx_grp = NULL;
static lck_attr_t*     tpm_mtx_attr = NULL;
static lck_mtx_t*      tpm_mtx = NULL;

/* user socket */

errno_t sock_nointerrupt(socket_t sock, int on);

static SInt32   tpm_activity = 0;
static UInt32   tpm_in_io = 0;
static socket_t tpmd_socket = 0;

static struct sockaddr_un tpmd_socket_addr = {
    sizeof(struct sockaddr_un),
    AF_LOCAL,
    TPM_SOCKET_NAME,
};

/* device */

static int       dev_tpm_index = -1;
static const int dev_tpm_minor = 0;
static void*     dev_tpm_node = NULL;

d_open_t   tpm_dev_open;
d_read_t   tpm_dev_read;
d_write_t  tpm_dev_write;
extern int seltrue(dev_t, int, struct proc*);

static struct cdevsw cdev_tpm = {
    tpm_dev_open,
    (d_close_t*)&nulldev,
    tpm_dev_read,
    tpm_dev_write,
    (d_ioctl_t*)&enodev,
    (d_stop_t*)&nulldev,
    (d_reset_t*)&nulldev,
    0,
    (select_fcn_t*)seltrue,
    eno_mmap,
    eno_strat,
    eno_getc,
    eno_putc,
    D_TTY,
};

static int    tpmd_connect(void);
static void   tpmd_disconnect(void);
kern_return_t tpm_bridge_start(kmod_info_t* ki, void* d);
kern_return_t tpm_bridge_stop(kmod_info_t* ki, void* d);
static int    tpm_bridge_locking_start(void);
static int    tpm_bridge_locking_stop(void);
static int    tpm_bridge_devfs_start(void);
static int    tpm_bridge_devfs_stop(void);

int
tpm_dev_open(dev_t dev, int flags, int devtype, struct proc* p)
{
    (void)OSIncrementAtomic(&tpm_activity);

    int error = 0;

    lck_mtx_lock(tpm_mtx);

    if ((tpmd_socket == NULL) || !sock_isconnected(tpmd_socket)) {
        if (tpmd_connect() != 0) {
            tpmd_socket = NULL;
            lck_mtx_unlock(tpm_mtx);
            error = ECONNREFUSED;
            goto out;
        }
    }

    lck_mtx_unlock(tpm_mtx);

out:

    (void)OSDecrementAtomic(&tpm_activity);
    
    return error;
}

int 
tpm_dev_read(dev_t dev, struct uio* uio, int ioflag)
{
    (void)OSIncrementAtomic(&tpm_activity);

    errno_t error = 0;
    size_t recvlen;
    struct msghdr msg;
    struct iovec aiov[1];

    lck_mtx_lock(tpm_mtx);

    if ((tpmd_socket == NULL) || !sock_isconnected(tpmd_socket)) {
        lck_mtx_unlock(tpm_mtx);
        error = ENOTCONN;
        goto out;
    }

    if (tpm_in_io) {
        error = msleep(&tpm_in_io, tpm_mtx, PCATCH, "tpm_in_io", NULL);
        if (error != 0) {
            lck_mtx_unlock(tpm_mtx);
            error = EAGAIN;
            goto out;
        }
    }

    tpm_in_io = 1;

    lck_mtx_unlock(tpm_mtx);

    (void)sock_nointerrupt(tpmd_socket, 1);

    recvlen = (uint32_t)uio_resid(uio);

    memset(&msg, 0, sizeof(msg));
    aiov[0].iov_base = (caddr_t)tpm_buffer;
    aiov[0].iov_len = TPM_CMD_BUF_SIZE;
    if (recvlen < TPM_CMD_BUF_SIZE) {
        aiov[0].iov_len = recvlen;
    }
    msg.msg_iovlen = 1;
    msg.msg_iov = aiov;

    if ((error = sock_receive(tpmd_socket, &msg, 0, (size_t*)&recvlen)) == 0) {
        error = uiomove64((addr64_t)(uintptr_t)tpm_buffer, (int)recvlen, uio);
    }

    lck_mtx_lock(tpm_mtx);
    tpm_in_io = 0;
    wakeup_one((caddr_t)&tpm_in_io);
    lck_mtx_unlock(tpm_mtx);

out:

    (void)OSDecrementAtomic(&tpm_activity);

    return error;
}

int                           
tpm_dev_write(dev_t dev, struct uio* uio, int ioflag)
{
    (void)OSIncrementAtomic(&tpm_activity);

    errno_t error = 0;
    size_t sentlen;
    struct msghdr msg;
    struct iovec aiov[1];

    lck_mtx_lock(tpm_mtx);

    if ((tpmd_socket == NULL) || !sock_isconnected(tpmd_socket)) {
        lck_mtx_unlock(tpm_mtx);
        error = ENOTCONN;
        goto out;
    }

    if (tpm_in_io) {
        error = msleep(&tpm_in_io, tpm_mtx, PCATCH, "tpm_in_io", NULL);
        if (error != 0) {
            lck_mtx_unlock(tpm_mtx);
            error = EAGAIN;
            goto out;
        }
    }

    tpm_in_io = 1;

    lck_mtx_unlock(tpm_mtx);

    sentlen = min((uint32_t)uio_resid(uio), TPM_CMD_BUF_SIZE);

    if ((error = uiomove64((addr64_t)(uintptr_t)tpm_buffer,
                           (int)sentlen, uio)) == 0) {
        memset(&msg, 0, sizeof(msg));
        aiov[0].iov_base = (caddr_t)tpm_buffer;
        aiov[0].iov_len = sentlen;
        msg.msg_iovlen = 1;
        msg.msg_iov = aiov;
        error = sock_send(tpmd_socket, &msg, 0, &sentlen);
    }

    lck_mtx_lock(tpm_mtx);
    tpm_in_io = 0;
    wakeup_one((caddr_t)&tpm_in_io);
    lck_mtx_unlock(tpm_mtx);

out:

    (void)OSDecrementAtomic(&tpm_activity);

    return error;
}

static int
tpmd_connect(void)
{
    errno_t error;
    struct timeval tv;

    error = sock_socket(PF_LOCAL, SOCK_STREAM, 0, NULL, NULL, &tpmd_socket);
    if (error != 0) {
        tpmd_socket = NULL;
        return error;
    }

    tv.tv_sec = 10;
    tv.tv_usec = 0;
    error = sock_setsockopt(tpmd_socket, SOL_SOCKET, SO_RCVTIMEO, &tv,
                            sizeof(struct timeval));
    if (error != 0) {
        sock_close(tpmd_socket);
        tpmd_socket = NULL;
        return error;
    }

    error = sock_connect(tpmd_socket,
                         (const struct sockaddr*)&tpmd_socket_addr, 0);
    if (error != 0) {
        sock_close(tpmd_socket);
        tpmd_socket = NULL;
        return error;
    }

    return 0;
}

static void
tpmd_disconnect(void)
{
    if (tpmd_socket != NULL) {
        sock_shutdown(tpmd_socket, SHUT_RDWR);
        sock_close(tpmd_socket);
        tpmd_socket = NULL;
    }
}

static int
tpm_bridge_locking_start(void)
{
    tpm_mtx_grp_attr = lck_grp_attr_alloc_init();
    if (tpm_mtx_grp_attr == NULL) {
        goto failed;
    }

    tpm_mtx_grp = lck_grp_alloc_init("tpm_mtx", tpm_mtx_grp_attr);
    if (tpm_mtx_grp == NULL) {
        goto failed;
    }

    tpm_mtx_attr = lck_attr_alloc_init();
    if (tpm_mtx_attr == NULL) {
        goto failed;
    }

    tpm_mtx = lck_mtx_alloc_init(tpm_mtx_grp, tpm_mtx_attr);
    if (tpm_mtx == NULL) {
        goto failed;
    }

    return KERN_SUCCESS;

failed:

    (void)tpm_bridge_locking_stop();

    return KERN_FAILURE;
}

static int
tpm_bridge_locking_stop(void)
{
    if (tpm_mtx != NULL) {
        lck_mtx_free(tpm_mtx, tpm_mtx_grp);
        tpm_mtx = NULL;
    }

    if (tpm_mtx_attr != NULL) {
        lck_attr_free(tpm_mtx_attr);
        tpm_mtx_attr = NULL;
    }

    if (tpm_mtx_grp != NULL) {
        lck_grp_free(tpm_mtx_grp);
        tpm_mtx_grp = NULL;
    }

    if (tpm_mtx_grp_attr != NULL) {
        lck_grp_attr_free(tpm_mtx_grp_attr);
        tpm_mtx_grp_attr = NULL;
    }

    return KERN_SUCCESS;
}

static int
tpm_bridge_devfs_start(void)
{
    dev_tpm_index = cdevsw_add(-1, &cdev_tpm);
    if (dev_tpm_index == -1) {
        return KERN_FAILURE;
    }

    dev_tpm_node = devfs_make_node(makedev(dev_tpm_index, dev_tpm_minor),
                                   DEVFS_CHAR, TPM_BRIDGE_UID, TPM_BRIDGE_GID,
                                   TPM_BRIDGE_MODE, TPM_BRIDGE_NAME);
    if (dev_tpm_node == NULL) {
        (void)tpm_bridge_devfs_stop();
        return KERN_FAILURE;
    }

    return KERN_SUCCESS;
}

static int
tpm_bridge_devfs_stop(void)
{
    int ret = KERN_SUCCESS;

    if (dev_tpm_node != NULL) {
        devfs_remove(dev_tpm_node);
        dev_tpm_node = NULL;
    }

    if (dev_tpm_index != -1) {
        ret = cdevsw_remove(dev_tpm_index, &cdev_tpm);
        if (ret != dev_tpm_index) {
            ret = KERN_FAILURE;
        } else {
            dev_tpm_index = -1;
            ret = KERN_SUCCESS;
        }
    }

    return ret;
}

kern_return_t
tpm_bridge_start(kmod_info_t* ki, void* d)
{
    if (tpm_bridge_locking_start() != KERN_SUCCESS) {
        return KERN_FAILURE;
    }

    if (tpm_bridge_devfs_start() != KERN_SUCCESS) {
        tpm_bridge_locking_stop();
        return KERN_FAILURE;
    }

#ifndef SUN_LEN
#define SUN_LEN(su) \
        (sizeof(*(su)) - sizeof((su)->sun_path) + strlen((su)->sun_path))
#define SUN_LEN_PRIVATELY_DEFINED 1
#endif

    tpmd_socket_addr.sun_len = SUN_LEN(&tpmd_socket_addr);

#if SUN_LEN_PRIVATELY_DEFINED
#undef SUN_LEN
#endif

    return KERN_SUCCESS;
}

kern_return_t
tpm_bridge_stop(kmod_info_t* ki, void* d)
{
    lck_mtx_lock(tpm_mtx);

    (void)tpm_bridge_devfs_stop();

    if ((tpmd_socket != NULL) && sock_isconnected(tpmd_socket)) {
        tpmd_disconnect();
        tpmd_socket = NULL;
    }

    lck_mtx_unlock(tpm_mtx);

    do {
        struct timespec ts = { 1, 0 };
        (void)msleep(&tpm_activity, NULL, PUSER, "tpm_activity", &ts);
    } while (tpm_activity > 0);


    (void)tpm_bridge_locking_stop();

    return KERN_SUCCESS;
}
