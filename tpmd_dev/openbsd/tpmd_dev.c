/* Software-based Trusted Platform Module (TPM) Emulator
 * Copyright (C) 2004-2010 Mario Strasser <mast@gmx.net>
 * Copyright (C) 2007 Sebastian Schuetz <sebastian_schuetz@genua.de>
 *
 * This module is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 *
 * This module is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * $Id$
 */

#include <sys/param.h>
#include <sys/fcntl.h>
#include <sys/systm.h>
#include <sys/ioctl.h>
#include <sys/exec.h>
#include <sys/conf.h>
#include <sys/lkm.h>
#include <sys/malloc.h>
#include <sys/socket.h>
#include <sys/mbuf.h>
#include <sys/un.h>
#include <sys/socketvar.h>
#include <sys/errno.h>
#include <sys/lock.h>
#include <sys/proc.h>
#include <machine/intr.h>

#include "tpmd_dev.h"


int	tpmopen __P((dev_t dev, int oflags, int devtype, struct proc *p));
int 	tpmclose __P((dev_t dev, int fflag, int devtype, struct proc *p));
int	tpmread __P((dev_t dev, struct uio *uio, int ioflag));
int	tpmioctl __P((dev_t dev, u_long cmd, caddr_t data, int fflag,
			struct proc *p));
int	tpmwrite __P((dev_t dev,struct uio *uio, int ioflag));
int	tpm_handler __P((struct lkm_table *lkmtp, int cmd));


/*
 * Provides a lkm which forwards all requests to /dev/tpm to
 * a local unix domain socket, reads the reply from the tpmd
 * and writes back to the user (tcsd)
 */




/* declare our character device */
cdev_decl(tpm);

/* define our cdev struct containing the functions */
static struct cdevsw cdev_tpm = cdev_tpmd_init(1,tpm);

/* fill in the lkm_dev structure */
MOD_DEV("tpm",LM_DT_CHAR,-1,&cdev_tpm);


/* code starts */

/* test and set the bit bit on addy
 * there is no guarantee that this function
 * works on other purposes as the tpm_emulator
 */
int
test_and_set_bit(uint32_t bit, uint32_t *addy)
{
	int rbit = 0;
	uint32_t tmp, mask;

	tmp = *addy;
	tmp >>=bit;
	if (tmp & 0x1) {
		rbit = 1;
	}
	mask = 1 << bit;
	*addy |= mask;
	return rbit;
}

int
clear_bit(uint32_t bit, uint32_t *addy)
{
	uint32_t mask = 0x1;

	mask = ~(mask << bit);
	*addy &= mask;

	return 0;
}

/*
 * create a connection to our local socket file
 * named by socket_name
 */
static int
tpmd_connect(char *socket_name)
{
	int res;
	struct sockaddr_un *saddr;

	debug("%s()", __FUNCTION__);
	res = socreate(AF_UNIX, &tpmd_sock, SOCK_STREAM, 0);
	if (res != 0) {
		error("sock_create() failed: %d", res);
		tpmd_sock = NULL;
		return res;
	}
	nm = m_get(M_WAITOK,M_MBUF);
	if (nm == NULL) {
		error("malloc() failed");
		return -1;
	}
	nm->m_len = sizeof(struct sockaddr_un);
	saddr = mtod(nm, struct sockaddr_un *);
	saddr->sun_family = AF_UNIX;
	saddr->sun_len = sizeof(*saddr);
	strlcpy(saddr->sun_path,socket_name,sizeof(saddr->sun_path));
	res = soconnect(tpmd_sock,nm);
	if (res != 0) {
		error("sock_connect() failed: %d", res);
		m_free(nm);
		nm = NULL;
		soclose(tpmd_sock);
		tpmd_sock = NULL;
	}

	return res;
}

/*
 * shut down the socket and free the
 * mbuf struct
 */
static void
tpmd_disconnect(void)
{
	debug("%s()",__FUNCTION__);
	if (tpmd_sock != NULL) {
		soshutdown(tpmd_sock,SHUT_RDWR);
		soclose(tpmd_sock);
		tpmd_sock = NULL;
	}
	if (nm != NULL) {
		m_free(nm);
		nm = NULL;
	}
}



int
outputData(const char *str, uint8_t *d, int len)
{
	int i = 0;

	printf("%s",str);
	for (i = 0; i < len; i++) {
		printf("%.2x ",d[i]);
	}
	printf("\n");
}


int
tpmopen(dev_t dev, int oflags, int devtype, struct proc *p)
{
	debug("%s()", __FUNCTION__);
	simple_lock(&slock);
	if (test_and_set_bit(TPM_STATE_IS_OPEN, (void*)&module_state))
		return -EBUSY;
	if (tpmd_connect(tpmd_socket_name)) {
		tpmclose(dev,oflags,devtype,p);
		simple_unlock(&slock);
		return -1;
	}
	simple_unlock(&slock);
	debug("connected");
  	return 0;
}

int
tpmclose(dev_t dev, int oflags, int devtype, struct proc *p)
{
	simple_lock(&slock);
	debug("%s()", __FUNCTION__);
	tpmd_disconnect();
	clear_bit(TPM_STATE_IS_OPEN, (void*)&module_state);
	simple_unlock(&slock);

	return 0;
}


/*
 *  read the data and write it back
 */
int
tpmread(dev_t dev, struct uio *uio, int ioflag)
{
	int error;
	debug("%s(%u)",__FUNCTION__,uio->uio_resid);
	simple_lock(&slock);

	/* this flag is neccessary, otherwise soreceive
 	 * sometime returns EINTR
	 */
	tpmd_sock->so_rcv.sb_flags |= SB_NOINTR;
	error = soreceive(tpmd_sock,NULL,uio,NULL,NULL,NULL,0);

	if (error) {
		debug("soreceive() failed %i",error);
	}
	simple_unlock(&slock);

	return error;
}

/*
 * write the data through the socket
 */
int
tpmwrite(dev_t dev, struct uio *uio, int ioflag)
{
	int error;
	debug("%s(%d)", __FUNCTION__, uio->uio_resid);
	simple_lock(&slock);

	/* ok send the command to our socket */
	if (tpmd_sock == NULL ||
 	    !(tpmd_sock->so_state & SS_ISCONNECTED)) {
		return ENOTCONN;
        }
	error = sosend(tpmd_sock, nm ,uio ,NULL,NULL,0);
	if (error) {
		error("sosend() failed %i",error);
		return error;
        }
	simple_unlock(&slock);

	return error;
}


/*
 * The goal was not to do any "tddl" related modifications in trousers.
 * However I don`t  know how to get the correct len of our data without
 * modifying the trousers ioctl call. Well trousers provides some fallback to
 * read/write methods, so it is not that much important to provide some
 * ioctl infrastructure
 */
int
tpmioctl(dev_t dev, u_long cmd, caddr_t data, int fflag,struct proc *p)
{
	/* tell trousers that this is not supported */
	return ENODEV;
}

/* tpm_handler for loading/unloading */
int
tpm_handler(struct lkm_table *lkmtp, int cmd)
{
	switch (cmd) {
		case LKM_E_LOAD:
			simple_lock_init(&slock);
			break;
		case LKM_E_UNLOAD:
			simple_unlock(&slock);
			tpmclose(0,0,0,NULL);
			break;
	}
	return 0;
}

/* our main entry point */
int
tpm(struct lkm_table *lkmtp, int cmd, int ver)
{
	DISPATCH(lkmtp,cmd,ver,tpm_handler,tpm_handler,lkm_nofunc);
}



