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

#ifndef _TPM_DEV_HEADER_
#define _TPM_DEV_HEADER_

#include "config.h"

#define cdev_tpmd_init(c,n) { \
    dev_init(c,n,open),dev_init(c,n,close),dev_init(c,n,read), \
    dev_init(c,n,write), dev_init(c,n,ioctl),(dev_type_stop((*))) lkmenodev, \
    0,(dev_type_poll((*))) lkmenodev,(dev_type_mmap((*))) lkmenodev }


/* This code is from linux_module.c */

/* module state */
static uint32_t module_state;
static struct socket *tpmd_sock = NULL;
static struct mbuf *nm = NULL;
static struct simplelock slock;

char tpmd_socket_name[] = TPM_SOCKET_NAME;

#define TPM_MODULE_NAME   "tpm_dev"
#define TPM_STATE_IS_OPEN 0


#ifdef DEBUG
#define debug(fmt, ...) printf("%s %s:%d: Debug: " fmt "\n", \
                        TPM_MODULE_NAME, __FILE__, __LINE__, ## __VA_ARGS__)
#else
#define debug(fmt, ...)
#endif
#define error(fmt, ...) printf("%s %s:%d: Error: " fmt "\n", \
                        TPM_MODULE_NAME, __FILE__, __LINE__, ## __VA_ARGS__)

#endif /* _TPM_DEV_HEADER_ */
