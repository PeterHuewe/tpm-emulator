/* Software-based Trusted Platform Module (TPM) Emulator
 * Copyright (C) 2004-2010 Mario Strasser <mast@gmx.net>
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
 * $Id: tpm_data.c 372 2010-02-15 12:52:00Z mast $
 */

#include "tpm_emulator.h"
#include "tpm_structures.h"
#include "tpm_marshalling.h"
#include "tpm_commands.h"
#include "tpm_data.h"

TPM_DATA tpmData;
UINT32 tpmConf;

#ifdef MTM_EMULATOR
#include "mtm/mtm_data.h"
#include "mtm/mtm_marshalling.h"
#endif

static TPM_VERSION tpm_version = { 1, 2, VERSION_MAJOR, VERSION_MINOR };

BOOL tpm_get_physical_presence(void)
{
  return (tpmData.stclear.flags.physicalPresence || TRUE);
}

static inline void init_pcr_attr(int pcr, BOOL reset, BYTE rl, BYTE el)
{
  tpmData.permanent.data.pcrAttrib[pcr].pcrReset = reset;
  tpmData.permanent.data.pcrAttrib[pcr].pcrResetLocal = rl;
  tpmData.permanent.data.pcrAttrib[pcr].pcrExtendLocal = el;
}

static void init_nv_storage(void)
{
    TPM_NV_DATA_SENSITIVE *nv;
    memset(tpmData.permanent.data.nvData, 0xff, TPM_MAX_NV_SIZE);
    /* init TPM_NV_INDEX_DIR */
    nv = &tpmData.permanent.data.nvStorage[0];
    memset(nv, 0, sizeof(TPM_NV_DATA_SENSITIVE));
    nv->tag = TPM_TAG_NV_DATA_SENSITIVE;
    nv->pubInfo.tag = TPM_TAG_NV_DATA_PUBLIC;
    nv->pubInfo.nvIndex = TPM_NV_INDEX_DIR;
    nv->pubInfo.pcrInfoRead.localityAtRelease = 0x1f;
    nv->pubInfo.pcrInfoWrite.localityAtRelease = 0x1f;
    nv->pubInfo.permission.tag = TPM_TAG_NV_ATTRIBUTES;
    nv->pubInfo.permission.attributes = TPM_NV_PER_OWNERWRITE 
                                        | TPM_NV_PER_WRITEALL;
    nv->pubInfo.dataSize = 20;
    nv->dataIndex = 0;
    nv->valid = TRUE;
    /* set NV data size */
    tpmData.permanent.data.nvDataSize = 20;
}

static void init_timeouts(void)
{
  /* for the timeouts we use the PC platform defaults */
  tpmData.permanent.data.tis_timeouts[0] = 750;
  tpmData.permanent.data.tis_timeouts[1] = 2000;
  tpmData.permanent.data.tis_timeouts[2] = 750;
  tpmData.permanent.data.tis_timeouts[3] = 750;
  tpmData.permanent.data.cmd_durations[0] = 1;
  tpmData.permanent.data.cmd_durations[1] = 10;
  tpmData.permanent.data.cmd_durations[2] = 1000;
}

void tpm_init_data(void)
{
  /* endorsement key */
  uint8_t ek_n[] =  "\xa8\xdb\xa9\x42\xa8\xf3\xb8\x06\x85\x90\x76\x93\xad\xf7"
    "\x74\xec\x3f\xd3\x3d\x9d\xe8\x2e\xff\x15\xed\x0e\xce\x5f\x93"
    "\x92\xeb\xd1\x96\x2b\x72\x18\x81\x79\x12\x9d\x9c\x40\xd7\x1a"
    "\x21\xda\x5f\x56\xe0\xc9\x48\x31\xdd\x96\xdc\xbb\x45\xc6\x8e"
    "\xad\x58\x23\xcb\xbe\xbb\x13\x2d\x6b\x86\xc5\x57\xf5\xdd\x48"
    "\xc1\x3d\xcd\x4d\xda\x81\xc4\x43\x17\xaa\x05\x40\x33\x62\x0a"
    "\x59\xdb\x28\xcd\xb5\x08\x31\xbb\x06\xf5\xf7\x71\xae\x21\xa8"
    "\xf2\x2f\x0e\x17\x80\x5d\x9c\xdf\xaa\xe9\x89\x09\x54\x65\x2b"
    "\x46\xfb\x9d\xb2\x00\x70\x63\x0d\x9a\x6d\x3d\x5e\x11\x78\x65"
    "\x90\xe6\x26\xee\x77\xbe\x08\xff\x07\x60\x5a\xcc\xf1\x0a\xbd"
    "\x44\x92\x6b\xca\xb6\xce\x66\xf9\x93\x40\xae\xf3\x3e\x53\x02"
    "\x3c\xa6\x81\xb3\xbe\xad\x6e\x6c\xa6\xf0\xeb\xdf\xe9\xa2\x83"
    "\x36\x0e\x52\x0d\x64\x17\xd9\xff\xa1\x74\x7c\x2b\xbc\x6a\xcc"
    "\xe5\x4e\xb4\x52\xd9\xec\x43\xbd\x26\x6a\x2b\x19\x19\x6e\x97"
    "\xb8\x1d\x9f\x7b\xe7\x32\x2d\xdd\x7c\x51\xc8\xe4\xf3\x02\xd4"
    "\x7c\x90\x44\xa0\x33\x72\x81\x75\xa9\x16\x27\x5c\x00\x1d\x07"
    "\x81\xd4\xf7\xac\xcb\xfe\xd6\x60\x03\x6f\x7a\xcc\x00\xd1\xc4"
    "\x85\x37";
  uint8_t ek_e[] = "\x01\x00\x01";
  uint8_t ek_p[] = "\xd7\xea\x61\x15\x8b\xa3\x71\xdf\xa8\x74\x77\xca\x88\x95"
    "\xd0\x76\x17\x43\x2c\xf6\x23\x27\x44\xb9\x0e\x18\x35\x7e\xe4"
    "\xc3\xcb\x13\x6e\xfc\x38\x02\x1e\x77\x26\x40\x9d\x17\xb2\x39"
    "\x9c\x7f\x5f\x98\xe6\xf2\x55\x0c\x12\x05\x4c\xb3\x51\xae\x29"
    "\xe7\xcd\xce\x41\x0b\x28\x4d\x97\x13\x4b\x60\xc8\xd8\x70\x81"
    "\xf9\x1c\x12\x44\xdf\x53\x0a\x87\x9d\x33\x92\x4a\x34\x69\xf0"
    "\x70\x5e\x1b\x5d\x65\xc7\x84\x90\xa2\x62\xdf\x83\x14\x10\x69"
    "\xe2\xa7\x18\x43\xd7\x1f\x60\xc9\x03\x8f\xd6\xa4\xce\xb2\x9d"
    "\x40\x37\x70\x17\x4c\xe3\x69\xd4\x59";
  uint8_t ek_q[] = "\xc8\x34\xd2\xd0\x7c\xfa\xdc\x68\xe2\x72\xd7\x92\xe2\x50"
    "\x93\xfc\xbb\x72\x55\x4d\x6b\x7a\x0c\x0b\xcf\x87\x66\x1f\x81"
    "\x71\xf3\x50\xcb\xaa\xe6\x43\x7e\xbe\x11\xc4\xec\x00\x53\xf4"
    "\x78\x13\x2b\x59\x26\x4a\x9f\x91\x61\x8f\xa7\x07\x64\x11\x5a"
    "\xf4\xaf\x9c\x9b\x5a\x5d\x69\x20\x17\x55\x74\xba\xd8\xe4\x59"
    "\x39\x1a\x0a\x7b\x4a\x30\xf0\xc8\x7f\xd9\xaf\x72\xc5\xb6\x71"
    "\xd1\xc0\x8b\x5b\xa2\x2e\xa7\x15\xca\x50\x75\x10\x48\x9c\x2b"
    "\x18\xb9\x67\x8f\x5d\x64\xc3\x28\x9f\x2f\x16\x2f\x08\xda\x47"
    "\xec\x86\x43\x0c\x80\x99\x07\x34\x0f";
  int i;
  info("initializing TPM data to default values");
  /* reset all data to NULL, FALSE or 0 */
  memset(&tpmData, 0, sizeof(tpmData));
  tpmData.permanent.data.tag = TPM_TAG_PERMANENT_DATA;
  /* set permanent flags */
  tpmData.permanent.flags.tag = TPM_TAG_PERMANENT_FLAGS;
  tpmData.permanent.flags.disable = FALSE;
  tpmData.permanent.flags.deactivated = FALSE;
  tpmData.permanent.flags.ownership = TRUE;
  tpmData.permanent.flags.readPubek = TRUE;
  tpmData.permanent.flags.allowMaintenance = TRUE;
  tpmData.permanent.flags.enableRevokeEK = TRUE;
  tpmData.permanent.flags.readSRKPub = TRUE;
  tpmData.permanent.flags.nvLocked = TRUE;
  /* set TPM vision */
  memcpy(&tpmData.permanent.data.version, 
         &tpm_version, sizeof(TPM_VERSION));
  /* seed PRNG */
  tpm_get_extern_random_bytes(&tpmData.permanent.data.rngState,
    sizeof(tpmData.permanent.data.rngState));
  /* setup PCR attributes */
  for (i = 0; i < TPM_NUM_PCR && i < 16; i++) {
    init_pcr_attr(i, FALSE, 0x00, 0x1f);
  }
  if (TPM_NUM_PCR >= 24) {
    init_pcr_attr(16, TRUE, 0x1f, 0x1f);
    init_pcr_attr(17, TRUE, 0x10, 0x1c);
    init_pcr_attr(18, TRUE, 0x10, 0x1c);
    init_pcr_attr(19, TRUE, 0x10, 0x0c);
    init_pcr_attr(20, TRUE, 0x14, 0x0e);
    init_pcr_attr(21, TRUE, 0x04, 0x04);
    init_pcr_attr(22, TRUE, 0x04, 0x04);
    init_pcr_attr(23, TRUE, 0x1f, 0x1f);
  }
  for (i = 24; i < TPM_NUM_PCR; i++) {
    init_pcr_attr(i, TRUE, 0x00, 0x00);
  }
  if (tpmConf & TPM_CONF_GENERATE_EK) {
    /* generate a new endorsement key */
    tpm_rsa_generate_key(&tpmData.permanent.data.endorsementKey, 2048);
  } else {
    /* setup endorsement key */
    tpm_rsa_import_key(&tpmData.permanent.data.endorsementKey, 
      RSA_MSB_FIRST, ek_n, 256, ek_e, 3, ek_p, ek_q);
  }
  if (tpmConf & TPM_CONF_GENERATE_SEED_DAA) {
    /* generate the DAA seed */
    tpm_get_random_bytes(tpmData.permanent.data.tpmDAASeed.nonce, 
      sizeof(tpmData.permanent.data.tpmDAASeed.nonce));
  } else {
    /* setup DAA seed */
    memcpy(tpmData.permanent.data.tpmDAASeed.nonce, 
      "\x77\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
      "\x00\x00\x00\x77", sizeof(TPM_NONCE));
  }
  memcpy(tpmData.permanent.data.ekReset.nonce, "\xde\xad\xbe\xef", 4);
  /* initialize predefined non-volatile storage */
  init_nv_storage();
  /* set the timeout and duration values */
  init_timeouts();
#ifdef MTM_EMULATOR
  mtm_init_data();
#endif
}

void tpm_release_data(void)
{
  free_TPM_DATA(tpmData);
#ifdef MTM_EMULATOR
  free_MTM_DATA(mtmData);
#endif
}

int tpm_store_permanent_data(void)
{
  uint8_t *buf, *ptr;
  size_t buf_length;
  uint32_t len;

  /* marshal data */
  buf_length = len = sizeof_TPM_VERSION(tpmData.permanent.data.version)
#ifdef MTM_EMULATOR
                     + sizeof_TPM_DATA(tpmData) + sizeof_MTM_DATA(mtmData);
#else
                     + sizeof_TPM_DATA(tpmData);
#endif
  debug("size of permanent data: %d", buf_length);
  buf = ptr = tpm_malloc(buf_length);
  if (buf == NULL
      || tpm_marshal_TPM_VERSION(&ptr, &len, &tpmData.permanent.data.version)
#ifdef MTM_EMULATOR
      || tpm_marshal_TPM_DATA(&ptr, &len, &tpmData)
      || tpm_marshal_MTM_DATA(&ptr, &len, &mtmData)) {
#else
      || tpm_marshal_TPM_DATA(&ptr, &len, &tpmData)) {
#endif
    tpm_free(buf);
    return -1;
  }
  if (len != 0) debug("warning: buffer was too large, %d bytes left", len);
  if (tpm_write_to_storage(buf, buf_length - len)) {
    tpm_free(buf);
    return -1; 
  }
  tpm_free(buf);
  return 0;
}

int tpm_restore_permanent_data(void)
{
  uint8_t *buf, *ptr;
  size_t buf_length;
  uint32_t len;
  TPM_VERSION ver;

  /* read data */
  if (tpm_read_from_storage(&buf, &buf_length)) return -1;
  ptr = buf;
  len = buf_length;
  /* unmarshal data */
  if (tpm_unmarshal_TPM_VERSION(&ptr, &len, &ver)
      || memcmp(&ver, &tpm_version, sizeof(TPM_VERSION))
      || tpm_unmarshal_TPM_DATA(&ptr, &len, &tpmData)
#ifdef MTM_EMULATOR
      || tpm_unmarshal_MTM_DATA(&ptr, &len, &mtmData)
#endif
      || len > 0) {
    tpm_free(buf);
    return -1;
  }
  tpm_free(buf);
  tpmData.permanent.flags.dataRestored = TRUE;
  return 0;
}

int tpm_erase_permanent_data(void)
{
  uint8_t d[1];
  int res = tpm_write_to_storage(d, 0);
  return res;
}

