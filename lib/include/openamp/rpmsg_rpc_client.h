/*
 * Copyright (c) 2014, Mentor Graphics Corporation
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef RPMSG_RPC_CLIENT_H
#define RPMSG_RPC_CLIENT_H

#include <metal/mutex.h>
#include <openamp/open_amp.h>
#include <openamp/rpmsg_retarget.h>
#include <stdint.h>

#if defined __cplusplus
extern "C" {
#endif

#define SCAN_SYSCALL_ID  0x7UL

/**
 * rpmsg_set_default_rpc - set default RPMsg RPC data
 *
 * The default RPC data is used to redirect standard C file operations
 * to RPMsg channels.
 *
 * @rpc: pointer to remoteproc procedure call data struct
 */
void linux_rpmsg_set_default_rpc(struct rpmsg_rpc_data *rpc);

int rpmsg_open(const char *filename, int flags, int mode);

int rpmsg_read(int fd, char *buffer, int buflen);

int rpmsg_write(int fd, const char *ptr, int len);

int rpmsg_close(int fd);

int rpmsg_scanf(char *buffer, int buflen);

#if defined __cplusplus
}
#endif

#endif /* RPMSG_RPC_CLIENT_H */
