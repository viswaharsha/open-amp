/*
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

/**
 * rpmsg_open - perform file open operation
 *
 * rpmsg_open is used to perform C file open operation
 * through RPMsg channels.
 *
 * @filename: pointer to file name buffer
 * @flags: file status flags
 * @mode: access mode
 */
int rpmsg_open(const char *filename, int flags, int mode);

/**
 * rpmsg_read - perform file read operation
 *
 * rpmsg_read is used to perform C file read operation
 * through RPMsg channels.
 *
 * @fd: file descriptor
 * @buffer: buffer to store read data
 * @buflen: size of the read buffer
 */
int rpmsg_read(int fd, char *buffer, int buflen);

/**
 * rpmsg_write - perform file write operation
 *
 * rpmsg_write is used to perform C file write operation
 * through RPMsg channels.
 *
 * @fd: file descriptor
 * @ptr: pointer to string buffer
 * @len: size of write buffer
 */
int rpmsg_write(int fd, const char *ptr, int len);

/**
 * rpmsg_close - perform file close operation
 *
 * rpmsg_close is used to perform C file close operation
 * through RPMsg channels.
 *
 * @fd: file descriptor
 */
int rpmsg_close(int fd);

/**
 * rpmsg_scanf - perform input operation
 *
 * rpmsg_scanf is used to perform input operation through
 * RPMsg channels.
 *
 * @buffer: buffer to store data
 * @buflen: size of buffer
 */
int rpmsg_scanf(char *buffer, int buflen);

#if defined __cplusplus
}
#endif

#endif /* RPMSG_RPC_CLIENT_H */
