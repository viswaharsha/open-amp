/*
 * Copyright (c) 2014, Mentor Graphics Corporation
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <errno.h>
#include <metal/mutex.h>
#include <metal/spinlock.h>
#include <metal/utilities.h>
#include <openamp/open_amp.h>
#include <openamp/rpmsg_rpc_client.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>

/*************************************************************************
 *	Description
 *	This files contains rpmsg based redefinitions for C RTL system calls
 *	such as _open, _read, _write, _close.
 *************************************************************************/

static struct rpmsg_rpc_data *rpmsg_default_rpc;

void linux_rpmsg_set_default_rpc(struct rpmsg_rpc_data *rpc)
{
	if (!rpc)
		return;
	rpmsg_default_rpc = rpc;
}

/*************************************************************************
 *
 *   FUNCTION
 *
 *       _open
 *
 *   DESCRIPTION
 *
 *       Open a file.  Minimal implementation
 *
 *************************************************************************/
#define MAX_BUF_LEN 496UL

int rpmsg_open(const char *filename, int flags, int mode)
{
	struct rpmsg_rpc_data *rpc = rpmsg_default_rpc;
	struct rpmsg_rpc_syscall *syscall;
	struct rpmsg_rpc_syscall resp;
	int filename_len = strlen(filename) + 1;
	unsigned int payload_size = sizeof(*syscall) + filename_len;
	unsigned char tmpbuf[MAX_BUF_LEN];
	int ret;

	if (!filename || payload_size > (int)MAX_BUF_LEN) {
		return -EINVAL;
	}

	if (!rpc)
		return -EINVAL;

	/* Construct rpc payload */
	syscall = (struct rpmsg_rpc_syscall *)tmpbuf;
	syscall->id = OPEN_SYSCALL_ID;
	syscall->args.int_field1 = flags;
	syscall->args.int_field2 = mode;
	syscall->args.data_len = filename_len;
	memcpy(tmpbuf + sizeof(*syscall), filename, filename_len);

	resp.id = 0;
	ret = rpmsg_rpc_send(rpc, tmpbuf, payload_size,
			     (void *)&resp, sizeof(resp));
	if (ret >= 0) {
		/* Obtain return args and return to caller */
		if (resp.id == OPEN_SYSCALL_ID)
			ret = resp.args.int_field1;
		else
			ret = -EINVAL;
	}

	return ret;
}

/*************************************************************************
 *
 *   FUNCTION
 *
 *       _read
 *
 *   DESCRIPTION
 *
 *       Low level function to redirect IO to serial.
 *
 *************************************************************************/
int rpmsg_read(int fd, char *buffer, int buflen)
{
	struct rpmsg_rpc_syscall syscall;
	struct rpmsg_rpc_syscall *resp;
	struct rpmsg_rpc_data *rpc = rpmsg_default_rpc;
	int payload_size = sizeof(syscall);
	unsigned char tmpbuf[MAX_BUF_LEN];
	int ret;

	if (!rpc || !buffer || buflen == 0)
		return -EINVAL;

	/* Construct rpc payload */
	syscall.id = READ_SYSCALL_ID;
	syscall.args.int_field1 = fd;
	syscall.args.int_field2 = buflen;
	syscall.args.data_len = 0;	/*not used */

	resp = (struct rpmsg_rpc_syscall *)tmpbuf;
	resp->id = 0;
	ret = rpmsg_rpc_send(rpc, (void *)&syscall, payload_size,
			     tmpbuf, sizeof(tmpbuf));

	/* Obtain return args and return to caller */
	if (ret >= 0) {
		if (resp->id == READ_SYSCALL_ID) {
			if (resp->args.int_field1 > 0) {
				int tmplen = resp->args.data_len;
				unsigned char *tmpptr = tmpbuf;

				tmpptr += sizeof(*resp);
				if (tmplen > buflen)
					tmplen = buflen;
				memcpy(buffer, tmpptr, tmplen);
			}
			ret = resp->args.int_field1;
		} else {
			ret = -EINVAL;
		}
	}

	return ret;
}

/*************************************************************************
 *
 *   FUNCTION
 *
 *       _write
 *
 *   DESCRIPTION
 *
 *       Low level function to redirect IO to serial.
 *
 *************************************************************************/
int rpmsg_write(int fd, const char *ptr, int len)
{
	int ret;
	struct rpmsg_rpc_syscall *syscall;
	struct rpmsg_rpc_syscall resp;
	int payload_size = sizeof(*syscall) + len;
	struct rpmsg_rpc_data *rpc = rpmsg_default_rpc;
	unsigned char tmpbuf[MAX_BUF_LEN];
	unsigned char *tmpptr;
	int null_term = 0;

	if (!rpc)
		return -EINVAL;
	if (fd == 1)
		null_term = 1;
	
	syscall = (struct rpmsg_rpc_syscall *)tmpbuf;
	syscall->id = WRITE_SYSCALL_ID;
	syscall->args.int_field1 = fd;
	syscall->args.int_field2 = len;
	syscall->args.data_len = len + null_term;
	tmpptr = tmpbuf + sizeof(*syscall);
	memcpy(tmpptr, ptr, len);
	if (null_term == 1) {
		*(char *)(tmpptr + len + null_term) = 0;
		payload_size += 1;
	}
	resp.id = 0;
	ret = rpmsg_rpc_send(rpc, tmpbuf, payload_size,
			     (void *)&resp, sizeof(resp));

	if (ret >= 0) {
		if (resp.id == WRITE_SYSCALL_ID)
			ret = resp.args.int_field1;
		else
			ret = -EINVAL;
	}

	return ret;

}

/*************************************************************************
 *
 *   FUNCTION
 *
 *       _close
 *
 *   DESCRIPTION
 *
 *       Close a file.  Minimal implementation
 *
 *************************************************************************/
int rpmsg_close(int fd)
{
	int ret;
	struct rpmsg_rpc_syscall syscall;
	struct rpmsg_rpc_syscall resp;
	int payload_size = sizeof(syscall);
	struct rpmsg_rpc_data *rpc = rpmsg_default_rpc;

	if (!rpc)
		return -EINVAL;
	syscall.id = CLOSE_SYSCALL_ID;
	syscall.args.int_field1 = fd;
	syscall.args.int_field2 = 0;	/*not used */
	syscall.args.data_len = 0;	/*not used */

	resp.id = 0;
	ret = rpmsg_rpc_send(rpc, (void *)&syscall, payload_size,
			     (void *)&resp, sizeof(resp));

	if (ret >= 0) {
		if (resp.id == CLOSE_SYSCALL_ID)
			ret = resp.args.int_field1;
		else
			ret = -EINVAL;
	}

	return ret;
}

/*************************************************************************
 *
 *   FUNCTION
 *
 *       rpmsg_scanf
 *
 *   DESCRIPTION
 *
 *       Low level function to redirect IO to serial.
 *
 *************************************************************************/
int rpmsg_scanf(char *buffer, int buflen)
{
	struct rpmsg_rpc_syscall syscall;
	struct rpmsg_rpc_syscall *resp;
	struct rpmsg_rpc_data *rpc = rpmsg_default_rpc;
	int payload_size = sizeof(syscall);
	unsigned char tmpbuf[MAX_BUF_LEN];
	int ret;

	if (!rpc || !buffer || buflen == 0)
		return -EINVAL;

	/* Construct rpc payload */
	syscall.id = SCAN_SYSCALL_ID;
	syscall.args.int_field1 = 0;	/*not used */
	syscall.args.int_field2 = buflen;
	syscall.args.data_len = 0;	/*not used */

	resp = (struct rpmsg_rpc_syscall *)tmpbuf;
	resp->id = 0;
	ret = rpmsg_rpc_send(rpc, (void *)&syscall, payload_size,
			     tmpbuf, sizeof(tmpbuf));

	/* Obtain return args and return to caller */
	if (ret >= 0) {
		if (resp->id == SCAN_SYSCALL_ID) {
			if (resp->args.int_field1 > 0) {
				int tmplen = resp->args.data_len;
				unsigned char *tmpptr = tmpbuf;

				tmpptr += sizeof(*resp);
				if (tmplen > buflen)
					tmplen = buflen;
				memcpy(buffer, tmpptr, tmplen);
			}
			ret = resp->args.int_field1;
		} else {
			ret = -EINVAL;
		}
	}

	return ret;
}
