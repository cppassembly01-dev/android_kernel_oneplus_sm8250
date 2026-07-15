// SPDX-License-Identifier: GPL-2.0
/*
 * pidfd_getfd(2) - Duplicate a file descriptor from another process.
 *
 * Backported from Linux 5.6 for LXC 7.0 container support.
 *
 * Copyright (C) 2020 Sargun Dhillon <sargun@sargun.me>
 */

#include <linux/compat.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/fs.h>
#include <linux/pid.h>
#include <linux/proc_fs.h>
#include <linux/ptrace.h>
#include <linux/sched.h>
#include <linux/syscalls.h>

/**
 * __pidfd_fget - get a file from another process by pidfd
 * @task:	the task to get the file from
 * @fd:		the file descriptor number to get
 *
 * This is a helper for pidfd_getfd that looks up and returns a file
 * from another task's file descriptor table. It performs ptrace
 * permission checks.
 */
static struct file *__pidfd_fget(struct task_struct *task, int fd)
{
	struct files_struct *files;
	struct file *file;

	files = get_files_struct(task);
	if (!files)
		return ERR_PTR(-EPERM);

	rcu_read_lock();
	file = fcheck_files(files, fd);
	if (file) {
		/* Prevent the file from being closed while we use it */
		if (!get_file_rcu(file))
			file = ERR_PTR(-EBADF);
	} else {
		file = ERR_PTR(-EBADF);
	}
	rcu_read_unlock();

	put_files_struct(files);
	return file;
}

/**
 * pidfd_getfd - get a file descriptor from another process
 * @pidfd:	the pidfd of the target process
 * @fd:		the file descriptor number to get
 * @flags:	reserved for future use (must be 0)
 *
 * Duplicate a file descriptor from a target process, using the
 * process's pidfd as a stable process handle. This requires
 * PTRACE_MODE_ATTACH_REALCREDS permissions.
 */
SYSCALL_DEFINE3(pidfd_getfd, int, pidfd, int, fd, unsigned int, flags)
{
	struct fd f;
	struct pid *pid;
	struct file *file;
	struct task_struct *task;
	int ret, newfd;

	/* flags is currently unused */
	if (flags)
		return -EINVAL;

	f = fdget(pidfd);
	if (!f.file)
		return -EBADF;

	pid = tgid_pidfd_to_pid(f.file);
	if (IS_ERR(pid)) {
		ret = PTR_ERR(pid);
		goto out_fdput;
	}

	task = get_pid_task(pid, PIDTYPE_PID);
	if (!task) {
		ret = -ESRCH;
		goto out_fdput;
	}

	/* Check ptrace permissions */
	if (!ptrace_may_access(task, PTRACE_MODE_ATTACH_REALCREDS)) {
		ret = -EPERM;
		goto out_put_task;
	}

	file = __pidfd_fget(task, fd);
	if (IS_ERR(file)) {
		ret = PTR_ERR(file);
		goto out_put_task;
	}

	/* Install the file in the current process */
	newfd = get_unused_fd_flags(O_CLOEXEC);
	if (newfd < 0) {
		ret = newfd;
		goto out_fput;
	}

	fd_install(newfd, file);
	ret = newfd;
	goto out_put_task;

out_fput:
	fput(file);
out_put_task:
	put_task_struct(task);
out_fdput:
	fdput(f);
	return ret;
}
