// SPDX-License-Identifier: GPL-2.0-only
/*
 * Landlock stub syscalls for LXC 7 compatibility.
 *
 * These are no-op stubs that make LXC 7's monitor protection succeed
 * without actually enforcing Landlock restrictions. Real Landlock
 * requires Linux 5.13+; this just prevents ENOSYS from killing the
 * LXC mainloop thread on 4.19 kernels.
 */

#include <linux/anon_inodes.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/syscalls.h>
#include <linux/uaccess.h>
#include <uapi/linux/landlock.h>

#define LANDLOCK_ABI_VERSION	4

static int landlock_ruleset_release(struct inode *inode, struct file *file)
{
	return 0;
}

static const struct file_operations landlock_ruleset_fops = {
	.release = landlock_ruleset_release,
};

/**
 * sys_landlock_create_ruleset - Create a Landlock ruleset (stub)
 *
 * When called with LANDLOCK_CREATE_RULESET_VERSION, returns the ABI version.
 * Otherwise creates a dummy ruleset fd.
 */
SYSCALL_DEFINE3(landlock_create_ruleset,
		const struct landlock_ruleset_attr __user *, attr,
		size_t, size, __u32, flags)
{
	/* Version query */
	if (flags == LANDLOCK_CREATE_RULESET_VERSION) {
		if (attr || size)
			return -EINVAL;
		return LANDLOCK_ABI_VERSION;
	}

	if (flags)
		return -EINVAL;

	if (!attr || size < sizeof(struct landlock_ruleset_attr))
		return -EINVAL;

	/* Return a dummy ruleset fd */
	return anon_inode_getfd("[landlock-ruleset]", &landlock_ruleset_fops,
				NULL, O_RDWR | O_CLOEXEC);
}

/**
 * sys_landlock_add_rule - Add a rule to a ruleset (stub)
 *
 * Accepts and silently ignores the rule.
 */
SYSCALL_DEFINE4(landlock_add_rule, int, ruleset_fd,
		enum landlock_rule_type, rule_type,
		const void __user *, rule_attr, __u32, flags)
{
	struct fd f;

	if (flags)
		return -EINVAL;

	/* Verify the fd is a valid landlock ruleset */
	f = fdget(ruleset_fd);
	if (!f.file)
		return -EBADF;
	if (f.file->f_op != &landlock_ruleset_fops) {
		fdput(f);
		return -EBADF;
	}
	fdput(f);

	/* Silently accept the rule */
	return 0;
}

/**
 * sys_landlock_restrict_self - Enforce a ruleset on the calling thread (stub)
 *
 * Silently succeeds without enforcing any restrictions.
 */
SYSCALL_DEFINE2(landlock_restrict_self, int, ruleset_fd, __u32, flags)
{
	struct fd f;

	if (flags)
		return -EINVAL;

	f = fdget(ruleset_fd);
	if (!f.file)
		return -EBADF;
	if (f.file->f_op != &landlock_ruleset_fops) {
		fdput(f);
		return -EBADF;
	}
	fdput(f);

	/* No-op: don't actually restrict anything */
	return 0;
}
