// SPDX-License-Identifier: GPL-2.0-or-later
/* Filesystem context-based mount syscalls.
 *
 * Copyright (C) 2018 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * Backported to 4.19.325-cip133.
 */

#include <linux/fs_context.h>
#include <linux/fs.h>
#include <linux/mount.h>
#include <linux/file.h>
#include <linux/anon_inodes.h>
#include <linux/namei.h>
#include <linux/security.h>
#include <linux/syscalls.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <uapi/linux/mount.h>
#include "mount.h"

/*
 * Allow the user to read back any error, warning or informational messages.
 */
static ssize_t fscontext_read(struct file *file,
			      char __user *_buf, size_t len, loff_t *pos)
{
	return 0;
}

static int fscontext_release(struct inode *inode, struct file *file)
{
	struct fs_context *fc = file->private_data;

	if (fc)
		put_fs_context(fc);
	return 0;
}

const struct file_operations fscontext_fops = {
	.read		= fscontext_read,
	.release	= fscontext_release,
	.llseek		= noop_llseek,
};

static int detached_mnt_release(struct inode *inode, struct file *file)
{
	struct vfsmount *mnt = file->private_data;

	if (mnt)
		mntput(mnt);
	return 0;
}

const struct file_operations detached_mnt_fops = {
	.release	= detached_mnt_release,
	.llseek		= noop_llseek,
};

/*
 * Retrieve the detached vfsmount from a mount fd.  Returns NULL if the
 * file is not a detached mount fd.  The caller must call mntput() on the
 * returned mount when done.
 */
struct vfsmount *lookup_detached_mnt(struct file *file)
{
	struct vfsmount *mnt;

	/* Legacy anon_inode path (from open_tree with OPEN_TREE_CLONE) */
	if (file->f_op == &detached_mnt_fops) {
		mnt = file->private_data;
		if (mnt)
			mntget(mnt);
		return mnt;
	}

	/*
	 * O_PATH fd from fsmount(): the mount root is stored in
	 * file->f_path. Check it's a detached mount (not yet in a
	 * mount namespace) by verifying it's the mount root.
	 */
	if (file->f_flags & O_PATH) {
		mnt = file->f_path.mnt;
		if (mnt && file->f_path.dentry == mnt->mnt_root) {
			mntget(mnt);
			return mnt;
		}
	}

	return NULL;
}
EXPORT_SYMBOL(lookup_detached_mnt);

/*
 * Open a filesystem by name so that it can be configured for mounting.
 *
 * We are allowed to specify a container in which the filesystem will be
 * opened, thereby indicating which namespaces will be used (notably, which
 * network namespace will be used for network filesystems).
 */
SYSCALL_DEFINE2(fsopen, const char __user *, fs_name, unsigned int, flags)
{
	struct file_system_type *fs_type;
	struct fs_context *fc;
	const char *name;
	int fd;

	if (!ns_capable(current->nsproxy->mnt_ns->user_ns, CAP_SYS_ADMIN))
		return -EPERM;

	if (flags & ~FSOPEN_CLOEXEC)
		return -EINVAL;

	name = strndup_user(fs_name, PAGE_SIZE);
	if (IS_ERR(name))
		return PTR_ERR(name);

	fs_type = get_fs_type(name);
	kfree(name);
	if (!fs_type)
		return -ENODEV;

	fc = fs_context_for_mount(fs_type, 0);
	put_filesystem(fs_type);
	if (IS_ERR(fc))
		return PTR_ERR(fc);

	fc->oldapi = false;

	fd = anon_inode_getfd("[fscontext]", &fscontext_fops, fc,
			      flags & FSOPEN_CLOEXEC ? O_CLOEXEC : 0);
	if (fd < 0)
		put_fs_context(fc);

	return fd;
}

/*
 * Check that the fd refers to an fs_context file and retrieve the fs_context.
 */
static struct fs_context *fscontext_from_fd(unsigned int fd, struct fd *f)
{
	*f = fdget(fd);
	if (!f->file)
		return ERR_PTR(-EBADF);

	if (f->file->f_op != &fscontext_fops) {
		fdput(*f);
		return ERR_PTR(-EINVAL);
	}

	return f->file->private_data;
}

/*
 * Configure a filesystem context according to a command.
 */
SYSCALL_DEFINE5(fsconfig,
		int, fd,
		unsigned int, cmd,
		const char __user *, _key,
		const void __user *, _value,
		int, aux)
{
	struct fs_context *fc;
	struct fd f;
	struct fs_parameter param;
	int ret;

	memset(&param, 0, sizeof(param));

	fc = fscontext_from_fd(fd, &f);
	if (IS_ERR(fc))
		return PTR_ERR(fc);

	/* Copy the key from userspace if provided */
	if (_key) {
		param.key = strndup_user(_key, 256);
		if (IS_ERR(param.key)) {
			ret = PTR_ERR(param.key);
			param.key = NULL;
			goto out_f;
		}
	} else {
		if (cmd != FSCONFIG_CMD_CREATE &&
		    cmd != FSCONFIG_CMD_RECONFIGURE) {
			ret = -EINVAL;
			goto out_f;
		}
		param.key = NULL;
	}

	/* Now handle each command type */
	switch (cmd) {
	case FSCONFIG_SET_FLAG:
		if (_value || aux) {
			ret = -EINVAL;
			break;
		}
		param.type = fs_value_is_flag;
		param.string = NULL;
		param.size = 0;
		ret = vfs_parse_fs_param(fc, &param);
		break;

	case FSCONFIG_SET_STRING:
		if (!_value) {
			ret = -EINVAL;
			break;
		}
		param.type = fs_value_is_string;
		param.string = strndup_user(_value, 256);
		if (IS_ERR(param.string)) {
			ret = PTR_ERR(param.string);
			param.string = NULL;
			break;
		}
		param.size = strlen(param.string);
		ret = vfs_parse_fs_param(fc, &param);
		kfree(param.string);
		break;

	case FSCONFIG_SET_BINARY:
		if (!_value || aux <= 0 || aux > 1024 * 1024) {
			ret = -EINVAL;
			break;
		}
		param.type = fs_value_is_blob;
		param.size = aux;
		param.blob = kmalloc(aux, GFP_KERNEL);
		if (!param.blob) {
			ret = -ENOMEM;
			break;
		}
		if (copy_from_user(param.blob, _value, aux)) {
			kfree(param.blob);
			ret = -EFAULT;
			break;
		}
		ret = vfs_parse_fs_param(fc, &param);
		/*
		 * Note: on success, the fs may have taken ownership of
		 * param.blob. On error, we free it.
		 */
		if (ret)
			kfree(param.blob);
		break;

	case FSCONFIG_SET_PATH:
	case FSCONFIG_SET_PATH_EMPTY: {
		struct filename *fname;
		unsigned int lookup_flags;

		if (!_value) {
			ret = -EINVAL;
			break;
		}

		lookup_flags = LOOKUP_FOLLOW;
		if (cmd == FSCONFIG_SET_PATH_EMPTY)
			lookup_flags = LOOKUP_EMPTY;

		fname = getname_flags(_value, lookup_flags, NULL);
		if (IS_ERR(fname)) {
			ret = PTR_ERR(fname);
			break;
		}

		param.type = (cmd == FSCONFIG_SET_PATH_EMPTY)
			? fs_value_is_filename_empty
			: fs_value_is_filename;
		param.name = fname;
		param.dirfd = aux;
		param.size = 0;
		ret = vfs_parse_fs_param(fc, &param);
		putname(fname);
		break;
	}

	case FSCONFIG_SET_FD: {
		struct file *val_file;

		if (_value) {
			ret = -EINVAL;
			break;
		}

		val_file = fget(aux);
		if (!val_file) {
			ret = -EBADF;
			break;
		}

		param.type = fs_value_is_file;
		param.file = val_file;
		param.size = 0;
		ret = vfs_parse_fs_param(fc, &param);
		fput(val_file);
		break;
	}

	case FSCONFIG_CMD_CREATE:
		if (_key || _value || aux) {
			ret = -EINVAL;
			break;
		}
		ret = vfs_get_tree(fc);
		if (ret == 0)
			up_write(&fc->root->d_sb->s_umount);
		break;

	case FSCONFIG_CMD_RECONFIGURE:
		if (_key || _value || aux) {
			ret = -EINVAL;
			break;
		}
		if (!fc->root || !fc->ops || !fc->ops->reconfigure) {
			ret = -EOPNOTSUPP;
			break;
		}
		down_write(&fc->root->d_sb->s_umount);
		ret = fc->ops->reconfigure(fc);
		up_write(&fc->root->d_sb->s_umount);
		break;

	default:
		ret = -EOPNOTSUPP;
		break;
	}

out_f:
	kfree(param.key);
	fdput(f);
	return ret;
}

/*
 * Convert MS_* flags to MNT_* flags for the detached mount.
 */
static unsigned int fsopen_ms_to_mnt(unsigned int ms_flags)
{
	unsigned int mnt_flags = 0;

	if (ms_flags & MS_RDONLY)
		mnt_flags |= MNT_READONLY;
	if (ms_flags & MS_NOSUID)
		mnt_flags |= MNT_NOSUID;
	if (ms_flags & MS_NODEV)
		mnt_flags |= MNT_NODEV;
	if (ms_flags & MS_NOEXEC)
		mnt_flags |= MNT_NOEXEC;
	if (ms_flags & MS_NOATIME)
		mnt_flags |= MNT_NOATIME;
	if (ms_flags & MS_NODIRATIME)
		mnt_flags |= MNT_NODIRATIME;
	if (ms_flags & MS_RELATIME)
		mnt_flags |= MNT_RELATIME;

	return mnt_flags;
}

/* Permitted ms_flags for fsmount() */
#define FSMOUNT_VALID_MS_FLAGS \
	(MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC | \
	 MS_NOATIME | MS_NODIRATIME | MS_RELATIME | MS_STRICTATIME)

/*
 * Create a new mount using a superblock configuration context that has been
 * fully configured (FSCONFIG_CMD_CREATE has been called).
 */
SYSCALL_DEFINE3(fsmount, int, fs_fd, unsigned int, flags, unsigned int, ms_flags)
{
	struct fs_context *fc;
	struct vfsmount *mnt;
	struct fd f;
	struct file *file;
	unsigned int mnt_flags;
	int fd, o_flags;

	if (!ns_capable(current->nsproxy->mnt_ns->user_ns, CAP_SYS_ADMIN))
		return -EPERM;

	if (flags & ~FSMOUNT_CLOEXEC)
		return -EINVAL;

	if (ms_flags & ~FSMOUNT_VALID_MS_FLAGS)
		return -EINVAL;

	fc = fscontext_from_fd(fs_fd, &f);
	if (IS_ERR(fc)) {
		return PTR_ERR(fc);
	}

	/* vfs_get_tree() / FSCONFIG_CMD_CREATE must have been called */
	if (!fc->root) {
		fdput(f);
		return -EINVAL;
	}

	mnt = vfs_create_mount(fc);
	if (IS_ERR(mnt)) {
		fdput(f);
		return PTR_ERR(mnt);
	}

	/* Apply mount flags */
	mnt_flags = fsopen_ms_to_mnt(ms_flags);

	/*
	 * MS_STRICTATIME clears the atime-related flags, matching the
	 * semantics of mount(2).
	 */
	if (ms_flags & MS_STRICTATIME)
		mnt_flags &= ~(MNT_RELATIME | MNT_NOATIME);

	mnt->mnt_flags |= mnt_flags;

	/*
	 * Create an O_PATH fd referencing the mount root. This allows
	 * openat2(fd, "relative/path") to work, unlike anon_inode fds.
	 */
	o_flags = O_PATH;
	if (flags & FSMOUNT_CLOEXEC)
		o_flags |= O_CLOEXEC;

	fd = get_unused_fd_flags(o_flags);
	if (fd < 0) {
		mntput(mnt);
		fdput(f);
		return fd;
	}

	{
		struct path path = { .mnt = mnt, .dentry = mnt->mnt_root };
		file = dentry_open(&path, o_flags, current_cred());
	}
	if (IS_ERR(file)) {
		put_unused_fd(fd);
		mntput(mnt);
		fdput(f);
		return PTR_ERR(file);
	}

	fd_install(fd, file);
	fdput(f);
	return fd;
}

/*
 * Pick an existing mountpoint to reconfigure.
 */
SYSCALL_DEFINE3(fspick, int, dfd, const char __user *, path, unsigned int, flags)
{
	struct fs_context *fc;
	struct path target;
	unsigned int lookup_flags;
	int fd, ret;

	if (!ns_capable(current->nsproxy->mnt_ns->user_ns, CAP_SYS_ADMIN))
		return -EPERM;

	if (flags & ~(FSPICK_CLOEXEC |
		      FSPICK_SYMLINK_NOFOLLOW |
		      FSPICK_NO_AUTOMOUNT |
		      FSPICK_EMPTY_PATH))
		return -EINVAL;

	lookup_flags = LOOKUP_FOLLOW | LOOKUP_AUTOMOUNT;
	if (flags & FSPICK_SYMLINK_NOFOLLOW)
		lookup_flags &= ~LOOKUP_FOLLOW;
	if (flags & FSPICK_NO_AUTOMOUNT)
		lookup_flags &= ~LOOKUP_AUTOMOUNT;
	if (flags & FSPICK_EMPTY_PATH)
		lookup_flags |= LOOKUP_EMPTY;

	ret = user_path_at(dfd, path, lookup_flags, &target);
	if (ret < 0)
		return ret;

	fc = fs_context_for_reconfigure(target.dentry, 0, 0);
	path_put(&target);
	if (IS_ERR(fc))
		return PTR_ERR(fc);

	fc->oldapi = false;

	fd = anon_inode_getfd("[fscontext]", &fscontext_fops, fc,
			      flags & FSPICK_CLOEXEC ? O_CLOEXEC : 0);
	if (fd < 0)
		put_fs_context(fc);

	return fd;
}
