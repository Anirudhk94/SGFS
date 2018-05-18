/*
 * Copyright (c) 1998-2015 Erez Zadok
 * Copyright (c) 2009	   Shrikar Archak
 * Copyright (c) 2003-2015 Stony Brook University
 * Copyright (c) 2003-2015 The Research Foundation of SUNY
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include "sgfs.h"

/* Custom filldir function */
static int sgfs_filldir(struct dir_context *ctx, const char *lower_name,
		 int lower_namelen, loff_t offset, u64 ino, unsigned int d_type);

static ssize_t sgfs_read(struct file *file, char __user *buf,
			   size_t count, loff_t *ppos)
{
	int err;
	struct file *lower_file;
	struct dentry *dentry = file->f_path.dentry;

	lower_file = sgfs_lower_file(file);
	err = vfs_read(lower_file, buf, count, ppos);
	/* update our inode atime upon a successful lower read */
	if (err >= 0)
		fsstack_copy_attr_atime(d_inode(dentry),
					file_inode(lower_file));

	return err;
}

static ssize_t sgfs_write(struct file *file, const char __user *buf,
			    size_t count, loff_t *ppos)
{
	int err;

	struct file *lower_file;
	struct dentry *dentry = file->f_path.dentry;

	lower_file = sgfs_lower_file(file);
	err = vfs_write(lower_file, buf, count, ppos);
	/* update our inode times+sizes upon a successful lower write */
	if (err >= 0) {
		fsstack_copy_inode_size(d_inode(dentry),
					file_inode(lower_file));
		fsstack_copy_attr_times(d_inode(dentry),
					file_inode(lower_file));
	}

	return err;
}

struct sgfs_getdents_callback {
	struct dir_context ctx;
	struct dir_context *caller;
	int filldir_called;
	int entries_written;
};

/* Inspired by ecryptfs filldir */
static int
sgfs_filldir(struct dir_context *ctx, const char *lower_name,
		 int lower_namelen, loff_t offset, u64 ino, unsigned int d_type)
{
	kuid_t uid_struct = current_uid();
	uid_t process_uid = uid_struct.val;
	char *uid;
	char *name = (char *)kmalloc((strlen(lower_name)+1)*sizeof(char), GFP_KERNEL);
	char *toFree = name;
	char *file_uid = NULL;
	struct sgfs_getdents_callback *buf = container_of(ctx, struct sgfs_getdents_callback, ctx);
	int rc;
	int len;

	/* Extract file UID for deleted file and check against current process UID. If matched, then display.
		If file is not a deleted file, then display nevertheless */
	strcpy(name, lower_name);
	file_uid = strsep(&name, ":");

	if(process_uid != 0 && strcmp(file_uid, lower_name) != 0){
		
		len = snprintf(NULL, 0, "%d", process_uid);
		uid = (char *)kmalloc(len+1, GFP_KERNEL);
		snprintf(uid, len+1, "%d", process_uid);
		
		if (strcmp(uid, file_uid) != 0){
			rc = 0;
			goto out;
		}
	}

	buf->filldir_called++;
	buf->caller->pos = buf->ctx.pos;
	rc = !dir_emit(buf->caller, lower_name, lower_namelen, ino, d_type);
	if (!rc)
		buf->entries_written++;
out:
	kfree(toFree);
	return rc;
}


static int sgfs_readdir(struct file *file, struct dir_context *ctx)
{
	int err;
	struct file *lower_file = NULL;
	struct dentry *dentry = file->f_path.dentry;
	struct dentry *lower_dentry;
	struct sgfs_getdents_callback buf = {
		.ctx.actor = sgfs_filldir,
		.caller = ctx,
	};

	lower_file = sgfs_lower_file(file);
	lower_dentry = lower_file->f_path.dentry;

	/* Check if doing ls on .sg folder */
	if (strcmp(lower_dentry->d_iname, ".sg") == 0){
		err = iterate_dir(lower_file, &buf.ctx);
		ctx->pos = buf.ctx.pos;
	}
	else {
		err = iterate_dir(lower_file, ctx);
	}

	file->f_pos = lower_file->f_pos;
	if (err >= 0)		/* copy the atime */
		fsstack_copy_attr_atime(d_inode(dentry),
					file_inode(lower_file));
	return err;
}

static long sgfs_unlocked_ioctl(struct file *file, unsigned int cmd,
				  unsigned long arg)
{
	int dec = 0;
	long err = -ENOTTY;
	struct file *lower_file, *key_file = NULL, *new_file = NULL;
	struct path *upper_path = &file->f_path;
	struct path *lower_path;
	struct dentry *upper_root = upper_path->dentry->d_inode->i_sb->s_root;
	struct path upper_root_path;
	struct dentry *lower_sgfs_root;
	struct inode *upper_dir = NULL, *lower_dir = NULL;
	struct dentry *upper_dentry = NULL, *lower_dentry = NULL, *lower_dir_dentry = NULL;
	char root_path_buffer[80];
	char *ext, *root_pathname, *key_buffer = NULL, *file_name = NULL, *file_buffer = NULL, *temp_buffer = NULL;
	char key_path[256];
	mm_segment_t oldfs;
	
	lower_file = sgfs_lower_file(file);
	lower_path = &lower_file->f_path;
	
	/* XXX: use vfs_ioctl if/when VFS exports it */
	if (!lower_file || !lower_file->f_op)
		goto out;
	if (lower_file->f_op->unlocked_ioctl)
		err = lower_file->f_op->unlocked_ioctl(lower_file, cmd, arg);

	/* some ioctls can change inode attributes (EXT2_IOC_SETFLAGS) */
	if (!err)
		fsstack_copy_attr_all(file_inode(file),
				      file_inode(lower_file));

	/* Restore command section */
	if (cmd == RES){
		/* Get lower path of sgfs mount point */
		sgfs_get_lower_path(upper_root, &upper_root_path);
		lower_sgfs_root = upper_root_path.dentry;
		dget(lower_sgfs_root);

		root_pathname = dentry_path_raw(lower_sgfs_root, root_path_buffer, 80);
		if (!root_pathname || IS_ERR(root_pathname)){
			err = (int) PTR_ERR(root_pathname);
			goto out;
		}
	
		strcpy(key_path, root_pathname);
		strcat(key_path, "/.trash_encryptor");

		oldfs = get_fs();
		set_fs(KERNEL_DS);

		/*Buffer allocations for key data and input file name*/
		key_buffer = (char *) kmalloc(BUFFER_SIZE, GFP_KERNEL);
		if (key_buffer == NULL){
			err = -ENOMEM;
			goto out;
		}
		
		file_name = (char *) kmalloc(strlen(lower_path->dentry->d_iname), GFP_KERNEL);
		if (file_name == NULL){
			err = -ENOMEM;
			goto out;
		}

		strcpy(file_name, strrchr(lower_path->dentry->d_iname, ':')+1 );
		ext = strrchr(file_name, '.');
		
		if (ext && strcmp(ext, ".enc") == 0){
			dec = 1;	
			*ext = '\0';
		} else {
			dec = 0;
		}
			
		/* Open and read current encryption key */
		key_file = filp_open(key_path, O_RDONLY, 0);
		if (!key_file || IS_ERR(key_file)){
			printk("Unable to open key file\n");
			err = -EPERM;
			goto out;
		}

		key_file->f_pos = 0;
		err = vfs_read(key_file, key_buffer, ksize(key_buffer), &key_file->f_pos);
		if (err < 0){
			printk("Unable to read the encryption key\n");
			goto out;
		}
		filp_close(key_file, NULL);

		file_buffer = (char *) kmalloc(BUFFER_SIZE, GFP_KERNEL);
		if (file_buffer == NULL){
			err = -ENOMEM;
			goto out;	
		}

		/* Read the key with which the file was encryted */
		lower_file->f_pos = 0;
		if (dec){
			err = vfs_read(lower_file, file_buffer, ksize(file_buffer), &lower_file->f_pos);
			if (err < 0){
				printk("Unable to read from lower file\n");
				goto out;
			}		
			printk("Keys are %s, %s\n", key_buffer, file_buffer);
			/* Check if encryption and decryption key are the same */
			if (memcmp(key_buffer, file_buffer, BUFFER_SIZE) != 0){
				printk("Encryption and decryption keys differ\n");
				goto out;
			}

			temp_buffer = (char *) kmalloc(BUFFER_SIZE, GFP_KERNEL);
			if (temp_buffer == NULL){
				err = -ENOMEM;
				goto out;
			}
		}
		/* Create new file in the cwd */
		new_file = filp_open(file_name, O_WRONLY|O_CREAT|O_TRUNC, 0644);
		if (!new_file || IS_ERR(new_file)){
			err = (int)PTR_ERR(new_file);
			goto out;
		}
		new_file->f_pos = 0;

		/* Decrypt file data and write to the new file created in the cwd */
		while(vfs_read(lower_file, file_buffer, ksize(file_buffer), &lower_file->f_pos) > 0){
			if (dec){
				err = kencrypt(key_buffer, ksize(key_buffer), temp_buffer, file_buffer, ksize(file_buffer), 0);
				if (err <= 0)
					goto out;
				err = vfs_write(new_file, temp_buffer, ksize(temp_buffer), &new_file->f_pos);
				if (err < 0)
					goto out;
			} else {
				err = vfs_write(new_file, file_buffer, ksize(file_buffer), &new_file->f_pos);
				if (err < 0)
					goto out;
			}
				
		}

		/* Unlink the file present in the recycle bin */
		upper_dir = upper_path->dentry->d_parent->d_inode;
		lower_dir = lower_path->dentry->d_parent->d_inode;

		upper_dentry = upper_path->dentry;
		lower_dentry = lower_path->dentry;

		lower_dir_dentry = lock_parent(lower_dentry);
		
		err = vfs_unlink(lower_dir, lower_dentry, NULL);
	
		if (err)
			goto out;
		fsstack_copy_attr_times(upper_dir, lower_dir);
		fsstack_copy_inode_size(upper_dir, lower_dir);
		set_nlink(d_inode(upper_dentry), sgfs_lower_inode(d_inode(upper_dentry))->i_nlink);
		d_inode(upper_dentry)->i_ctime = upper_dir->i_ctime;
		d_drop(upper_dentry);
		
		unlock_dir(lower_dir_dentry);

		set_fs(oldfs);
	}
out:
	if (new_file)
		filp_close(new_file, NULL);
	if (temp_buffer)
		kfree(temp_buffer);
	if (file_buffer)
		kfree(file_buffer);
	if (lower_file)
		filp_close(lower_file, NULL);
	if (file_name)
		kfree(file_name);
	if (key_buffer)
		kfree(key_buffer);
	return err;
}

#ifdef CONFIG_COMPAT
static long sgfs_compat_ioctl(struct file *file, unsigned int cmd,
				unsigned long arg)
{
	long err = -ENOTTY;
	struct file *lower_file;

	lower_file = sgfs_lower_file(file);

	/* XXX: use vfs_ioctl if/when VFS exports it */
	if (!lower_file || !lower_file->f_op)
		goto out;
	if (lower_file->f_op->compat_ioctl)
		err = lower_file->f_op->compat_ioctl(lower_file, cmd, arg);

out:
	return err;
}
#endif

static int sgfs_mmap(struct file *file, struct vm_area_struct *vma)
{
	int err = 0;
	bool willwrite;
	struct file *lower_file;
	const struct vm_operations_struct *saved_vm_ops = NULL;

	/* this might be deferred to mmap's writepage */
	willwrite = ((vma->vm_flags | VM_SHARED | VM_WRITE) == vma->vm_flags);

	/*
	 * File systems which do not implement ->writepage may use
	 * generic_file_readonly_mmap as their ->mmap op.  If you call
	 * generic_file_readonly_mmap with VM_WRITE, you'd get an -EINVAL.
	 * But we cannot call the lower ->mmap op, so we can't tell that
	 * writeable mappings won't work.  Therefore, our only choice is to
	 * check if the lower file system supports the ->writepage, and if
	 * not, return EINVAL (the same error that
	 * generic_file_readonly_mmap returns in that case).
	 */
	lower_file = sgfs_lower_file(file);
	if (willwrite && !lower_file->f_mapping->a_ops->writepage) {
		err = -EINVAL;
		printk(KERN_ERR "sgfs: lower file system does not "
		       "support writeable mmap\n");
		goto out;
	}

	/*
	 * find and save lower vm_ops.
	 *
	 * XXX: the VFS should have a cleaner way of finding the lower vm_ops
	 */
	if (!SGFS_F(file)->lower_vm_ops) {
		err = lower_file->f_op->mmap(lower_file, vma);
		if (err) {
			printk(KERN_ERR "sgfs: lower mmap failed %d\n", err);
			goto out;
		}
		saved_vm_ops = vma->vm_ops; /* save: came from lower ->mmap */
	}

	/*
	 * Next 3 lines are all I need from generic_file_mmap.  I definitely
	 * don't want its test for ->readpage which returns -ENOEXEC.
	 */
	file_accessed(file);
	vma->vm_ops = &sgfs_vm_ops;

	file->f_mapping->a_ops = &sgfs_aops; /* set our aops */
	if (!SGFS_F(file)->lower_vm_ops) /* save for our ->fault */
		SGFS_F(file)->lower_vm_ops = saved_vm_ops;

out:
	return err;
}

static int sgfs_open(struct inode *inode, struct file *file)
{
	int err = 0;
	struct file *lower_file = NULL;
	struct path lower_path;

	/* don't open unhashed/deleted files */
	if (d_unhashed(file->f_path.dentry)) {
		err = -ENOENT;
		goto out_err;
	}

	file->private_data =
		kzalloc(sizeof(struct sgfs_file_info), GFP_KERNEL);
	if (!SGFS_F(file)) {
		err = -ENOMEM;
		goto out_err;
	}

	/* open lower object and link sgfs's file struct to lower's */
	sgfs_get_lower_path(file->f_path.dentry, &lower_path);
	lower_file = dentry_open(&lower_path, file->f_flags, current_cred());
	path_put(&lower_path);
	if (IS_ERR(lower_file)) {
		err = PTR_ERR(lower_file);
		lower_file = sgfs_lower_file(file);
		if (lower_file) {
			sgfs_set_lower_file(file, NULL);
			fput(lower_file); /* fput calls dput for lower_dentry */
		}
	} else {
		sgfs_set_lower_file(file, lower_file);
	}

	if (err)
		kfree(SGFS_F(file));
	else
		fsstack_copy_attr_all(inode, sgfs_lower_inode(inode));
out_err:
	return err;
}

static int sgfs_flush(struct file *file, fl_owner_t id)
{
	int err = 0;
	struct file *lower_file = NULL;

	lower_file = sgfs_lower_file(file);
	if (lower_file && lower_file->f_op && lower_file->f_op->flush) {
		filemap_write_and_wait(file->f_mapping);
		err = lower_file->f_op->flush(lower_file, id);
	}

	return err;
}

/* release all lower object references & free the file info structure */
static int sgfs_file_release(struct inode *inode, struct file *file)
{
	struct file *lower_file;

	lower_file = sgfs_lower_file(file);
	if (lower_file) {
		sgfs_set_lower_file(file, NULL);
		fput(lower_file);
	}

	kfree(SGFS_F(file));
	return 0;
}

static int sgfs_fsync(struct file *file, loff_t start, loff_t end,
			int datasync)
{
	int err;
	struct file *lower_file;
	struct path lower_path;
	struct dentry *dentry = file->f_path.dentry;

	err = __generic_file_fsync(file, start, end, datasync);
	if (err)
		goto out;
	lower_file = sgfs_lower_file(file);
	sgfs_get_lower_path(dentry, &lower_path);
	err = vfs_fsync_range(lower_file, start, end, datasync);
	sgfs_put_lower_path(dentry, &lower_path);
out:
	return err;
}

static int sgfs_fasync(int fd, struct file *file, int flag)
{
	int err = 0;
	struct file *lower_file = NULL;

	lower_file = sgfs_lower_file(file);
	if (lower_file->f_op && lower_file->f_op->fasync)
		err = lower_file->f_op->fasync(fd, lower_file, flag);

	return err;
}

/*
 * Sgfs cannot use generic_file_llseek as ->llseek, because it would
 * only set the offset of the upper file.  So we have to implement our
 * own method to set both the upper and lower file offsets
 * consistently.
 */
static loff_t sgfs_file_llseek(struct file *file, loff_t offset, int whence)
{
	int err;
	struct file *lower_file;

	err = generic_file_llseek(file, offset, whence);
	if (err < 0)
		goto out;

	lower_file = sgfs_lower_file(file);
	err = generic_file_llseek(lower_file, offset, whence);

out:
	return err;
}

/*
 * Sgfs read_iter, redirect modified iocb to lower read_iter
 */
ssize_t
sgfs_read_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	int err;
	struct file *file = iocb->ki_filp, *lower_file;

	lower_file = sgfs_lower_file(file);
	if (!lower_file->f_op->read_iter) {
		err = -EINVAL;
		goto out;
	}

	get_file(lower_file); /* prevent lower_file from being released */
	iocb->ki_filp = lower_file;
	err = lower_file->f_op->read_iter(iocb, iter);
	iocb->ki_filp = file;
	fput(lower_file);
	/* update upper inode atime as needed */
	if (err >= 0 || err == -EIOCBQUEUED)
		fsstack_copy_attr_atime(d_inode(file->f_path.dentry),
					file_inode(lower_file));
out:
	return err;
}

/*
 * Sgfs write_iter, redirect modified iocb to lower write_iter
 */
ssize_t
sgfs_write_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	int err;
	struct file *file = iocb->ki_filp, *lower_file;

	lower_file = sgfs_lower_file(file);
	if (!lower_file->f_op->write_iter) {
		err = -EINVAL;
		goto out;
	}

	get_file(lower_file); /* prevent lower_file from being released */
	iocb->ki_filp = lower_file;
	err = lower_file->f_op->write_iter(iocb, iter);
	iocb->ki_filp = file;
	fput(lower_file);
	/* update upper inode times/sizes as needed */
	if (err >= 0 || err == -EIOCBQUEUED) {
		fsstack_copy_inode_size(d_inode(file->f_path.dentry),
					file_inode(lower_file));
		fsstack_copy_attr_times(d_inode(file->f_path.dentry),
					file_inode(lower_file));
	}
out:
	return err;
}

const struct file_operations sgfs_main_fops = {
	.llseek		= generic_file_llseek,
	.read		= sgfs_read,
	.write		= sgfs_write,
	.unlocked_ioctl	= sgfs_unlocked_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= sgfs_compat_ioctl,
#endif
	.mmap		= sgfs_mmap,
	.open		= sgfs_open,
	.flush		= sgfs_flush,
	.release	= sgfs_file_release,
	.fsync		= sgfs_fsync,
	.fasync		= sgfs_fasync,
	.read_iter	= sgfs_read_iter,
	.write_iter	= sgfs_write_iter,
};

/* trimmed directory options */
const struct file_operations sgfs_dir_fops = {
	.llseek		= sgfs_file_llseek,
	.read		= generic_read_dir,
	.iterate	= sgfs_readdir,
	.unlocked_ioctl	= sgfs_unlocked_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= sgfs_compat_ioctl,
#endif
	.open		= sgfs_open,
	.release	= sgfs_file_release,
	.flush		= sgfs_flush,
	.fsync		= sgfs_fsync,
	.fasync		= sgfs_fasync,
};
