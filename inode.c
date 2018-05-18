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

static int sgfs_encrypt(char *, char *, char *);
static void tcrypt_complete(struct crypto_async_request *, int);

static int sgfs_create(struct inode *dir, struct dentry *dentry,
			 umode_t mode, bool want_excl)
{
	int err;
	struct dentry *lower_dentry;
	struct dentry *lower_parent_dentry = NULL;
	struct path lower_path;

	sgfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	lower_parent_dentry = lock_parent(lower_dentry);

	err = vfs_create(d_inode(lower_parent_dentry), lower_dentry, mode,
			 want_excl);
	if (err)
		goto out;
	err = sgfs_interpose(dentry, dir->i_sb, &lower_path);
	if (err)
		goto out;
	fsstack_copy_attr_times(dir, sgfs_lower_inode(dir));
	fsstack_copy_inode_size(dir, d_inode(lower_parent_dentry));

out:
	unlock_dir(lower_parent_dentry);
	sgfs_put_lower_path(dentry, &lower_path);
	return err;
}

static int sgfs_link(struct dentry *old_dentry, struct inode *dir,
		       struct dentry *new_dentry)
{
	struct dentry *lower_old_dentry;
	struct dentry *lower_new_dentry;
	struct dentry *lower_dir_dentry;
	u64 file_size_save;
	int err;
	struct path lower_old_path, lower_new_path;

	file_size_save = i_size_read(d_inode(old_dentry));
	sgfs_get_lower_path(old_dentry, &lower_old_path);
	sgfs_get_lower_path(new_dentry, &lower_new_path);
	lower_old_dentry = lower_old_path.dentry;
	lower_new_dentry = lower_new_path.dentry;
	lower_dir_dentry = lock_parent(lower_new_dentry);

	err = vfs_link(lower_old_dentry, d_inode(lower_dir_dentry),
		       lower_new_dentry, NULL);
	if (err || !d_inode(lower_new_dentry))
		goto out;

	err = sgfs_interpose(new_dentry, dir->i_sb, &lower_new_path);
	if (err)
		goto out;
	fsstack_copy_attr_times(dir, d_inode(lower_new_dentry));
	fsstack_copy_inode_size(dir, d_inode(lower_new_dentry));
	set_nlink(d_inode(old_dentry),
		  sgfs_lower_inode(d_inode(old_dentry))->i_nlink);
	i_size_write(d_inode(new_dentry), file_size_save);
out:
	unlock_dir(lower_dir_dentry);
	sgfs_put_lower_path(old_dentry, &lower_old_path);
	sgfs_put_lower_path(new_dentry, &lower_new_path);
	return err;
}

static int sgfs_unlink(struct inode *dir, struct dentry *dentry)
{
	int err;
	int test_len;
	struct timespec ts;
	struct dentry *lower_dentry;
	struct inode *lower_dir_inode = sgfs_lower_inode(dir);
	struct dentry *lower_dir_dentry;
	struct path lower_path;
	struct dentry *del_dentry;
	struct path del_path;
	struct inode *del_parent_inode;
	struct super_block *upper_sb = dentry->d_inode->i_sb;
	struct dentry *upper_root = upper_sb->s_root;
	struct path upper_root_path;
	struct dentry *lower_sgfs_root;
	struct file *temp = NULL;
	struct path *temp_path = NULL;
	char root_file[256];
	char test_file[15];
	char uid[8];
	char *root_pathname;
	char root_path_buffer[80];
	char *ext;
	char key_file[256];
	unsigned int lookup_flags = LOOKUP_CREATE;
	mm_segment_t oldfs;	
	int del_status = 0;

	sgfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	dget(lower_dentry);

	/* Code to get the parent dir of the current file being unlinked 
	   If file being deleted is from the .sg directory, then simply
	   unlink the file, else move it to the .sg folder */
	lower_dir_dentry = lower_dentry->d_parent;
	dget(lower_dir_dentry);
	if (strcmp(lower_dir_dentry->d_iname, ".sg") == 0)
		goto simpledelete;

	/* Don't move files with multiple hard links to the recycle bin */
	if (lower_dentry->d_inode->i_nlink != 1)
		goto simpledelete;

	/* Get the lower path of the root of the sgfs file system i.e the lower mount point */	
	sgfs_get_lower_path(upper_root, &upper_root_path);
	lower_sgfs_root = upper_root_path.dentry;
	dget(lower_sgfs_root);
	
	/* Get the lower mount points absolute path */
	root_pathname = dentry_path_raw(lower_sgfs_root, root_path_buffer, 80);
	if (!root_pathname || IS_ERR(root_pathname)) {
		err = (int)PTR_ERR(root_pathname);
		goto out_err;
	}

	/* Get the extension of the file being unlinked */
	ext = strrchr(lower_dentry->d_iname, '.');
	
	/* Check extension of the file to make sure that temp files created during file editing are moved to recycle bin */
	if (!ext || ( strcmp(ext, ".swo") != 0 && ext[strlen(ext)-1] != '~' && strcmp(ext, ".swpx") != 0 && strcmp(ext, ".swp") != 0 && strcmp(ext, ".swx") != 0 )) {

		/* Get the UID of the file to ensure that */
		test_len = snprintf(NULL, 0, "%d", lower_dentry->d_inode->i_uid.val);
		snprintf(uid, test_len+1, "%d", lower_dentry->d_inode->i_uid.val);
		strcat(uid, ":");

		/* Get the epoch timestamp for the operation */
		getnstimeofday(&ts);
		test_len = snprintf(NULL, 0, "%lu", ts.tv_sec);
		snprintf(test_file, test_len+1, "%lu", ts.tv_sec);
		strcat(test_file, ":");
	
		/* Construct the filename for the recycle bin */
		strcpy(root_file, root_pathname);
		strcpy(key_file, root_pathname);
		strcat(key_file, "/.trash_encryptor");
		strcat(root_file, "/.sg/");
		strcat(root_file, uid);
		strcat(root_file, test_file);
		strcat(root_file, lower_dentry->d_iname);
		strcat(key_file, "\0");

		oldfs = get_fs();
		set_fs(KERNEL_DS);

		temp = filp_open(key_file, O_RDONLY, 0);
		if (!temp || IS_ERR(temp)){
			printk("Unable to open key file\n");
			return -ENOENT;
		}
		
		temp_path = &temp->f_path;
		if (temp_path->dentry->d_inode->i_size > 0)
			strcat(root_file, ".enc");
		filp_close(temp, NULL);
		
		strcat(root_file, "\0");
		printk("Deleted filename is %s\n", root_file);
		/* Get the negative dentry for the entry in the recycle bin */
		del_dentry = user_path_create(AT_FDCWD, root_file, &del_path, lookup_flags);
		if(IS_ERR(del_dentry)) {
			printk("Failed to create dentry for trash file %s, %d, %s\n", root_file, (int)PTR_ERR(del_dentry), lower_dentry->d_iname);
			err = (int)PTR_ERR(del_dentry);
			goto out_err;
		}
		
		del_parent_inode = del_dentry->d_parent->d_inode;
		
		/* Hard link the recycle bin path to the file */
		err = vfs_link(lower_dentry, del_parent_inode, del_dentry, NULL);
		if (err < 0) {
			printk("Failed to link trash entry\n");
			goto out_err;
		}

		done_path_create(&del_path, del_dentry);	
		set_fs(oldfs);
		del_status = 1;
	}

simpledelete:	
	lower_dir_dentry = lock_parent(lower_dentry);

	err = vfs_unlink(lower_dir_inode, lower_dentry, NULL);

	/*
	 * Note: unlinking on top of NFS can cause silly-renamed files.
	 * Trying to delete such files results in EBUSY from NFS
	 * below.  Silly-renamed files will get deleted by NFS later on, so
	 * we just need to detect them here and treat such EBUSY errors as
	 * if the upper file was successfully deleted.
	 */
	if (err == -EBUSY && lower_dentry->d_flags & DCACHE_NFSFS_RENAMED)
		err = 0;
	if (err)
		goto out;
	fsstack_copy_attr_times(dir, lower_dir_inode);
	fsstack_copy_inode_size(dir, lower_dir_inode);
	set_nlink(d_inode(dentry),
		  sgfs_lower_inode(d_inode(dentry))->i_nlink);
	d_inode(dentry)->i_ctime = dir->i_ctime;
	d_drop(dentry); /* this is needed, else LTP fails (VFS won't do it) */
	
	/* Perform encryption on the file if deleted successfully */
	if (del_status == 1){
		oldfs = get_fs();
		set_fs(KERNEL_DS);
		err = sgfs_encrypt(root_pathname, key_file, root_file);
		set_fs(oldfs);
	}

out:
	unlock_dir(lower_dir_dentry);
	dput(lower_dentry);
	sgfs_put_lower_path(dentry, &lower_path);
out_err:
	return err;
}

static int sgfs_encrypt(char *root_pathname, char *key_file, char *input_file)
{
	int key_bytes, file_bytes, file_size, padding, bytes_written = 0, ret = 0, temp_bytes = 0;
	char *key_buff, *file_buff, *temp_buff, *temp_file;
	struct file *file_temp, *file_key, *file_input;
	struct path *p1 = NULL;
	struct path *p2 = NULL;
	struct path *p3 = NULL;
	struct dentry *trap = NULL;
	struct inode *pinode1 = NULL;
	struct inode *pinode2 = NULL;

	temp_file = (char *)kmalloc(80, GFP_KERNEL);
	if (temp_file == NULL)
		return -ENOMEM;

	/* Path name for temporary file to be created in the bin */
	strcpy(temp_file, root_pathname);
	strcat(temp_file, "/.sg/.temp.enc.file");
	
	/* Open key and input file for encryption */
	file_key = filp_open(key_file, O_RDONLY, 0);
	if (IS_ERR(file_key) || !file_key)
		goto out;

	file_input = filp_open(input_file, O_RDONLY, 0);
	if (IS_ERR(file_input) || !file_input)
		goto file_cleanup2;
	
	p1 = &file_key->f_path;
	p2 = &file_input->f_path;

	file_size = p2->dentry->d_inode->i_size;
	
	file_key->f_pos = 0;
	file_input->f_pos = 0;

	/* Allocate buffers to read key, file and cipher data */
	key_buff = (char *)kmalloc(BUFFER_SIZE, GFP_KERNEL);
	if (key_buff == NULL){
		ret = -ENOMEM;
		goto file_cleanup1;
	}

	file_buff = (char *)kmalloc(BUFFER_SIZE, GFP_KERNEL);
	if (file_buff == NULL){
		ret = -ENOMEM;
		goto mem_cleanup1;
	}
	
	temp_buff = (char *)kmalloc(BUFFER_SIZE, GFP_KERNEL);
	if (temp_buff == NULL){
		ret = -ENOMEM;
		goto mem_cleanup2;
	}

	/* Read the key and ensure that it is not empty */
	key_bytes = vfs_read(file_key, key_buff, ksize(key_buff), &file_key->f_pos);
	if (key_bytes != p1->dentry->d_inode->i_size){
		ret = -EIO;
		goto mem_cleanup3;
	}
	if (key_bytes == 0)
		goto mem_cleanup3;
	
	file_temp = filp_open(temp_file, O_RDWR|O_CREAT|O_TRUNC, 0777);
	if (IS_ERR(file_temp)){
		ret = (int) PTR_ERR(file_temp);
		goto file_cleanup4;
	}
	file_temp->f_pos = 0;	
	
	/* Write the encryption key to the temp file for future decryption */
	temp_bytes = vfs_write(file_temp, key_buff, ksize(key_buff), &file_temp->f_pos);
	if (temp_bytes < 0){
		printk("Failed to write encryption key preamble to temp file\n");
		ret = -ENOMEM;
		goto file_cleanup4;
	}

	/* Read the input file and encrypt it. Write encrypted data to temp file */
	while ( (file_bytes = vfs_read(file_input, file_buff, ksize(file_buff), &file_input->f_pos)) > 0){
		padding = (0x10 - (file_bytes & 0x0f))%ksize(file_buff);
		memset(file_buff+file_bytes, padding, padding);

		if ( ( temp_bytes = kencrypt(key_buff, key_bytes, temp_buff, file_buff, ksize(file_buff), 1) ) > 0){
			temp_bytes = vfs_write(file_temp, temp_buff, ksize(file_buff), &file_temp->f_pos);
			bytes_written += temp_bytes;
		}	
	}

	/* Ensure that all the file contents were written */
	if (bytes_written < file_size){
		ret = -EIO;
		goto file_cleanup4;
	}
	
	p3 = &file_temp->f_path;
	pinode1 = p2->dentry->d_parent->d_inode;
	pinode2 = p3->dentry->d_parent->d_inode;

	/* Rename the temp file and the deleted file */
	trap = lock_rename(p2->dentry->d_parent, p3->dentry->d_parent);
	if (trap != NULL){
		ret = -EINVAL;
		goto rename_cleanup;
	}

	ret = vfs_rename(pinode1, p2->dentry, pinode2, p3->dentry, NULL, RENAME_EXCHANGE);

rename_cleanup:
	unlock_rename(p2->dentry->d_parent, p3->dentry->d_parent);
	
	if (ret != -EINVAL){
		inode_lock(pinode1);
		vfs_unlink(pinode1, p2->dentry, NULL);
		inode_unlock(pinode1);
	}
	
file_cleanup4:
	filp_close(file_temp, NULL);
mem_cleanup3:
	kfree(temp_buff);
mem_cleanup2:
	kfree(file_buff);
mem_cleanup1:
	kfree(key_buff);
file_cleanup1:
	filp_close(file_input, NULL);
file_cleanup2:
	filp_close(file_key, NULL);
out:
	return ret;
}

static void tcrypt_complete(struct crypto_async_request *req, int err)
{
	struct tcrypt_result *res = req->data;
	
	if (err == -EINPROGRESS)
		return;

	res->err = err;
	complete(&res->completion);
}

int kencrypt(const char *key, int key_len, char *dst, char *src, int src_len, int op)
{
	int ret = 0;
	int dst_len = src_len;
	struct crypto_skcipher *tfm = crypto_alloc_skcipher("cbc(aes)", 0, 0);
	struct scatterlist sg_in;
	struct skcipher_request *req = NULL;
	struct tcrypt_result result;
	char iv[16];

	/* Check tranformation allocation */
	if (IS_ERR(tfm) || tfm == NULL){
		printk("Failed to allocate tfm, err: %d\n", (int)PTR_ERR(tfm));
		ret = (int)PTR_ERR(tfm);
		goto exitlabel;
	}

	/* Initialize IV and set cipher key */
	memset(iv, 0, 16);
	ret = crypto_skcipher_setkey(tfm, key, key_len);
	if (ret < 0){
		printk("Failed to set cipher key, err: %d\n", ret);
		goto cleanup;
	}

	/* Allocate cipher request object */
	req = skcipher_request_alloc(tfm, GFP_KERNEL);
	if (!req || IS_ERR(req)){
		printk("Failed to allocate skcipher_req");
		ret = PTR_ERR(req);
		goto exitlabel;
	}
	
	/* Set callback function */
	skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG, tcrypt_complete, &result);
	init_completion(&result.completion);

	sg_init_one(&sg_in, src, src_len);
	
	skcipher_request_set_crypt(req, &sg_in, &sg_in, src_len, iv);
	
	if (op)
		ret = crypto_skcipher_encrypt(req);
	else
		ret = crypto_skcipher_decrypt(req);

	if (ret == -EINPROGRESS || ret == -EBUSY){
		printk("Encryption/decryption is in busy state\n");
		wait_for_completion(&result.completion);
	}

	if (ret < 0){
		printk("Encryption/decryption failed\n");
		goto req_cleanup;
	}

	ret = sg_copy_to_buffer(&sg_in, 1, dst, dst_len);

req_cleanup:
	skcipher_request_free(req);
cleanup:
	crypto_free_skcipher(tfm);
exitlabel:
	return ret;

}

static int sgfs_symlink(struct inode *dir, struct dentry *dentry,
			  const char *symname)
{
	int err;
	struct dentry *lower_dentry;
	struct dentry *lower_parent_dentry = NULL;
	struct path lower_path;

	sgfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	lower_parent_dentry = lock_parent(lower_dentry);

	err = vfs_symlink(d_inode(lower_parent_dentry), lower_dentry, symname);
	if (err)
		goto out;
	err = sgfs_interpose(dentry, dir->i_sb, &lower_path);
	if (err)
		goto out;
	fsstack_copy_attr_times(dir, sgfs_lower_inode(dir));
	fsstack_copy_inode_size(dir, d_inode(lower_parent_dentry));

out:
	unlock_dir(lower_parent_dentry);
	sgfs_put_lower_path(dentry, &lower_path);
	return err;
}

static int sgfs_mkdir(struct inode *dir, struct dentry *dentry, umode_t mode)
{	
	int err;
	struct dentry *lower_dentry;
	struct dentry *lower_parent_dentry = NULL;
	struct path lower_path;

	sgfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	lower_parent_dentry = lock_parent(lower_dentry);
	
	err = vfs_mkdir(d_inode(lower_parent_dentry), lower_dentry, mode);
	if (err)
		goto out;

	err = sgfs_interpose(dentry, dir->i_sb, &lower_path);
	if (err)
		goto out;

	fsstack_copy_attr_times(dir, sgfs_lower_inode(dir));
	fsstack_copy_inode_size(dir, d_inode(lower_parent_dentry));
	/* update number of links on parent directory */
	set_nlink(dir, sgfs_lower_inode(dir)->i_nlink);

out:
	unlock_dir(lower_parent_dentry);
	sgfs_put_lower_path(dentry, &lower_path);
	return err;
}

static int sgfs_rmdir(struct inode *dir, struct dentry *dentry)
{
	struct dentry *lower_dentry;
	struct dentry *lower_dir_dentry;
	int err;
	struct path lower_path;

	sgfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	lower_dir_dentry = lock_parent(lower_dentry);

	printk("sgfs_rmdir called\n");	

	err = vfs_rmdir(d_inode(lower_dir_dentry), lower_dentry);
	if (err)
		goto out;

	d_drop(dentry);	/* drop our dentry on success (why not VFS's job?) */
	if (d_inode(dentry))
		clear_nlink(d_inode(dentry));
	fsstack_copy_attr_times(dir, d_inode(lower_dir_dentry));
	fsstack_copy_inode_size(dir, d_inode(lower_dir_dentry));
	set_nlink(dir, d_inode(lower_dir_dentry)->i_nlink);

out:
	unlock_dir(lower_dir_dentry);
	sgfs_put_lower_path(dentry, &lower_path);
	return err;
}

static int sgfs_mknod(struct inode *dir, struct dentry *dentry, umode_t mode,
			dev_t dev)
{
	int err;
	struct dentry *lower_dentry;
	struct dentry *lower_parent_dentry = NULL;
	struct path lower_path;

	sgfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	lower_parent_dentry = lock_parent(lower_dentry);

	err = vfs_mknod(d_inode(lower_parent_dentry), lower_dentry, mode, dev);
	if (err)
		goto out;

	err = sgfs_interpose(dentry, dir->i_sb, &lower_path);
	if (err)
		goto out;
	fsstack_copy_attr_times(dir, sgfs_lower_inode(dir));
	fsstack_copy_inode_size(dir, d_inode(lower_parent_dentry));

out:
	unlock_dir(lower_parent_dentry);
	sgfs_put_lower_path(dentry, &lower_path);
	return err;
}

/*
 * The locking rules in sgfs_rename are complex.  We could use a simpler
 * superblock-level name-space lock for renames and copy-ups.
 */
static int sgfs_rename(struct inode *old_dir, struct dentry *old_dentry,
			 struct inode *new_dir, struct dentry *new_dentry)
{
	int err = 0;
	struct dentry *lower_old_dentry = NULL;
	struct dentry *lower_new_dentry = NULL;
	struct dentry *lower_old_dir_dentry = NULL;
	struct dentry *lower_new_dir_dentry = NULL;
	struct dentry *trap = NULL;
	struct path lower_old_path, lower_new_path;

	sgfs_get_lower_path(old_dentry, &lower_old_path);
	sgfs_get_lower_path(new_dentry, &lower_new_path);
	lower_old_dentry = lower_old_path.dentry;
	lower_new_dentry = lower_new_path.dentry;
	lower_old_dir_dentry = dget_parent(lower_old_dentry);
	lower_new_dir_dentry = dget_parent(lower_new_dentry);

	trap = lock_rename(lower_old_dir_dentry, lower_new_dir_dentry);
	/* source should not be ancestor of target */
	if (trap == lower_old_dentry) {
		err = -EINVAL;
		goto out;
	}
	/* target should not be ancestor of source */
	if (trap == lower_new_dentry) {
		err = -ENOTEMPTY;
		goto out;
	}

	err = vfs_rename(d_inode(lower_old_dir_dentry), lower_old_dentry,
			 d_inode(lower_new_dir_dentry), lower_new_dentry,
			 NULL, 0);
	if (err)
		goto out;

	fsstack_copy_attr_all(new_dir, d_inode(lower_new_dir_dentry));
	fsstack_copy_inode_size(new_dir, d_inode(lower_new_dir_dentry));
	if (new_dir != old_dir) {
		fsstack_copy_attr_all(old_dir,
				      d_inode(lower_old_dir_dentry));
		fsstack_copy_inode_size(old_dir,
					d_inode(lower_old_dir_dentry));
	}

out:
	unlock_rename(lower_old_dir_dentry, lower_new_dir_dentry);
	dput(lower_old_dir_dentry);
	dput(lower_new_dir_dentry);
	sgfs_put_lower_path(old_dentry, &lower_old_path);
	sgfs_put_lower_path(new_dentry, &lower_new_path);
	return err;
}

static int sgfs_readlink(struct dentry *dentry, char __user *buf, int bufsiz)
{
	int err;
	struct dentry *lower_dentry;
	struct path lower_path;

	sgfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	if (!d_inode(lower_dentry)->i_op ||
	    !d_inode(lower_dentry)->i_op->readlink) {
		err = -EINVAL;
		goto out;
	}

	err = d_inode(lower_dentry)->i_op->readlink(lower_dentry,
						    buf, bufsiz);
	if (err < 0)
		goto out;
	fsstack_copy_attr_atime(d_inode(dentry), d_inode(lower_dentry));

out:
	sgfs_put_lower_path(dentry, &lower_path);
	return err;
}

static const char *sgfs_get_link(struct dentry *dentry, struct inode *inode,
				   struct delayed_call *done)
{
	char *buf;
	int len = PAGE_SIZE, err;
	mm_segment_t old_fs;

	if (!dentry)
		return ERR_PTR(-ECHILD);

	/* This is freed by the put_link method assuming a successful call. */
	buf = kmalloc(len, GFP_KERNEL);
	if (!buf) {
		buf = ERR_PTR(-ENOMEM);
		return buf;
	}

	/* read the symlink, and then we will follow it */
	old_fs = get_fs();
	set_fs(KERNEL_DS);
	err = sgfs_readlink(dentry, buf, len);
	set_fs(old_fs);
	if (err < 0) {
		kfree(buf);
		buf = ERR_PTR(err);
	} else {
		buf[err] = '\0';
	}
	set_delayed_call(done, kfree_link, buf);
	return buf;
}

static int sgfs_permission(struct inode *inode, int mask)
{
	struct inode *lower_inode;
	int err;

	lower_inode = sgfs_lower_inode(inode);
	err = inode_permission(lower_inode, mask);
	return err;
}

static int sgfs_setattr(struct dentry *dentry, struct iattr *ia)
{
	int err;
	struct dentry *lower_dentry;
	struct inode *inode;
	struct inode *lower_inode;
	struct path lower_path;
	struct iattr lower_ia;

	inode = d_inode(dentry);

	/*
	 * Check if user has permission to change inode.  We don't check if
	 * this user can change the lower inode: that should happen when
	 * calling notify_change on the lower inode.
	 */
	err = inode_change_ok(inode, ia);
	if (err)
		goto out_err;

	sgfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	lower_inode = sgfs_lower_inode(inode);

	/* prepare our own lower struct iattr (with the lower file) */
	memcpy(&lower_ia, ia, sizeof(lower_ia));
	if (ia->ia_valid & ATTR_FILE)
		lower_ia.ia_file = sgfs_lower_file(ia->ia_file);

	/*
	 * If shrinking, first truncate upper level to cancel writing dirty
	 * pages beyond the new eof; and also if its' maxbytes is more
	 * limiting (fail with -EFBIG before making any change to the lower
	 * level).  There is no need to vmtruncate the upper level
	 * afterwards in the other cases: we fsstack_copy_inode_size from
	 * the lower level.
	 */
	if (ia->ia_valid & ATTR_SIZE) {
		err = inode_newsize_ok(inode, ia->ia_size);
		if (err)
			goto out;
		truncate_setsize(inode, ia->ia_size);
	}

	/*
	 * mode change is for clearing setuid/setgid bits. Allow lower fs
	 * to interpret this in its own way.
	 */
	if (lower_ia.ia_valid & (ATTR_KILL_SUID | ATTR_KILL_SGID))
		lower_ia.ia_valid &= ~ATTR_MODE;

	/* notify the (possibly copied-up) lower inode */
	/*
	 * Note: we use d_inode(lower_dentry), because lower_inode may be
	 * unlinked (no inode->i_sb and i_ino==0.  This happens if someone
	 * tries to open(), unlink(), then ftruncate() a file.
	 */
	inode_lock(d_inode(lower_dentry));
	err = notify_change(lower_dentry, &lower_ia, /* note: lower_ia */
			    NULL);
	inode_unlock(d_inode(lower_dentry));
	if (err)
		goto out;

	/* get attributes from the lower inode */
	fsstack_copy_attr_all(inode, lower_inode);
	/*
	 * Not running fsstack_copy_inode_size(inode, lower_inode), because
	 * VFS should update our inode size, and notify_change on
	 * lower_inode should update its size.
	 */

out:
	sgfs_put_lower_path(dentry, &lower_path);
out_err:
	return err;
}

static int sgfs_getattr(struct vfsmount *mnt, struct dentry *dentry,
			  struct kstat *stat)
{
	int err;
	struct kstat lower_stat;
	struct path lower_path;

	sgfs_get_lower_path(dentry, &lower_path);
	err = vfs_getattr(&lower_path, &lower_stat);
	if (err)
		goto out;
	fsstack_copy_attr_all(d_inode(dentry),
			      d_inode(lower_path.dentry));
	generic_fillattr(d_inode(dentry), stat);
	stat->blocks = lower_stat.blocks;
out:
	sgfs_put_lower_path(dentry, &lower_path);
	return err;
}

static int
sgfs_setxattr(struct dentry *dentry, const char *name, const void *value,
		size_t size, int flags)
{
	int err; struct dentry *lower_dentry;
	struct path lower_path;

	sgfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	if (!d_inode(lower_dentry)->i_op->setxattr) {
		err = -EOPNOTSUPP;
		goto out;
	}
	err = vfs_setxattr(lower_dentry, name, value, size, flags);
	if (err)
		goto out;
	fsstack_copy_attr_all(d_inode(dentry),
			      d_inode(lower_path.dentry));
out:
	sgfs_put_lower_path(dentry, &lower_path);
	return err;
}

static ssize_t
sgfs_getxattr(struct dentry *dentry, const char *name, void *buffer,
		size_t size)
{
	int err;
	struct dentry *lower_dentry;
	struct path lower_path;

	sgfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	if (!d_inode(lower_dentry)->i_op->getxattr) {
		err = -EOPNOTSUPP;
		goto out;
	}
	err = vfs_getxattr(lower_dentry, name, buffer, size);
	if (err)
		goto out;
	fsstack_copy_attr_atime(d_inode(dentry),
				d_inode(lower_path.dentry));
out:
	sgfs_put_lower_path(dentry, &lower_path);
	return err;
}

static ssize_t
sgfs_listxattr(struct dentry *dentry, char *buffer, size_t buffer_size)
{
	int err;
	struct dentry *lower_dentry;
	struct path lower_path;

	sgfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	if (!d_inode(lower_dentry)->i_op->listxattr) {
		err = -EOPNOTSUPP;
		goto out;
	}
	err = vfs_listxattr(lower_dentry, buffer, buffer_size);
	if (err)
		goto out;
	fsstack_copy_attr_atime(d_inode(dentry),
				d_inode(lower_path.dentry));
out:
	sgfs_put_lower_path(dentry, &lower_path);
	return err;
}

static int
sgfs_removexattr(struct dentry *dentry, const char *name)
{
	int err;
	struct dentry *lower_dentry;
	struct path lower_path;

	sgfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	if (!d_inode(lower_dentry)->i_op ||
	    !d_inode(lower_dentry)->i_op->removexattr) {
		err = -EINVAL;
		goto out;
	}
	err = vfs_removexattr(lower_dentry, name);
	if (err)
		goto out;
	fsstack_copy_attr_all(d_inode(dentry),
			      d_inode(lower_path.dentry));
out:
	sgfs_put_lower_path(dentry, &lower_path);
	return err;
}
const struct inode_operations sgfs_symlink_iops = {
	.readlink	= sgfs_readlink,
	.permission	= sgfs_permission,
	.setattr	= sgfs_setattr,
	.getattr	= sgfs_getattr,
	.get_link	= sgfs_get_link,
	.setxattr	= sgfs_setxattr,
	.getxattr	= sgfs_getxattr,
	.listxattr	= sgfs_listxattr,
	.removexattr	= sgfs_removexattr,
};

const struct inode_operations sgfs_dir_iops = {
	.create		= sgfs_create,
	.lookup		= sgfs_lookup,
	.link		= sgfs_link,
	.unlink		= sgfs_unlink,
	.symlink	= sgfs_symlink,
	.mkdir		= sgfs_mkdir,
	.rmdir		= sgfs_rmdir,
	.mknod		= sgfs_mknod,
	.rename		= sgfs_rename,
	.permission	= sgfs_permission,
	.setattr	= sgfs_setattr,
	.getattr	= sgfs_getattr,
	.setxattr	= sgfs_setxattr,
	.getxattr	= sgfs_getxattr,
	.listxattr	= sgfs_listxattr,
	.removexattr	= sgfs_removexattr,
};

const struct inode_operations sgfs_main_iops = {
	.permission	= sgfs_permission,
	.setattr	= sgfs_setattr,
	.getattr	= sgfs_getattr,
	.setxattr	= sgfs_setxattr,
	.getxattr	= sgfs_getxattr,
	.listxattr	= sgfs_listxattr,
	.removexattr	= sgfs_removexattr,
};
