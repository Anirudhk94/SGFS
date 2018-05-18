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
#include <linux/module.h>
#include <linux/string.h>
#include <linux/namei.h>
#include <asm/uaccess.h>
#include <linux/types.h>
#include <linux/fs.h>
#include <asm-generic/errno-base.h>
#include <linux/security.h>
#include <linux/stat.h>

/*
 * There is no need to lock the sgfs_super_info's rwsem as there is no
 * way anyone can have a reference to the superblock at this point in time.
 */
static int sgfs_read_super(struct super_block *sb, void *raw_data, int silent)
{
	int err = 0;
	struct super_block *lower_sb;
	struct path lower_path;
	char *dev_name = NULL;
	struct sgfs_parameters *params = NULL;
	struct inode *inode;
	
	params = (struct sgfs_parameters *) raw_data;
	dev_name = (char *) params->lower_path_name;

	if (!dev_name) {
		printk(KERN_ERR
		       "sgfs: read_super: missing dev_name argument\n");
		err = -EINVAL;
		goto out;
	}

	/* parse lower path */
	err = kern_path(dev_name, LOOKUP_FOLLOW | LOOKUP_DIRECTORY,
			&lower_path);
	if (err) {
		printk(KERN_ERR	"sgfs: error accessing "
		       "lower directory '%s'\n", dev_name);
		goto out;
	}

	/* allocate superblock private data */
	sb->s_fs_info = kzalloc(sizeof(struct sgfs_sb_info), GFP_KERNEL);
	if (!SGFS_SB(sb)) {
		printk(KERN_CRIT "sgfs: read_super: out of memory\n");
		err = -ENOMEM;
		goto out_free;
	}

	/* set the lower superblock field of upper superblock */
	lower_sb = lower_path.dentry->d_sb;
	atomic_inc(&lower_sb->s_active);
	sgfs_set_lower_super(sb, lower_sb);

	/* inherit maxbytes from lower file system */
	sb->s_maxbytes = lower_sb->s_maxbytes;

	/*
	 * Our c/m/atime granularity is 1 ns because we may stack on file
	 * systems whose granularity is as good.
	 */
	sb->s_time_gran = 1;

	sb->s_op = &sgfs_sops;

	sb->s_export_op = &sgfs_export_ops; /* adding NFS support */

	/* get a new inode and allocate our root dentry */
	inode = sgfs_iget(sb, d_inode(lower_path.dentry));
	if (IS_ERR(inode)) {
		err = PTR_ERR(inode);
		goto out_sput;
	}
	sb->s_root = d_make_root(inode);
	if (!sb->s_root) {
		err = -ENOMEM;
		goto out_iput;
	}
	d_set_d_op(sb->s_root, &sgfs_dops);

	/* link the upper and lower dentries */
	sb->s_root->d_fsdata = NULL;
	err = new_dentry_private_data(sb->s_root);
	if (err)
		goto out_freeroot;

	/* if get here: cannot have error */

	/* set the lower dentries for s_root */
	sgfs_set_lower_path(sb->s_root, &lower_path);

	/*
	 * No need to call interpose because we already have a positive
	 * dentry, which was instantiated by d_make_root.  Just need to
	 * d_rehash it.
	 */
	d_rehash(sb->s_root);
	if (!silent)
		printk(KERN_INFO
		       "sgfs: mounted on top of %s type %s\n",
		       dev_name, lower_sb->s_type->name);
	goto out; /* all is well */

	/* no longer needed: free_dentry_private_data(sb->s_root); */
out_freeroot:
	dput(sb->s_root);
out_iput:
	iput(inode);
out_sput:
	/* drop refs we took earlier */
	atomic_dec(&lower_sb->s_active);
	kfree(SGFS_SB(sb));
	sb->s_fs_info = NULL;
out_free:
	path_put(&lower_path);

out:
	return err;
}

struct dentry *sgfs_mount(struct file_system_type *fs_type, int flags,
			    const char *dev_name, void *raw_data)
{	
	struct sgfs_parameters *params = NULL;
	char *prefix = NULL;
	char *encrypt_key = NULL;
	char *trash_folder_path = NULL;
	char *trash_folder_name = "/.sg";
	char *encrypt_file_path = NULL;
	char *encrypt_file_name = "/.trash_encryptor"; 
	struct file *fp = NULL;
	int len = 0;
	int error = 0;
	struct dentry *mnt_dentry = NULL;
	struct dentry *trash_dentry = NULL;
	mm_segment_t oldfs;
	unsigned int lookup_flags = LOOKUP_DIRECTORY;
	struct path trash_path;
	umode_t dmode = S_IRWXU|S_IRWXG|S_IRWXO;
	umode_t fmode = S_IRWXU|S_IRWXG|S_IRWXO;
	
	params = (struct sgfs_parameters *)kmalloc(sizeof(struct sgfs_parameters), GFP_KERNEL);
	
	if (params == NULL){
		printk("Failed to allocate memory for parameters\n");
		goto exitlabel;
	}
	
	params->lower_path_name = (void *)dev_name;

	/* Allocate memory for trash folder and encryption key paths */
	trash_folder_path = (char *)kmalloc((strlen(dev_name)+strlen(trash_folder_name)+1)*sizeof(char), GFP_KERNEL);
	encrypt_file_path = (char *)kmalloc((strlen(dev_name)+strlen(encrypt_file_name)+1)*sizeof(char), GFP_KERNEL);
	if (trash_folder_path == NULL || encrypt_file_path == NULL){
		printk("Failed to allocate memory for internal trash folders\n");
		goto exitlabel;
	}

	strcpy(trash_folder_path, dev_name);
	strcpy(encrypt_file_path, dev_name);
	strcat(trash_folder_path, trash_folder_name);
	strcat(encrypt_file_path, encrypt_file_name);
	strcat(trash_folder_path, "\0");
	strcat(encrypt_file_path, "\0");
	
	/* If key is passed extract key */
	if (raw_data){
		prefix = strsep((char **)&raw_data, "=");
		strcat((char *)raw_data, "\0");
		len = strlen(raw_data);

		/* Throw error if key is not of required length */
		if (len != 0 && len != 16)
			return ERR_PTR(-EINVAL);

		encrypt_key = (char *)kmalloc(len*sizeof(char), GFP_KERNEL);
	
		if(encrypt_key == NULL){
			printk("Failed to allocate memory for encryption key\n");
		}

		strcpy(encrypt_key, raw_data);
		params->encrypt_key = encrypt_key;
	}
	
	/* Mount the file system */
	mnt_dentry = mount_nodev(fs_type, flags, params, sgfs_read_super);
	
	if (mnt_dentry == NULL){
		printk("Failed to mount filesystem\n");
		goto exitlabel;	
	}
	
	/* Create the trash folder and the encryption key file */
	oldfs = get_fs();
	set_fs(KERNEL_DS);
	trash_dentry = user_path_create(AT_FDCWD, trash_folder_path, &trash_path, lookup_flags);
	if (IS_ERR(trash_dentry) && (int)PTR_ERR(trash_dentry) != -EEXIST){
		printk("Failed to create dentry %d\n", (int) PTR_ERR(trash_dentry) );
		goto segment_exit;
	}

	error = security_path_mkdir(&trash_path, trash_dentry, dmode);
	if (!error)
		error = vfs_mkdir(trash_path.dentry->d_inode, trash_dentry, dmode);

	done_path_create(&trash_path, trash_dentry);

	if (error < 0 && error != -EEXIST){
		printk("Error while creating dir %d\n", error);
		goto segment_exit;
	}	
	
	fp = filp_open(encrypt_file_path, O_CREAT|O_WRONLY|O_TRUNC, fmode);
	if (fp == NULL || IS_ERR(fp)) {
		printk("Failed to create encrypt key file, err:%d\n", (int) PTR_ERR(fp));
		goto segment_exit;
	}
	
	fp->f_pos = 0;
	if (len > 0)
		if( ( error = vfs_write(fp, encrypt_key, len, &fp->f_pos) ) < len)
			printk("Failed to write key to file, err:%d\n", error);

	filp_close(fp, NULL);

	segment_exit:
		set_fs(oldfs);
	exitlabel:
		return mnt_dentry;
}

static struct file_system_type sgfs_fs_type = {
	.owner		= THIS_MODULE,
	.name		= SGFS_NAME,
	.mount		= sgfs_mount,
	.kill_sb	= generic_shutdown_super,
	.fs_flags	= 0,
};
MODULE_ALIAS_FS(SGFS_NAME);

static int __init init_sgfs_fs(void)
{
	int err;

	pr_info("Registering sgfs " SGFS_VERSION "\n");

	err = sgfs_init_inode_cache();
	if (err)
		goto out;
	err = sgfs_init_dentry_cache();
	if (err)
		goto out;
	err = register_filesystem(&sgfs_fs_type);
out:
	if (err) {
		sgfs_destroy_inode_cache();
		sgfs_destroy_dentry_cache();
	}
	return err;
}

static void __exit exit_sgfs_fs(void)
{
	sgfs_destroy_inode_cache();
	sgfs_destroy_dentry_cache();
	unregister_filesystem(&sgfs_fs_type);
	pr_info("Completed sgfs module unload\n");
}

MODULE_AUTHOR("Erez Zadok, Filesystems and Storage Lab, Stony Brook University"
	      " (http://www.fsl.cs.sunysb.edu/)");
MODULE_DESCRIPTION("SGfs " SGFS_VERSION
		   " (http://sgfs.filesystems.org/)");
MODULE_LICENSE("GPL");

module_init(init_sgfs_fs);
module_exit(exit_sgfs_fs);
