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

/*
 * The inode cache is used with alloc_inode for both our inode info and the
 * vfs inode.
 */
static struct kmem_cache *sgfs_inode_cachep;

/* final actions when unmounting a file system */
static void sgfs_put_super(struct super_block *sb)
{
	struct sgfs_sb_info *spd;
	struct super_block *s;

	spd = SGFS_SB(sb);
	if (!spd)
		return;

	/* decrement lower super references */
	s = sgfs_lower_super(sb);
	sgfs_set_lower_super(sb, NULL);
	atomic_dec(&s->s_active);

	kfree(spd);
	sb->s_fs_info = NULL;
}

static int sgfs_statfs(struct dentry *dentry, struct kstatfs *buf)
{
	int err;
	struct path lower_path;

	sgfs_get_lower_path(dentry, &lower_path);
	err = vfs_statfs(&lower_path, buf);
	sgfs_put_lower_path(dentry, &lower_path);

	/* set return buf to our f/s to avoid confusing user-level utils */
	buf->f_type = SGFS_SUPER_MAGIC;

	return err;
}

/*
 * @flags: numeric mount options
 * @options: mount options string
 */
static int sgfs_remount_fs(struct super_block *sb, int *flags, char *options)
{
	int err = 0;

	/*
	 * The VFS will take care of "ro" and "rw" flags among others.  We
	 * can safely accept a few flags (RDONLY, MANDLOCK), and honor
	 * SILENT, but anything else left over is an error.
	 */
	if ((*flags & ~(MS_RDONLY | MS_MANDLOCK | MS_SILENT)) != 0) {
		printk(KERN_ERR
		       "sgfs: remount flags 0x%x unsupported\n", *flags);
		err = -EINVAL;
	}

	return err;
}

/*
 * Called by iput() when the inode reference count reached zero
 * and the inode is not hashed anywhere.  Used to clear anything
 * that needs to be, before the inode is completely destroyed and put
 * on the inode free list.
 */
static void sgfs_evict_inode(struct inode *inode)
{
	struct inode *lower_inode;

	truncate_inode_pages(&inode->i_data, 0);
	clear_inode(inode);
	/*
	 * Decrement a reference to a lower_inode, which was incremented
	 * by our read_inode when it was created initially.
	 */
	lower_inode = sgfs_lower_inode(inode);
	sgfs_set_lower_inode(inode, NULL);
	iput(lower_inode);
}

static struct inode *sgfs_alloc_inode(struct super_block *sb)
{
	struct sgfs_inode_info *i;

	i = kmem_cache_alloc(sgfs_inode_cachep, GFP_KERNEL);
	if (!i)
		return NULL;

	/* memset everything up to the inode to 0 */
	memset(i, 0, offsetof(struct sgfs_inode_info, vfs_inode));

	i->vfs_inode.i_version = 1;
	return &i->vfs_inode;
}

static void sgfs_destroy_inode(struct inode *inode)
{
	kmem_cache_free(sgfs_inode_cachep, SGFS_I(inode));
}

/* sgfs inode cache constructor */
static void init_once(void *obj)
{
	struct sgfs_inode_info *i = obj;

	inode_init_once(&i->vfs_inode);
}

int sgfs_init_inode_cache(void)
{
	int err = 0;

	sgfs_inode_cachep =
		kmem_cache_create("sgfs_inode_cache",
				  sizeof(struct sgfs_inode_info), 0,
				  SLAB_RECLAIM_ACCOUNT, init_once);
	if (!sgfs_inode_cachep)
		err = -ENOMEM;
	return err;
}

/* sgfs inode cache destructor */
void sgfs_destroy_inode_cache(void)
{
	if (sgfs_inode_cachep)
		kmem_cache_destroy(sgfs_inode_cachep);
}

/*
 * Used only in nfs, to kill any pending RPC tasks, so that subsequent
 * code can actually succeed and won't leave tasks that need handling.
 */
static void sgfs_umount_begin(struct super_block *sb)
{
	struct super_block *lower_sb;

	lower_sb = sgfs_lower_super(sb);
	if (lower_sb && lower_sb->s_op && lower_sb->s_op->umount_begin)
		lower_sb->s_op->umount_begin(lower_sb);
}

const struct super_operations sgfs_sops = {
	.put_super	= sgfs_put_super,
	.statfs		= sgfs_statfs,
	.remount_fs	= sgfs_remount_fs,
	.evict_inode	= sgfs_evict_inode,
	.umount_begin	= sgfs_umount_begin,
	.show_options	= generic_show_options,
	.alloc_inode	= sgfs_alloc_inode,
	.destroy_inode	= sgfs_destroy_inode,
	.drop_inode	= generic_delete_inode,
};

/* NFS support */

static struct inode *sgfs_nfs_get_inode(struct super_block *sb, u64 ino,
					  u32 generation)
{
	struct super_block *lower_sb;
	struct inode *inode;
	struct inode *lower_inode;

	lower_sb = sgfs_lower_super(sb);
	lower_inode = ilookup(lower_sb, ino);
	inode = sgfs_iget(sb, lower_inode);
	return inode;
}

static struct dentry *sgfs_fh_to_dentry(struct super_block *sb,
					  struct fid *fid, int fh_len,
					  int fh_type)
{
	return generic_fh_to_dentry(sb, fid, fh_len, fh_type,
				    sgfs_nfs_get_inode);
}

static struct dentry *sgfs_fh_to_parent(struct super_block *sb,
					  struct fid *fid, int fh_len,
					  int fh_type)
{
	return generic_fh_to_parent(sb, fid, fh_len, fh_type,
				    sgfs_nfs_get_inode);
}

/*
 * all other funcs are default as defined in exportfs/expfs.c
 */

const struct export_operations sgfs_export_ops = {
	.fh_to_dentry	   = sgfs_fh_to_dentry,
	.fh_to_parent	   = sgfs_fh_to_parent
};
