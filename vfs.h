#ifndef _VFS_H_
#define _VFS_H_

#include <linux/fs.h>

/* from /include/linux/fs.h struct file_operations */
typedef int (*readdir_t)(struct file *, void *, filldir_t);

int patch_vfs_readdir(const char *, readdir_t *, readdir_t);
int unpatch_vfs_readdir(const char *, readdir_t);

#endif
