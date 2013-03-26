#ifndef _UTILS_H_
#define _UTILS_H_

#include <linux/module.h>
#include <linux/version.h>
#include <linux/mm.h>
#include <linux/mm_types.h>

#include "config.h"

#ifdef I_DEBUG
    #define dbgprint(format,args...) printk(PKPRE "function:%s-L%d: "format, __FUNCTION__, __LINE__, ##args);
#else
    #define dbgprint(format,args...) do {} while(0);
#endif


void *memmem(const void *, size_t, const void *, size_t);
void *get_writable_addr(void *);
void clean_writable_addr(void *);

/*
void set_addr_rw(void *);
void set_addr_ro(void *);
*/

void set_cr0_rw(void);
void set_cr0_ro(void);

#endif
