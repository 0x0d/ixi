#ifndef _SCT_H_
#define _SCT_H_

#include <linux/syscalls.h>
#include <linux/mempool.h>

/*
 * IDT structure, the same for 32 and 64 bit
 */
struct idtr {
    unsigned short limit;
    void * base;
} __attribute__ ((packed));

#ifdef __i386__
/*
 * x86 idt_descriptor 
 */
struct idt_descriptor {
    unsigned short offset_low;
    unsigned short selector;
    unsigned char zero;
    unsigned char type_flags;
    unsigned short offset_high;
} __attribute__ ((packed));

#elif defined(CONFIG_IA32_EMULATION)
/*
 * x86_64 idt descriptor
 * in long mode -- 64bit mode and compatity mode, 
 * every IDT entry has a 16-byte size
 */
struct idt_descriptor {
    unsigned short offset_low;
    unsigned short selector;
    unsigned char zero1;
    unsigned char type_flags;
    unsigned short offset_middle;
    unsigned int offset_high;
    unsigned int zero2;
} __attribute__ ((packed));

#endif

#if defined(__i386__)
void *get_sys_call_table(void);
#elif defined(__x86_64__)
void *get_ia32_sys_call_table(void);
void *get_sys_call_table(void);
#endif

void *get_sys_call_table_brute(void);

#endif
