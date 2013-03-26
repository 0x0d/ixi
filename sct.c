#include "sct.h"
#include "utils.h"

/*
 * Get system call table address if x86, or 32-bit system call table emulation address if x86_64
 */

#if defined(__i386__) || defined(CONFIG_IA32_EMULATION)
#ifdef __i386__
void *get_sys_call_table(void)
#elif defined(__x86_64__)
void *get_ia32_sys_call_table(void)
#endif
{
    #define OFFSET_SYSCALL 150

    struct idtr idtr;
    struct idt_descriptor idtd;
    void *system_call;
    void *retval;
    char sc_asm[OFFSET_SYSCALL];

    #ifdef __i386__
    dbgprint("get sys_call_table using idtr\n");
    #elif defined(__x86_64__)
    dbgprint("get ia32_sys_call_table using idtr\n");
    #endif

    asm volatile("sidt %0" : "=m"(idtr));

    dbgprint("idtr base at 0x%p\n", (void *)idtr.base);

    // Read in IDT for vector 0x80 (syscall) 
    memcpy(&idtd, (void *) idtr.base + (sizeof(idtd) * 0x80), sizeof(idtd));

    dbgprint("idt80: type_flags=%X selector=%X offset_low=%x offset_high=%X\n", (unsigned) idtd.type_flags, (unsigned) idtd.selector, (unsigned) idtd.offset_low, (unsigned) idtd.offset_high);

    #ifdef __i386__
    system_call = (void *) ((idtd.offset_high<<16) | idtd.offset_low);
    #elif defined(__x86_64__)
    system_call = (void *) (((long)idtd.offset_high<<32) | (idtd.offset_middle<<16) | idtd.offset_low);
    #endif

    #ifdef __i386__
    dbgprint("system_call addr: 0x%p\n", system_call);
    #elif defined(__x86_64__)
    dbgprint("ia32_system_call addr: 0x%p\n", system_call);
    #endif

    // we have syscall routine address now, look for syscall table dispatch (indirect call) 
    memcpy(sc_asm, system_call, OFFSET_SYSCALL);

    /**
    * ia32_call > ia32_tracesys > ia32_do_syscall > 'call *ia32_sys_call_table(,%rax,8)'
    * Find callq *ia32_sys_call_table(,%rax,8)
    *
    * (gdb) disassemble ia32_syscall
    * Dump of assembler code for function ia32_syscall:
    * 0xffffffff81066b98 <ia32_syscall+0>:    swapgs
    * 0xffffffff81066b9b <ia32_syscall+3>:    sti
    * 0xffffffff81066b9c <ia32_syscall+4>:    mov    %eax,%eax
    * 0xffffffff81066b9e <ia32_syscall+6>:    push   %rax
    * 0xffffffff81066b9f <ia32_syscall+7>:    cld
    * 0xffffffff81066ba0 <ia32_syscall+8>:    sub    $0x48,%rsp
    * 0xffffffff81066ba4 <ia32_syscall+12>:   mov    %rdi,0x40(%rsp)
    * 0xffffffff81066ba9 <ia32_syscall+17>:   mov    %rsi,0x38(%rsp)
    * 0xffffffff81066bae <ia32_syscall+22>:   mov    %rdx,0x30(%rsp)
    * 0xffffffff81066bb3 <ia32_syscall+27>:   mov    %rcx,0x28(%rsp)
    * 0xffffffff81066bb8 <ia32_syscall+32>:   mov    %rax,0x20(%rsp)
    * 0xffffffff81066bbd <ia32_syscall+37>:   mov    %gs:0x10,%r10
    * 0xffffffff81066bc6 <ia32_syscall+46>:   sub    $0x1fd8,%r10
    * 0xffffffff81066bcd <ia32_syscall+53>:   orl    $0x2,0x14(%r10)
    * 0xffffffff81066bd2 <ia32_syscall+58>:   testl  $0x181,0x10(%r10)
    * 0xffffffff81066bda <ia32_syscall+66>:   jne    0xffffffff81066c04 <ia32_tracesys>
    * End of assembler dump.
    *
    * (gdb) disassemble ia32_tracesys
    * Dump of assembler code for function ia32_tracesys:
    * 0xffffffff81066c04 <ia32_tracesys+0>:   sub    $0x30,%rsp
    * 0xffffffff81066c08 <ia32_tracesys+4>:   mov    %rbx,0x28(%rsp)
    * 0xffffffff81066c0d <ia32_tracesys+9>:   mov    %rbp,0x20(%rsp)
    * 0xffffffff81066c12 <ia32_tracesys+14>:  mov    %r12,0x18(%rsp)
    * 0xffffffff81066c17 <ia32_tracesys+19>:  mov    %r13,0x10(%rsp)
    * 0xffffffff81066c1c <ia32_tracesys+24>:  mov    %r14,0x8(%rsp)
    * 0xffffffff81066c21 <ia32_tracesys+29>:  mov    %r15,(%rsp)
    * 0xffffffff81066c25 <ia32_tracesys+33>:  movq   $0xffffffffffffffda,0x50(%rsp)
    * 0xffffffff81066c2e <ia32_tracesys+42>:  mov    %rsp,%rdi
    * 0xffffffff81066c31 <ia32_tracesys+45>:  callq  0xffffffff81073a02 <syscall_trace_enter>
    * 0xffffffff81066c36 <ia32_tracesys+50>:  mov    0x30(%rsp),%r11
    * 0xffffffff81066c3b <ia32_tracesys+55>:  mov    0x38(%rsp),%r10
    * 0xffffffff81066c40 <ia32_tracesys+60>:  mov    0x40(%rsp),%r9
    * 0xffffffff81066c45 <ia32_tracesys+65>:  mov    0x48(%rsp),%r8
    * 0xffffffff81066c4a <ia32_tracesys+70>:  mov    0x58(%rsp),%rcx
    * 0xffffffff81066c4f <ia32_tracesys+75>:  mov    0x60(%rsp),%rdx
    * 0xffffffff81066c54 <ia32_tracesys+80>:  mov    0x68(%rsp),%rsi
    * 0xffffffff81066c59 <ia32_tracesys+85>:  mov    0x70(%rsp),%rdi
    * 0xffffffff81066c5e <ia32_tracesys+90>:  mov    0x78(%rsp),%rax
    * 0xffffffff81066c63 <ia32_tracesys+95>:  mov    (%rsp),%r15
    * 0xffffffff81066c67 <ia32_tracesys+99>:  mov    0x8(%rsp),%r14
    * 0xffffffff81066c6c <ia32_tracesys+104>: mov    0x10(%rsp),%r13
    * 0xffffffff81066c71 <ia32_tracesys+109>: mov    0x18(%rsp),%r12
    * 0xffffffff81066c76 <ia32_tracesys+114>: mov    0x20(%rsp),%rbp
    * 0xffffffff81066c7b <ia32_tracesys+119>: mov    0x28(%rsp),%rbx
    * 0xffffffff81066c80 <ia32_tracesys+124>: add    $0x30,%rsp
    * 0xffffffff81066c84 <ia32_tracesys+128>: jmpq   0xffffffff81066bdc <ia32_do_syscall>
    * End of assembler dump.
    *
    * (gdb) disassemble ia32_do_syscall
    * Dump of assembler code for function ia32_do_syscall:
    * 0xffffffff81066bdc <ia32_do_syscall+0>: cmp    $0x13d,%eax
    * 0xffffffff81066be1 <ia32_do_syscall+5>: ja     0xffffffff81066c89 <ia32_badsys>
    * 0xffffffff81066be7 <ia32_do_syscall+11>:        mov    %edi,%r8d
    * 0xffffffff81066bea <ia32_do_syscall+14>:        mov    %ebp,%r9d
    * 0xffffffff81066bed <ia32_do_syscall+17>:        xchg   %ecx,%esi
    * 0xffffffff81066bef <ia32_do_syscall+19>:        mov    %ebx,%edi
    * 0xffffffff81066bf1 <ia32_do_syscall+21>:        mov    %edx,%edx
    * 0xffffffff81066bf3 <ia32_do_syscall+23>:        callq  *0xffffffff812e7c70(,%rax,8)
    * End of assembler dump.
    *
    * (gdb) x/xw ia32_do_syscall+23
    * 0xffffffff81066bf3 <ia32_do_syscall+23>:        0x70c514ff
    * (gdb)
    *
    */


    #ifdef __i386__
    // search opcode of `call sys_call_table(,%eax,4)'
    retval = memmem(sc_asm, OFFSET_SYSCALL, "\xff\x14\x85", 3);
    #elif defined(__x86_64__)
    // search opcode of `call ia32_sys_call_table(,%rax,8)'
    retval = memmem(sc_asm, OFFSET_SYSCALL, "\xff\x14\xc5", 3);
    #endif
    if (retval != NULL) {
        #ifdef __i386__
        retval = *((void**)(retval+3));
        dbgprint("sys_call_table addr: 0x%p\n", retval);
        #elif defined(__x86_64__)
        retval = (void *) (0xffffffff00000000 | *((unsigned long*) (retval+3)));
        dbgprint("ia32_sys_call_table addr: 0x%p\n", retval);
        #endif
    } else {
        retval = NULL;
        #ifdef __i386__
        dbgprint("fail to get sys_call_table address using idt\n");
        #elif defined(__x86_64__)
        dbgprint("fail to get ia32_sys_call_table address using idt\n");
        #endif
    }

    return retval;
    #undef OFFSET_SYSCALL
}
#endif

/*
 * Get system call table address if x86_64
 */

#ifdef __x86_64__
void *get_sys_call_table(void)
{

    #define OFFSET_SYSCALL 150
    #define IA32_LSTAR  0xc0000082

    void *system_call;
    char sc_asm[OFFSET_SYSCALL];
    int low, high;
    void *retval;

    dbgprint("get sys_call_table using msr\n");

    asm volatile("rdmsr" : "=a" (low), "=d" (high) : "c" (IA32_LSTAR));
    dbgprint("MSR: low=%d high=%d\n", low, high);

    system_call = (void*)(((long)high<<32) | low);
    dbgprint("system_call addr: 0x%p\n", system_call);

    memcpy(sc_asm, system_call, OFFSET_SYSCALL);

    /**
     * Find callq *sys_call_table(,%rax,8) 
     * -------------------------------------
     * (gdb) disassemble system_call
     * Dump of assembler code for function system_call:
     * 0xffffffff81063750 <system_call+0>:     swapgs
     * 0xffffffff81063753 <system_call+3>:     mov    %rsp,%gs:0x18
     * 0xffffffff8106375c <system_call+12>:    mov    %gs:0x10,%rsp
     * 0xffffffff81063765 <system_call+21>:    sti
     * 0xffffffff81063766 <system_call+22>:    sub    $0x50,%rsp
     * 0xffffffff8106376a <system_call+26>:    mov    %rdi,0x40(%rsp)
     * 0xffffffff8106376f <system_call+31>:    mov    %rsi,0x38(%rsp)
     * 0xffffffff81063774 <system_call+36>:    mov    %rdx,0x30(%rsp)
     * 0xffffffff81063779 <system_call+41>:    mov    %rax,0x20(%rsp)
     * 0xffffffff8106377e <system_call+46>:    mov    %r8,0x18(%rsp)
     * 0xffffffff81063783 <system_call+51>:    mov    %r9,0x10(%rsp)
     * 0xffffffff81063788 <system_call+56>:    mov    %r10,0x8(%rsp)
     * 0xffffffff8106378d <system_call+61>:    mov    %r11,(%rsp)
     * 0xffffffff81063791 <system_call+65>:    mov    %rax,0x48(%rsp)
     * 0xffffffff81063796 <system_call+70>:    mov    %rcx,0x50(%rsp)
     * 0xffffffff8106379b <system_call+75>:    mov    %gs:0x10,%rcx
     * 0xffffffff810637a4 <system_call+84>:    sub    $0x1fd8,%rcx
     * 0xffffffff810637ab <system_call+91>:    testl  $0x181,0x10(%rcx)
     * 0xffffffff810637b2 <system_call+98>:    jne    0xffffffff81063889 <tracesys>
     * 0xffffffff810637b8 <system_call+104>:   cmp    $0x117,%rax
     * 0xffffffff810637be <system_call+110>:   ja     0xffffffff8106387b <badsys>
     * 0xffffffff810637c4 <system_call+116>:   mov    %r10,%rcx
     * 0xffffffff810637c7 <system_call+119>:   callq  *0xffffffff812e6d60(,%rax,8)
     * 0xffffffff810637ce <system_call+126>:   mov    %rax,0x20(%rsp)
     * End of assembler dump.
     * (gdb) x/xw system_call+119
     * 0xffffffff810637c7 <system_call+119>:   0x60c514ff
     * (gdb)
     */

    // search opcode of `call sys_call_table(,%rax,8)'
    retval = memmem(sc_asm, OFFSET_SYSCALL, "\xff\x14\xc5", 3);

    if ( retval != NULL ) {
        retval = (void *) (0xffffffff00000000 | *((unsigned long *)(retval+3)));
        dbgprint("sys_call_table addr: 0x%p\n", retval);
    } else {
        retval = NULL;
        dbgprint("fail to get sys_call_table address using msr\n");
    }

    #undef OFFSET_SYSCALL
    return retval;
}
#endif

void *get_sys_call_table_brute(void)
{
    void *ptr, *start_addr, *end_addr;
    unsigned long **scp;
    void *retval;

    dbgprint("get sys_call_table using bruteforce\n");

    start_addr = &mempool_free;
    end_addr = &boot_cpu_data;

    //dbgprint("mempool_free addr: 0x%p, %lu\n", (void *) &mempool_free, (unsigned long) &mempool_free);
    //dbgprint("boot_cpu_data addr: 0x%p, %lu\n", (void *) &boot_cpu_data, (unsigned long) &boot_cpu_data);

    dbgprint("searching from 0x%p to 0x%p\n", (void *) start_addr, (void *) end_addr);

    // get pointer to the end of code section(in my case this is dirty hack, i think that end address is a mempool_free address)
    ptr = start_addr;
    retval = NULL;

    // start search for the end of data section(in my case, end of data section is boot_cpu_data address, lol)
    while (ptr < end_addr) {
        scp = (unsigned long **)ptr;
        // comparing to sys_close address
        if (scp[__NR_close] == (unsigned long *) sys_close) {
            // yeap, we found it
            retval = (void *) scp;
            dbgprint("sys_call_table addr: 0x%p\n", retval);
            break;
        }
        // increase our pointer by pointer size
        ptr += sizeof(void *);
    }

    if(retval == NULL) {
        dbgprint("fail to get sys_call_table address using bruteforce\n");
    }

    return retval;
}

