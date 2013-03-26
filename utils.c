#include "utils.h"

/* man 3 memmem */
void *memmem(const void *haystack, size_t haystack_len, const void *needle, size_t needle_len)
{
    const char *begin;
    const char *const last_possible = (const char *) haystack + haystack_len - needle_len;

    if (needle_len == 0) {
        // The first occurrence of the empty string is deemed to occur at the beginning of the string.
        return (void *) haystack;
    }

    // Sanity check, otherwise the loop might search through the whole memory.
    if (__builtin_expect(haystack_len < needle_len, 0)) {
        return NULL;
    }

    for (begin = (const char *) haystack; begin <= last_possible; ++begin) {
        if (begin[0] == ((const char *) needle)[0] && !memcmp((const void *) &begin[1], (const void *) ((const char *) needle + 1), needle_len - 1)) {
            return (void *) begin;
        }
    }

    return NULL;
}


//PAGE RW HELPERS
void *get_writable_addr(void *s_addr)
{
    struct page *p[2];
    void *sct;
    unsigned long addr = (unsigned long)s_addr & PAGE_MASK;

    if (s_addr == NULL) {
        return NULL;
    }

    #if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,22) && defined(__x86_64__)
    p[0] = pfn_to_page(__pa_symbol(addr) >> PAGE_SHIFT);
    p[1] = pfn_to_page(__pa_symbol(addr + PAGE_SIZE) >> PAGE_SHIFT);
    #else
    p[0] = virt_to_page(addr);
    p[1] = virt_to_page(addr + PAGE_SIZE);
    #endif

    sct = vmap(p, 2, VM_MAP, PAGE_KERNEL);
    if (sct == NULL) {
        return NULL;
    }
    dbgprint("vmap for 0x%p now is: 0x%p\n", s_addr, sct + offset_in_page(s_addr));
    return sct + offset_in_page(s_addr);
}

void clean_writable_addr(void *s_addr)
{
    if (s_addr == NULL) {
        dbgprint("vunmap failed for NULL\n");
        return;
    }
    dbgprint("vunmap for 0x%p\n", s_addr);
    vunmap((void*)((unsigned long)s_addr & PAGE_MASK));
}

void set_addr_rw(void *addr)
{
    unsigned int level;
    pte_t *pte = lookup_address((unsigned long) addr, &level);
    if (pte->pte &~ _PAGE_RW) {
        pte->pte |= _PAGE_RW;
    }
}

void set_addr_ro(void *addr)
{
    unsigned int level;
    pte_t *pte = lookup_address((unsigned long) addr, &level);
    pte->pte = pte->pte &~_PAGE_RW;
}

void set_cr0_rw(void)
{
    write_cr0 (read_cr0 () & (~ 0x10000));
}

void set_cr0_ro(void)
{
    write_cr0 (read_cr0 () | 0x10000);
}

