#include <stdio.h>

/*
 * Assembly optimized check for zeroes filled memory, based on:
 * http://stackoverflow.com/questions/2589736/fast-way-to-check-if-an-array-of-chars-is-zero
 */

#if __x86_64__
int checkzero(void *p, int len)
{
    int is_zero;
    __asm__ (
        "cld\n"
        "xorb %%al, %%al\n"
        "repz scasb\n"
        : "=c" (is_zero)
        : "c" (len), "D" (p)
        : "eax", "cc"
    );
    return !is_zero;
}
#else
int checkzero (void *p, int len)
{
    char *cp = (char *)p;

    while (len--) {
        if (*cp++) return 0;
    }
    return 1;
}
#endif
