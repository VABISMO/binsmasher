/* t15_canary_fmtstr  port 14455 — canary leak via banner + stack overflow.
   Protocol: connect → read COOKIE:0x<canary16>\n → send exploit payload → PWNED.
   BinSmasher reads canary from banner, sends overflow with correct canary.
   Single TCP read — standard _send_recv compatible.
   Compile: gcc -o t15_canary_fmtstr t15_canary_fmtstr.c -fstack-protector-all -no-pie -w */
#include <stdint.h>
#include <unistd.h>
#include <stdio.h>

void win(void) { write(1, "PWNED\n", 6); }

void vuln(void) {
    char buf[64];

    /* Leak canary in banner before reading user input */
    uint64_t cookie;
    __asm__ volatile ("mov %%fs:0x28, %0" : "=r"(cookie));
    char banner[48];
    int bn = snprintf(banner, sizeof(banner), "COOKIE:0x%016lx\n", cookie);
    write(1, banner, bn);

    /* Single VULN read — overflows buf[64]; canary at buf+72 */
    read(0, buf, 512);
    write(1, buf, 4);   /* echo 4 bytes (response received before canary check) */
}

int main(void) { vuln(); return 0; }
