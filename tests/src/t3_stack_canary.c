/* t3_stack_canary — canary on, NX on, no PIE.  Port 14443.
   Single-phase: read overflow → canary check → crash or return.
   BinSmasher brute-forces canary byte-by-byte via socat-fork server.
   Compile: gcc -o t3_stack_canary t3_stack_canary.c -fstack-protector-all -no-pie -w */
#include <unistd.h>
void win(void) { write(1, "PWNED\n", 6); }
void vuln(void) {
    char buf[64];
    read(0, buf, 512);   /* VULN: overflow, canary protects ret addr */
    write(1, buf, 4);    /* response ONLY when canary is intact */
}
int main(void) { vuln(); return 0; }
