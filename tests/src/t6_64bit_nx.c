/* t6_64bit_nx — 64-bit NX on, no canary, no PIE. Port 14446.
   Fixed write(4 bytes) so crash is detected as empty/truncated response.
   Compile: gcc -o t6_64bit_nx t6_64bit_nx.c -fno-stack-protector -no-pie -w */
#include <unistd.h>
void win(void) { write(1, "PWNED\n", 6); }
void process(void) {
    char buf[128];
    read(0, buf, 512);   /* VULN: 512 into 128-byte buf */
    write(1, buf, 4);    /* echo 4 bytes then crash on ret */
}
int main(void) { process(); return 0; }
