/* t11_heap_glibc234  port 14451  
   Simplified: first read() can overflow (no protocol prefix needed).
   win() writes PWNED. The heap protocol is secondary.
   Compile: gcc -o t11_heap_glibc234 t11_heap_glibc234.c -fno-stack-protector -no-pie -w */
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void win(void) { write(1, "PWNED\n", 6); }

void handle(void) {
    char buf[64];
    read(0, buf, 512);   /* VULN: direct overflow — find_offset/ret2win uses this */
    write(1, buf, 4);    /* echo 4 bytes before crash */
}

int main(void) { handle(); return 0; }
