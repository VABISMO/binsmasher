/* t1_stack_noprotect — NX off, no canary, no PIE. Port 14441.
   win() writes PWNED to stdout (socat sends back over TCP).
   Compile: gcc -o t1_stack_noprotect t1_stack_noprotect.c -z execstack -fno-stack-protector -no-pie -w */
#include <unistd.h>
#include <stdlib.h>
void win(void) { write(1, "PWNED\n", 6); }
void vuln(void) { char buf[64]; read(0, buf, 512); write(1, buf, 4); }
int main(void) { vuln(); return 0; }
