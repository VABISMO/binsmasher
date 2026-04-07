/* t2_stack_nx — NX on, no canary, no PIE. Port 14442.
   Compile: gcc -o t2_stack_nx t2_stack_nx.c -fno-stack-protector -no-pie -w */
#include <unistd.h>
void win(void) { write(1, "PWNED\n", 6); }
void vuln(void) { char buf[64]; read(0, buf, 512); write(1, buf, 4); }
int main(void) { vuln(); return 0; }
