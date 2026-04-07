/* t8_seccomp — NX on, stack overflow, execve blocked. Port 14448.
   Compile: gcc -o t8_seccomp t8_seccomp.c -fno-stack-protector -no-pie -w */
#include <unistd.h>
void win(void) { write(1, "PWNED\n", 6); }
void handle(void) { char buf[64]; read(0, buf, 512); write(1, buf, 4); }
int main(void) { handle(); return 0; }
