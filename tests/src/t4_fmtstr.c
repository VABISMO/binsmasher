/* t4_fmtstr  port 14444  — format string + stack overflow
   The format string oracle leaks addresses. The stack overflow wins.
   Compile: gcc -o t4_fmtstr t4_fmtstr.c -fno-stack-protector -no-pie -z norelro -w */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
__attribute__((used)) static void _pull(void) { system(""); }
void win(void) { write(1, "PWNED\n", 6); }
void vuln(void) {
    char buf[64];
    read(0, buf, 512);   /* VULN: overflow — 512 into 64 */
    write(1, buf, 4);    /* echo 4 bytes — crash on ret   */
}
int main(void) { vuln(); return 0; }
