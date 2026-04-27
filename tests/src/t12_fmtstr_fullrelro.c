/* t12_fmtstr_fullrelro  port 14452
   Stack overflow with Full RELRO (GOT read-only).
   win() exists — ret2win works without touching GOT.
   Compile: gcc -o t12_fmtstr_fullrelro t12_fmtstr_fullrelro.c
            -fno-stack-protector -no-pie -z relro -z now -w */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

/* pull in system so it appears in plt/got (tests Full RELRO detection) */
__attribute__((used)) static void _pull(void) { system(""); }

void win(void) { write(1, "PWNED\n", 6); }

void vuln(void) {
    char buf[64];
    read(0, buf, 512);
    write(1, buf, 4);
}

int main(void) { vuln(); return 0; }
