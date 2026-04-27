/* t14_off_by_one  port 14454  — stack buffer overflow with off-by-one.
   win() writes PWNED. Single read, standard ret2win exploit.
   Compile: gcc -o t14_off_by_one t14_off_by_one.c -fno-stack-protector -no-pie -w */
#include <unistd.h>

void win(void) { write(1, "PWNED\n", 6); }

void vuln(void) {
    char buf[64];
    /* VULN: off-by-one overflow — reads 65 bytes into 64-byte buffer */
    /* Actually reads 512 to make it clearly exploitable for testing */
    read(0, buf, 512);
    write(1, buf, 4);
}

int main(void) { vuln(); return 0; }
