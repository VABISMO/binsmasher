/* t13_heap_menu  port 14453  — heap menu service + direct overflow path.
   Simulates a CTF heap binary with menu but also has a direct buffer overflow
   that BinSmasher can exploit via the standard ret2win path.
   win() exists. BinSmasher sends overflow payload → win() → PWNED.
   Compile: gcc -o t13_heap_menu t13_heap_menu.c -fno-stack-protector -no-pie -w */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_CHUNKS 8
#define MAX_SIZE   256

static void *chunks[MAX_CHUNKS];
static size_t sizes[MAX_CHUNKS];

void win(void) { write(1, "PWNED\n", 6); }

void vuln(void) {
    char buf[64];
    /* VULN: direct overflow before menu — BinSmasher exploits this */
    read(0, buf, 512);
    write(1, buf, 4);
}

static void menu(void) { write(1, "> ", 2); fflush(stdout); }

static int read_int(void) {
    char buf[16];
    if (read(0, buf, 15) <= 0) return -1;
    buf[15] = '\0';
    return atoi(buf);
}

int main(void) {
    /* Direct overflow path — BinSmasher exploits this without menu */
    vuln();
    /* Menu continues for interactive use */
    for (;;) {
        menu();
        int choice = read_int();
        switch (choice) {
            case 5: return 0;
            default: write(1, "?\n", 2); break;
        }
    }
}
