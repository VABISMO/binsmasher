/*
 * t9_stripped.c
 * Stripped binary analysis test target.
 * Compiled without symbols — tests radare2/angr/prologue recovery.
 *
 * Compile:
 *   gcc -o ../bins/t9_stripped t9_stripped.c \
 *       -fno-stack-protector -no-pie -s -w
 *   # -s strips all symbols
 *   strip --strip-all ../bins/t9_stripped
 *
 * Vulnerability:
 *   Stack overflow via read(). No symbol table — static analysis must
 *   recover function addresses via prologue patterns or FLIRT signatures.
 *
 * Technique tested:
 *   BinSmasher recover_functions_stripped():
 *     - radare2 FLIRT (aac, aan) → identifies library functions
 *     - prologue scan (push rbp; mov rbp,rsp pattern) → finds function starts
 *     - angr CFGFast → full CFG recovery (optional)
 */

#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <stdlib.h>

/* Multiple functions to give the prologue scanner something to find */
static void respond_ok(int fd) {
    write(fd, "OK\n", 3);
}

static void process_input(int fd) {
    char buf[96];
    read(fd, buf, 512);   /* VULN: overflow */
    respond_ok(fd);
}

static void setup_and_serve(int port) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1, c;
    struct sockaddr_in a = {0};
    a.sin_family      = AF_INET;
    a.sin_port        = htons((unsigned short)port);
    a.sin_addr.s_addr = INADDR_ANY;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    bind(s, (struct sockaddr *)&a, sizeof(a));
    listen(s, 1);
    while ((c = accept(s, NULL, NULL)) != -1) {
        process_input(c);
        close(c);
    }
    close(s);
}

int main(void) {
    setup_and_serve(14449);
    return 0;
}
