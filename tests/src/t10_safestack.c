/*
 * t10_safestack.c
 * SafeStack (LLVM) bypass test target.
 *
 * Compile with LLVM SafeStack:
 *   clang -o ../bins/t10_safestack t10_safestack.c \
 *       -fsanitize=safe-stack -fno-stack-protector -no-pie -w
 *
 * Fallback (GCC, simulates the format-string oracle aspect):
 *   gcc -o ../bins/t10_safestack t10_safestack.c \
 *       -fno-stack-protector -no-pie -z execstack -w
 *
 * Vulnerability:
 *   Two bugs combined:
 *   1. Format string oracle: echoes formatted input back (leaks stack/TLS values)
 *   2. Stack overflow via second read() call
 *
 * SafeStack bypass technique:
 *   Step 1 — send "%p.%p..." to leak the unsafe stack base pointer from TLS
 *   Step 2 — send overflow payload that overwrites the return address in
 *             the SAFE stack (which SafeStack isolates to a separate mmap region)
 *   The unsafe stack base (found via %p walk) points near the safe stack.
 */

#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

void handle(int fd) {
    char fmt_buf[256];
    char overflow_buf[64];
    char resp[512];
    int  n;

    /* Phase 1: format string oracle — leak addresses */
    n = read(fd, fmt_buf, 255);
    fmt_buf[n] = '\0';
    int l = snprintf(resp, sizeof(resp), fmt_buf);  /* VULN: format string */
    write(fd, resp, l);

    /* Phase 2: stack overflow (safe stack return address) */
    read(fd, overflow_buf, 512);   /* VULN: overflow */
    write(fd, "done\n", 5);
}

int main(void) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1, c;
    struct sockaddr_in a = {0};
    a.sin_family      = AF_INET;
    a.sin_port        = htons(14450);
    a.sin_addr.s_addr = INADDR_ANY;

    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    bind(s, (struct sockaddr *)&a, sizeof(a));
    listen(s, 1);

    /* Multi-accept: format string probes need multiple connections */
    while ((c = accept(s, NULL, NULL)) != -1) {
        handle(c);
        close(c);
    }
    close(s);
    return 0;
}
