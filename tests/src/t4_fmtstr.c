/*
 * t4_fmtstr.c
 * Format string vulnerability — NX on, no canary, no PIE, no RELRO
 *
 * Compile:
 *   gcc -o t4_fmtstr t4_fmtstr.c \
 *       -fno-stack-protector -no-pie -z norelro -w
 *
 * Vulnerability:
 *   snprintf(resp, sizeof(resp), buf) uses buf directly as format string.
 *   With %p: stack addresses are leaked back to the caller.
 *   With %n (Partial/No RELRO): a GOT entry can be overwritten → RCE.
 *   The binary echoes the formatted response → perfect oracle.
 *
 * system() is referenced so it appears in PLT (required for GOT overwrite).
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

/* Keep system() in PLT — never actually reached, but essential for the
   format-string GOT-overwrite technique (exit@GOT → system@PLT). */
__attribute__((used)) static void _pull_system(void) { system(""); }

void vuln(int fd) {
    char buf[256];
    char resp[512];
    int n = read(fd, buf, 255);
    buf[n] = '\0';
    int l = snprintf(resp, sizeof(resp), buf);   /* VULN: format string */
    write(fd, resp, l);
}

int main(void) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    struct sockaddr_in a = {0};
    a.sin_family      = AF_INET;
    a.sin_port        = htons(14444);
    a.sin_addr.s_addr = INADDR_ANY;

    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    bind(s, (struct sockaddr *)&a, sizeof(a));
    listen(s, 1);

    int c = accept(s, NULL, NULL);
    vuln(c);
    close(c);
    close(s);
    return 0;
}
