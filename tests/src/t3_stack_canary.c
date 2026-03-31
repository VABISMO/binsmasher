/*
 * t3_stack_canary.c
 * Stack overflow — stack ejecutable + canary activo, sin PIE
 *
 * Compile:
 *   gcc -o t3_stack_canary t3_stack_canary.c \
 *       -z execstack -fstack-protector-all -no-pie -w
 *
 * Vulnerability:
 *   Overflow disponible pero el canary detecta la corrupción y llama
 *   __stack_chk_fail antes de llegar al ret.
 *   Requiere leak del canary (format string o brute-force) para explotar.
 */

#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

void handle(int fd) {
    char buf[64];
    read(fd, buf, 512);   /* VULN: overflow — canary lo detecta */
    write(fd, buf, 8);
}

int main(void) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    struct sockaddr_in a = {0};
    a.sin_family      = AF_INET;
    a.sin_port        = htons(14443);
    a.sin_addr.s_addr = INADDR_ANY;

    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    bind(s, (struct sockaddr *)&a, sizeof(a));
    listen(s, 1);

    int c = accept(s, NULL, NULL);
    handle(c);
    close(c);
    close(s);
    return 0;
}
