/*
 * t2_stack_nx.c
 * Stack overflow — NX activado, sin canary, sin PIE
 *
 * Compile:
 *   gcc -o t2_stack_nx t2_stack_nx.c \
 *       -fno-stack-protector -no-pie -w
 *
 * Vulnerability:
 *   Igual que t1 pero con NX — shellcode en stack no ejecutable.
 *   Requiere ret2libc, ret2plt o cadena ROP para explotar.
 */

#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

void handle(int fd) {
    char buf[64];
    read(fd, buf, 512);   /* VULN: overflow */
    write(fd, buf, 8);
}

int main(void) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    struct sockaddr_in a = {0};
    a.sin_family      = AF_INET;
    a.sin_port        = htons(14442);
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
