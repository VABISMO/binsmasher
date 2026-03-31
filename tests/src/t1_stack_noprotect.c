/*
 * t1_stack_noprotect.c
 * Stack overflow — sin ninguna protección (NX off, sin canary, sin PIE)
 *
 * Compile:
 *   gcc -o t1_stack_noprotect t1_stack_noprotect.c \
 *       -z execstack -fno-stack-protector -no-pie -w
 *
 * Vulnerability:
 *   read() acepta hasta 512 bytes pero buf solo tiene 64 → desbordamiento
 *   directo, stack ejecutable, ret addr sobreescribible sin obstáculos.
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
    a.sin_port        = htons(14441);
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
