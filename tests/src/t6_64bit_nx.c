/*
 * t6_64bit_nx.c
 * Stack overflow 64-bit — unbounded read(), NX on, no canary, no PIE
 *
 * Compile:
 *   gcc -o t6_64bit_nx t6_64bit_nx.c \
 *       -fno-stack-protector -no-pie -w
 *
 * Vulnerability:
 *   read(fd, buf, 512) copies up to 512 bytes into a 128-byte buffer.
 *   NX enabled: shellcode on stack won't execute.
 *   Requires ROP chain — ret2libc (pop rdi; ret → system("/bin/sh")).
 *
 * Note: intentionally uses read() instead of gets() because gets() was
 *       removed from glibc headers in newer versions (gcc >= 14 errors).
 *       The vulnerability is identical: no length check on user input.
 */

#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

void process(int fd) {
    char buf[128];
    read(fd, buf, 512);           /* VULN: 512 bytes into 128-byte buf */
    write(fd, buf, strlen(buf));
}

int main(void) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    struct sockaddr_in a = {0};
    a.sin_family      = AF_INET;
    a.sin_port        = htons(14446);
    a.sin_addr.s_addr = INADDR_ANY;

    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    bind(s, (struct sockaddr *)&a, sizeof(a));
    listen(s, 1);

    int c = accept(s, NULL, NULL);
    process(c);
    close(c);
    close(s);
    return 0;
}
