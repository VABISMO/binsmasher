/*
 * t8_seccomp.c
 * seccomp-bpf bypass test target.
 * Installs a strict seccomp filter, then has a stack overflow.
 *
 * Compile:
 *   gcc -o ../bins/t8_seccomp t8_seccomp.c \
 *       -fno-stack-protector -no-pie -w -lseccomp
 *
 * If libseccomp not available:
 *   gcc -o ../bins/t8_seccomp t8_seccomp.c \
 *       -fno-stack-protector -no-pie -w -DNO_SECCOMP
 *
 * Vulnerability:
 *   read() overflow into return address. The seccomp filter blocks execve,
 *   execveat and many other syscalls. A working exploit must use only
 *   the ALLOWED syscalls: read, write, open, close, exit, mmap.
 *
 * Bypass technique:
 *   Build a ROP chain using only the allowed syscalls:
 *     open("/flag") → read(fd, buf) → write(1, buf) → exit(0)
 *   OR use SROP (sigreturn) which is itself a allowed syscall on many kernels.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <sys/prctl.h>

#ifndef NO_SECCOMP
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <sys/syscall.h>

static void install_seccomp(void) {
    /* Allow: read(0), write(1), open(2), close(3), exit(60),
     *        mmap(9), munmap(11), sigreturn(15), exit_group(231)
     * Kill everything else.
     */
    struct sock_filter filter[] = {
        /* Load syscall number */
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 (offsetof(struct seccomp_data, nr))),
        /* Allow list */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_read,         10, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_write,         9, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_open,          8, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_close,         7, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_exit,          6, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_mmap,          5, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_munmap,        4, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_rt_sigreturn,  3, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_exit_group,    2, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_brk,           1, 0),
        /* Kill — execve and everything else */
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL),
        /* Allow */
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog prog = {
        .len    = sizeof(filter) / sizeof(filter[0]),
        .filter = filter,
    };
    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog);
}
#else
static void install_seccomp(void) { /* no-op */ }
#endif

void handle(int fd) {
    char buf[64];
    install_seccomp();        /* filter active before overflow */
    read(fd, buf, 512);       /* VULN: overflow */
    write(fd, buf, 4);
}

int main(void) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1, c;
    struct sockaddr_in a = {0};
    a.sin_family      = AF_INET;
    a.sin_port        = htons(14448);
    a.sin_addr.s_addr = INADDR_ANY;

    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    bind(s, (struct sockaddr *)&a, sizeof(a));
    listen(s, 1);

    while ((c = accept(s, NULL, NULL)) != -1) {
        handle(c);
        close(c);
    }
    close(s);
    return 0;
}
