/*
 * t7_cfi_vtable.c
 * CFI (Control-Flow Integrity) bypass test target.
 * Simulates a C++ vtable corruption vulnerability.
 *
 * Compile (GCC — CFI simulation via function pointer):
 *   gcc -o ../bins/t7_cfi_vtable t7_cfi_vtable.c \
 *       -fno-stack-protector -no-pie -z execstack -w
 *
 * For real Clang CFI (requires clang):
 *   clang -o ../bins/t7_cfi_vtable_cfi t7_cfi_vtable.c \
 *       -fsanitize=cfi -flto -fno-stack-protector -fvisibility=default -w
 *
 * Vulnerability:
 *   A function pointer stored on the heap (simulating a vtable entry)
 *   is overwritten via an out-of-bounds write. The attacker controls
 *   which function is called. Target for CFI valid-target pivoting.
 *
 * Technique: CFI forward-edge bypass — find a CFI-valid function whose
 *   start address is useful (e.g. win(), system()).  Redirect the vtable
 *   entry to that valid target address.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

/* Simulated vtable entry: a function pointer */
typedef struct {
    char   name[48];        /* buffer — overflow here overwrites fn */
    void (*dispatch)(int);  /* "vtable" function pointer           */
} Handler;

void win(int fd) {
    char msg[] = "CFI_BYPASS_SUCCESS\n";
    write(fd, msg, sizeof(msg) - 1);
}

void default_handler(int fd) {
    char msg[] = "OK\n";
    write(fd, msg, 3);
}

void vuln(int fd) {
    Handler *h = malloc(sizeof(Handler));
    h->dispatch = default_handler;

    /* Read into name[48] — allows overwriting dispatch pointer */
    int n = read(fd, h->name, 256);   /* VULN: overflow into fn ptr */
    (void)n;
    h->dispatch(fd);   /* CFI checks this indirect call target */
    free(h);
}

int main(void) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1, c;
    struct sockaddr_in a = {0};
    a.sin_family      = AF_INET;
    a.sin_port        = htons(14447);
    a.sin_addr.s_addr = INADDR_ANY;

    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    bind(s, (struct sockaddr *)&a, sizeof(a));
    listen(s, 1);

    while ((c = accept(s, NULL, NULL)) != -1) {
        vuln(c);
        close(c);
    }
    close(s);
    return 0;
}
