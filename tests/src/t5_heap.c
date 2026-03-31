/*
 * t5_heap.c
 * Heap overflow — desbordamiento de heap con sobreescritura de puntero a función
 *
 * Compile:
 *   gcc -o t5_heap t5_heap.c \
 *       -fno-stack-protector -no-pie -z execstack -w
 *
 * Vulnerability:
 *   Obj tiene name[32] seguido de fn (puntero a función).
 *   memcpy copia hasta 255 bytes desde buf → overflows name[] e
 *   sobreescribe fn con la dirección que el atacante envíe.
 *   Al llamar o->fn() se ejecuta el puntero controlado.
 *
 * Técnica de explotación:
 *   Enviar 32 bytes de relleno + 8 bytes con la dirección de win()
 *   (o cualquier gadget/función) → RCE inmediato sin ASLR.
 */

#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

typedef struct {
    char   name[32];
    void (*fn)(void);
} Obj;

void win(void)  { write(1, "pwned!\n", 7); }
void noop(void) {}

void vuln(int fd) {
    Obj  *o   = malloc(sizeof(Obj));
    o->fn     = noop;
    char buf[64];
    int  n    = read(fd, buf, 255);   /* VULN: n puede superar sizeof(name) */
    memcpy(o->name, buf, n);          /* VULN: overflows fn pointer */
    o->fn();
    free(o);
}

int main(void) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    struct sockaddr_in a = {0};
    a.sin_family      = AF_INET;
    a.sin_port        = htons(14445);
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
