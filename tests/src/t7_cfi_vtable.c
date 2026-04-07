/* t7_cfi_vtable — heap vtable fn-ptr. Port 14447.
   Compile: gcc -o t7_cfi_vtable t7_cfi_vtable.c -fno-stack-protector -no-pie -w */
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
typedef struct { char name[48]; void (*dispatch)(void); } Handler;
void win(void)             { write(1, "PWNED\n", 6); }
void default_handler(void) { write(1, "OK\n",    3); }
void vuln(void) {
    Handler *h = malloc(sizeof(Handler)); h->dispatch = default_handler;
    int n = read(0, h->name, 256); (void)n; /* VULN */
    h->dispatch();
    free(h);
}
int main(void) { vuln(); return 0; }
