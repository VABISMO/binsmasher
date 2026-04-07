/* t5_heap — heap fn-ptr overwrite. Port 14445.
   Compile: gcc -o t5_heap t5_heap.c -fno-stack-protector -no-pie -w */
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
typedef struct { char name[32]; void (*fn)(void); } Obj;
void win(void)  { write(1, "PWNED\n", 6); }
void noop(void) { write(1, "OK\n",    3); }
void vuln(void) {
    Obj *o = malloc(sizeof(Obj)); o->fn = noop;
    char buf[64]; int n = read(0, buf, 255);
    memcpy(o->name, buf, n);   /* VULN: overflows fn ptr */
    o->fn();
    free(o);
}
int main(void) { vuln(); return 0; }
