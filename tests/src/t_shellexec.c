/* t_shellexec  port 14461 via socat fork  — CMD exec test
   win() runs system("id; hostname") output goes to stdout (socat→BinSmasher).
   NO banner — BinSmasher sends exploit immediately, gets uid= back.
   Compile: gcc -o t_shellexec t_shellexec.c -fno-stack-protector -no-pie -w */
#include <unistd.h>
#include <stdlib.h>
void win(void) {
    system("/bin/sh -c 'id; hostname'");
    fflush(NULL);
    _exit(0);
}
void vuln(void) {
    char buf[64];
    read(0, buf, 512);   /* overflow */
    write(1, buf, 4);    /* echo 4 bytes before crash */
}
int main(void) { vuln(); return 0; }
