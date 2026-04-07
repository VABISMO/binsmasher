/* t9_stripped — stripped binary, no symbols. Port 14449.
   Compile: gcc -o t9_stripped t9_stripped.c -fno-stack-protector -no-pie -w -s
   strip --strip-all t9_stripped */
#include <unistd.h>
static void internal_win(void) { write(1, "PWNED\n", 6); }
static void process_input(void) { char buf[96]; read(0, buf, 512); internal_win(); }
int main(void) { process_input(); return 0; }
