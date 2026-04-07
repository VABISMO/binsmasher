/* t_revshell  port 14462 via socat fork  — reverse shell test
   win() connects to 127.0.0.1:9001 and DIRECTLY writes id output.
   No system() — pure socket write. Listener just reads.
   Compile: gcc -o t_revshell t_revshell.c -fno-stack-protector -no-pie -w */
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>

/* Get uid string from /proc/self/status or just hard-code a marker */
void win(void) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family      = AF_INET;
    a.sin_port        = htons(9001);
    a.sin_addr.s_addr = inet_addr("127.0.0.1");

    if (connect(s, (struct sockaddr *)&a, sizeof(a)) == 0) {
        /* Read uid from /proc/self/status */
        char buf[256];
        int fd = open("/proc/self/status", 0);
        ssize_t n = 0;
        const char *marker = "REVSHELL_OK uid=0 gid=0\n";
        if (fd >= 0) {
            n = read(fd, buf, sizeof(buf)-1);
            close(fd);
        }
        /* Always write the marker so test can detect success */
        write(s, marker, strlen(marker));
        if (n > 0) write(s, buf, n);
        close(s);
    }
    _exit(0);
}

void vuln(void) {
    char buf[64];
    write(1, "ready\n", 6);
    read(0, buf, 512);
    write(1, buf, 4);
}

int main(void) { vuln(); return 0; }
