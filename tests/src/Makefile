CC      = gcc
CFLAGS  = -w -g
OUTDIR  = ../bins

all: $(OUTDIR) t1 t2 t3 t4 t5 t6 t7 t8 t9 t10 t11 tsh trev
	@echo ""
	@echo "All binaries compiled in $(OUTDIR)/"
	@echo "Run tests: python3 tests/realtest.py --local-only"

$(OUTDIR):
	mkdir -p $(OUTDIR)

t1:  t1_stack_noprotect.c
	$(CC) -o $(OUTDIR)/t1_stack_noprotect  $< -z execstack -fno-stack-protector -no-pie $(CFLAGS)
	@echo "  t1_stack_noprotect  NX=off  canary=off  port=14441  win=yes"

t2:  t2_stack_nx.c
	$(CC) -o $(OUTDIR)/t2_stack_nx         $< -fno-stack-protector -no-pie $(CFLAGS)
	@echo "  t2_stack_nx         NX=on   canary=off  port=14442  win=yes"

t3:  t3_stack_canary.c
	$(CC) -o $(OUTDIR)/t3_stack_canary     $< -fstack-protector-all -fno-pie -no-pie $(CFLAGS)
	@echo "  t3_stack_canary     NX=on   canary=ON   port=14443  win=yes (needs canary leak)"

t4:  t4_fmtstr.c
	$(CC) -o $(OUTDIR)/t4_fmtstr           $< -fno-stack-protector -no-pie -z norelro $(CFLAGS)
	@echo "  t4_fmtstr           NX=on   fmtstr      port=14444  win=yes  system@plt"

t5:  t5_heap.c
	$(CC) -o $(OUTDIR)/t5_heap             $< -fno-stack-protector -no-pie $(CFLAGS)
	@echo "  t5_heap             NX=on   heap fnptr  port=14445  win=yes"

t6:  t6_64bit_nx.c
	$(CC) -o $(OUTDIR)/t6_64bit_nx         $< -fno-stack-protector -no-pie $(CFLAGS)
	@echo "  t6_64bit_nx         NX=on   canary=off  port=14446  win=yes"

t7:  t7_cfi_vtable.c
	$(CC) -o $(OUTDIR)/t7_cfi_vtable       $< -fno-stack-protector -no-pie $(CFLAGS)
	@echo "  t7_cfi_vtable       NX=on   vtable fnp  port=14447  win=yes"

t8:  t8_seccomp.c
	$(CC) -o $(OUTDIR)/t8_seccomp          $< -fno-stack-protector -no-pie $(CFLAGS)
	@echo "  t8_seccomp          NX=on   no-canary   port=14448  win=yes"

t9:  t9_stripped.c
	$(CC) -o $(OUTDIR)/t9_stripped         $< -fno-stack-protector -no-pie -s $(CFLAGS)
	strip --strip-all $(OUTDIR)/t9_stripped
	@echo "  t9_stripped         NX=on   stripped    port=14449  (WARN expected)"

t10: t10_safestack.c
	$(CC) -o $(OUTDIR)/t10_safestack       $< -fno-stack-protector -no-pie $(CFLAGS)
	@echo "  t10_safestack       NX=on   fmtoracle   port=14450  win=yes"

t11: t11_heap_glibc234.c
	$(CC) -o $(OUTDIR)/t11_heap_glibc234   $< -fno-stack-protector -no-pie $(CFLAGS)
	@echo "  t11_heap_glibc234   NX=on   heap proto  port=14451  win=yes"

tsh: t_shellexec.c
	$(CC) -o $(OUTDIR)/t_shellexec         $< -fno-stack-protector -no-pie $(CFLAGS)
	@echo "  t_shellexec         CMD test            port=14461  win->system(id)"

trev: t_revshell.c
	$(CC) -o $(OUTDIR)/t_revshell          $< -fno-stack-protector -no-pie $(CFLAGS)
	@echo "  t_revshell          REVSHELL test       port=14462  win->connect-back"

clean:
	rm -f $(OUTDIR)/t1_stack_noprotect $(OUTDIR)/t2_stack_nx $(OUTDIR)/t3_stack_canary \
	       $(OUTDIR)/t4_fmtstr $(OUTDIR)/t5_heap $(OUTDIR)/t6_64bit_nx $(OUTDIR)/t7_cfi_vtable \
	       $(OUTDIR)/t8_seccomp $(OUTDIR)/t9_stripped $(OUTDIR)/t10_safestack \
	       $(OUTDIR)/t11_heap_glibc234 $(OUTDIR)/t_shellexec $(OUTDIR)/t_revshell

.PHONY: all clean t1 t2 t3 t4 t5 t6 t7 t8 t9 t10 t11 tsh trev
