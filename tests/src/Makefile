# BinSmasher — tests/src/Makefile
# Compiles all 11 vulnerable test binaries (6 original + 5 advanced)
#
# Usage:
#   cd tests/src && make          → compile all
#   cd tests/src && make clean    → remove binaries
#   cd tests/src && make t7       → single target

CC     = gcc
OUTDIR = ../bins
CFLAGS = -w

.PHONY: all clean advanced t1 t2 t3 t4 t5 t6 t7 t8 t9 t10 t11

all: $(OUTDIR) t1 t2 t3 t4 t5 t6 t7 t8 t9 t10 t11
	@echo "" && echo "All 11 binaries compiled in $(OUTDIR)/"

advanced: $(OUTDIR) t7 t8 t9 t10 t11

$(OUTDIR):
	mkdir -p $(OUTDIR)

# ── Original 6 ──────────────────────────────────────────────────────────────
t1: $(OUTDIR)/t1_stack_noprotect
$(OUTDIR)/t1_stack_noprotect: t1_stack_noprotect.c
	$(CC) -o $@ $< $(CFLAGS) -z execstack -fno-stack-protector -no-pie
	@echo "  t1 NX=off canary=off"

t2: $(OUTDIR)/t2_stack_nx
$(OUTDIR)/t2_stack_nx: t2_stack_nx.c
	$(CC) -o $@ $< $(CFLAGS) -fno-stack-protector -no-pie
	@echo "  t2 NX=on canary=off"

t3: $(OUTDIR)/t3_stack_canary
$(OUTDIR)/t3_stack_canary: t3_stack_canary.c
	$(CC) -o $@ $< $(CFLAGS) -z execstack -fstack-protector-all -no-pie
	@echo "  t3 canary=on"

t4: $(OUTDIR)/t4_fmtstr
$(OUTDIR)/t4_fmtstr: t4_fmtstr.c
	$(CC) -o $@ $< $(CFLAGS) -fno-stack-protector -no-pie -z norelro
	@echo "  t4 format-string RELRO=none"

t5: $(OUTDIR)/t5_heap
$(OUTDIR)/t5_heap: t5_heap.c
	$(CC) -o $@ $< $(CFLAGS) -fno-stack-protector -no-pie -z execstack
	@echo "  t5 heap fn-ptr"

t6: $(OUTDIR)/t6_64bit_nx
$(OUTDIR)/t6_64bit_nx: t6_64bit_nx.c
	$(CC) -o $@ $< $(CFLAGS) -fno-stack-protector -no-pie
	@echo "  t6 64-bit NX"

# ── Advanced technique binaries ─────────────────────────────────────────────
t7: $(OUTDIR)/t7_cfi_vtable
$(OUTDIR)/t7_cfi_vtable: t7_cfi_vtable.c
	$(CC) -o $@ $< $(CFLAGS) -fno-stack-protector -no-pie -z execstack
	@echo "  t7 CFI vtable fn-ptr (port 14447)"

t8: $(OUTDIR)/t8_seccomp
$(OUTDIR)/t8_seccomp: t8_seccomp.c
	$(CC) -o $@ $< $(CFLAGS) -fno-stack-protector -no-pie -lseccomp 2>/dev/null \
	  || $(CC) -o $@ $< $(CFLAGS) -fno-stack-protector -no-pie -DNO_SECCOMP
	@echo "  t8 seccomp-bpf filter (port 14448)"

t9: $(OUTDIR)/t9_stripped
$(OUTDIR)/t9_stripped: t9_stripped.c
	$(CC) -o $@ $< $(CFLAGS) -fno-stack-protector -no-pie -s
	strip --strip-all $@ 2>/dev/null || true
	@echo "  t9 stripped binary (port 14449)"

t10: $(OUTDIR)/t10_safestack
$(OUTDIR)/t10_safestack: t10_safestack.c
	$(CC) -o $@ $< $(CFLAGS) -fno-stack-protector -no-pie -z execstack
	@echo "  t10 safestack sim fmt+overflow (port 14450)"

t11: $(OUTDIR)/t11_heap_glibc234
$(OUTDIR)/t11_heap_glibc234: t11_heap_glibc234.c
	$(CC) -o $@ $< $(CFLAGS) -fno-stack-protector -no-pie
	@echo "  t11 glibc2.34+ heap alloc/free/UAF (port 14451)"

clean:
	rm -f $(addprefix $(OUTDIR)/, t1_stack_noprotect t2_stack_nx t3_stack_canary \
	       t4_fmtstr t5_heap t6_64bit_nx t7_cfi_vtable t8_seccomp t9_stripped \
	       t10_safestack t11_heap_glibc234)
	@echo "All binaries removed."
