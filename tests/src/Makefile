# BinSmasher — tests/src/Makefile
# Compila todos los binarios vulnerables de prueba
#
# Uso:
#   cd tests/src
#   make          → compila todos en ../bins/
#   make clean    → elimina binarios compilados
#   make t1       → compila solo t1

CC      = gcc
OUTDIR  = ../bins
CFLAGS  = -w

.PHONY: all clean t1 t2 t3 t4 t5 t6

all: $(OUTDIR) t1 t2 t3 t4 t5 t6
	@echo ""
	@echo "✅ Todos los binarios compilados en $(OUTDIR)/"

$(OUTDIR):
	mkdir -p $(OUTDIR)

t1: $(OUTDIR)/t1_stack_noprotect
$(OUTDIR)/t1_stack_noprotect: t1_stack_noprotect.c
	$(CC) -o $@ $< $(CFLAGS) -z execstack -fno-stack-protector -no-pie
	@echo "  t1_stack_noprotect → NX=off  canary=off  PIE=off"

t2: $(OUTDIR)/t2_stack_nx
$(OUTDIR)/t2_stack_nx: t2_stack_nx.c
	$(CC) -o $@ $< $(CFLAGS) -fno-stack-protector -no-pie
	@echo "  t2_stack_nx        → NX=on   canary=off  PIE=off"

t3: $(OUTDIR)/t3_stack_canary
$(OUTDIR)/t3_stack_canary: t3_stack_canary.c
	$(CC) -o $@ $< $(CFLAGS) -z execstack -fstack-protector-all -no-pie
	@echo "  t3_stack_canary    → NX=off  canary=ON   PIE=off"

t4: $(OUTDIR)/t4_fmtstr
$(OUTDIR)/t4_fmtstr: t4_fmtstr.c
	$(CC) -o $@ $< $(CFLAGS) -fno-stack-protector -no-pie -z norelro
	@echo "  t4_fmtstr          → NX=on   canary=off  RELRO=none"

t5: $(OUTDIR)/t5_heap
$(OUTDIR)/t5_heap: t5_heap.c
	$(CC) -o $@ $< $(CFLAGS) -fno-stack-protector -no-pie -z execstack
	@echo "  t5_heap            → NX=off  canary=off  heap fn-ptr"

t6: $(OUTDIR)/t6_64bit_nx
$(OUTDIR)/t6_64bit_nx: t6_64bit_nx.c
	$(CC) -o $@ $< $(CFLAGS) -fno-stack-protector -no-pie
	@echo "  t6_64bit_nx        → NX=on   canary=off  PIE=off  64-bit"

clean:
	rm -f $(OUTDIR)/t1_stack_noprotect \
	      $(OUTDIR)/t2_stack_nx        \
	      $(OUTDIR)/t3_stack_canary    \
	      $(OUTDIR)/t4_fmtstr          \
	      $(OUTDIR)/t5_heap            \
	      $(OUTDIR)/t6_64bit_nx
	@echo "Binarios eliminados"
