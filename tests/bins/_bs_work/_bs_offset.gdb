set pagination off
file /home/cryptocalypse/projects/binsmasher_final/binsmasher_final/tests/bins/t_revshell
run <<< $(python3 -c "import sys; from pwn import cyclic; sys.stdout.buffer.write(cyclic(400))")
info registers rip
info registers eip
quit
