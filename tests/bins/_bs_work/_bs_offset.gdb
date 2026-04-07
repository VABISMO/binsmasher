set pagination off
file /home/cryptocalypse/Downloads/binsmasher_v7 (4)/v7/tests/bins/t10_safestack
run <<< $(python3 -c "import sys; from pwn import cyclic; sys.stdout.buffer.write(cyclic(400))")
info registers rip
info registers eip
quit
