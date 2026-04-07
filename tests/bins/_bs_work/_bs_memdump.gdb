set pagination off
file /home/cryptocalypse/Downloads/binsmasher_v7 (4)/v7/tests/bins/t10_safestack
break _dl_relocate_static_pie
run 
continue
x/64xg $rsp
info registers
backtrace
quit
