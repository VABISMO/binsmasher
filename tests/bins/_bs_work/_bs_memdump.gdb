set pagination off
file /home/cryptocalypse/projects/binsmasher_final/binsmasher_final/tests/bins/t_revshell
break _dl_relocate_static_pie
run 
continue
x/64xg $rsp
info registers
backtrace
quit
