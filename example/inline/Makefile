inline: libmap.c
	clang -S -O3 -emit-llvm libmap.c -o libmap.ll
	llvm-link -S -o xdp-counter-inline.ll xdp-counter.ll libmap.ll
	opt -passes=always-inline -S xdp-counter-inline.ll -o xdp-counter-inline.ll
	clang -O3 -g -c xdp-counter-inline.ll -o inline.o
