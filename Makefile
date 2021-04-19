all: bpf_cubic.o bpf_dctcp.o
bpf_cubic.o: bpf_cubic.c
	clang -O2 -g -target bpf -c bpf_cubic.c -o bpf_cubic.o 
bpf_dctcp.o: bpf_dctcp.c
	clang -O2 -g -target bpf -c bpf_dctcp.c -o bpf_dctcp.o 
clean:
	rm *.o
