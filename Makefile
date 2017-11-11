bpf_inkernel_db :	bpf_inkernel_db.c libbpf.o
	gcc -Wall -o bpf_inkernel_db bpf_inkernel_db.c libbpf.c

bpf_xmit.o :	bpf_inkernel_db.c
	gcc -c bpf_inkernel_db.c

libbpf.o :	libbpf.c
	gcc -c libbpf.c

clean :
	rm -f bpf_inkernel_db bpf_inkernel_db.o libbpf.o
