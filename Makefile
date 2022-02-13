run:
	cargo build
	cbindgen --lang C -o ./usage/crpgp.h .
	gcc usage/use.c -o usage/use.out -lcrpgp -L./target/debug
	LD_LIBRARY_PATH=./target/debug/ usage/use.out
