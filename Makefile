objs = SecretKeyParamsBuilder SecretKeyParams SignedSecretKey SecretKey PublicKey Signature
build:
	cargo build
	cbindgen --lang C -o usage/crpgp.h . 2>&1 | grep -v "WARN: Can't find" || true
	for obj in $(objs); do \
		# echo '$$obj'; \
		sed -i 's/\b'$$obj'\b/struct '$$obj'/g' -i usage/crpgp.h; \
	done

runc: build
	rm -rf ./usage/use.out
	gcc -Wall -Wextra -Werror usage/use.c -o usage/use.out -lcrpgp -L./target/debug
	LD_LIBRARY_PATH=./target/debug/ usage/use.out

runv: build
	rm -rf ./usage/use.out
	v -cg usage/use.v -o usage/use.out
	LD_LIBRARY_PATH=./target/debug/ usage/use.out

valgrindv: build
	rm -rf ./usage/use.out
	v -cg usage/use.v -o usage/use.out
	LD_LIBRARY_PATH=./target/debug/ valgrind --leak-check=full usage/use.out

valgrindc: build
	rm -rf ./usage/use.out
	gcc -Wall -Wextra -Werror usage/use.c -o usage/use.out -lcrpgp -L./target/debug
	LD_LIBRARY_PATH=./target/debug/ valgrind --leak-check=full usage/use.out
