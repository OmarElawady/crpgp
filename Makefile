objs = SecretKeyParamsBuilder SecretKeyParams SignedSecretKey SecretKey PublicKey Signature
run:
	cargo build
	cbindgen --lang C -o usage/crpgp.h . 2>&1 | grep -v "WARN: Can't find" || true
	for obj in $(objs); do \
		# echo '$$obj'; \
		sed -i 's/\b'$$obj'\b/struct '$$obj'/g' -i usage/crpgp.h; \
	done
	gcc -Wall -Wextra -Werror usage/use.c -o usage/use.out -lcrpgp -L./target/debug
	LD_LIBRARY_PATH=./target/debug/ usage/use.out
