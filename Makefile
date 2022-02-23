objs = SecretKeyParamsBuilder SecretKeyParams SignedSecretKey SecretKey PublicKey Signature SignedPublicKey SignedPublicSubKey SubkeyParams SubkeyParamsBuilder 
build:
	cargo build
	cbindgen --lang C -o usage/crpgp.h . 2>&1 | grep -v "WARN: Can't find" || true
	for obj in $(objs); do \
		# echo '$$obj'; \
		sed 's/\b'$$obj'\b/struct '$$obj'/g' -i usage/crpgp.h; \
		sed -z 's/\n\n/\nstruct '$$obj';\n\n/' -i usage/crpgp.h; \
	done

runc: build
	rm -rf ./usage/use.out
	gcc -Wall -Wextra -Werror usage/use.c -o usage/use.out -lcrpgp -L./target/debug
	LD_LIBRARY_PATH=./target/debug/ usage/use.out

runv: genv
	rm -rf ./usage/use.out
	v -gc boehm -cg usage/v -o usage/use.out
	LD_LIBRARY_PATH=./target/debug/ usage/use.out

genv: build
	cat usage/crpgp.h |\
	egrep -o 'struct [a-zA-Z_]+' |\
	sort  | uniq |\
	sed 's/struct \([a-zA-Z]*\)/struct C.\1 {}\nstruct \1 {\n    internal \&C.\1\n}/g' \
	> usage/v/crpgp.v

	cat usage/crpgp.h |\
	sed -z 's/\n\s\s\s*/ /g' |\
	grep ');' |\
	sed 's/ [*]/* /g' |\
	sed 's/ [a-z_][a-z_]*[)]/\)/g' |\
	sed 's/struct \([a-zA-Z_]*\)[*]/\&C.\1/g' |\
	sed 's/struct \([a-zA-Z_]*\)/C.\1/g' |\
	sed -z 's/ [a-z_]*,/,/g' |\
	sed 's/^\([^ ]*\) \(.*\);$$/fn C.\2 \1/g' |\
	sed 's/uint8_t/u8/g' |\
	sed 's/size_t/u64/g' |\
	sed 's/\([a-zA-Z0-9]*\)[*]/\&\1/g' |\
	sed 's/[(]void[)]/()/g' \
	>> usage/v/crpgp.v

valgrindv: build
	rm -rf ./usage/use.out
	v -cg usage/use.v -o usage/use.out
	LD_LIBRARY_PATH=./target/debug/ valgrind --leak-check=full usage/use.out

valgrindc: build
	rm -rf ./usage/use.out
	gcc -Wall -Wextra -Werror usage/use.c -o usage/use.out -lcrpgp -L./target/debug
	LD_LIBRARY_PATH=./target/debug/ valgrind --leak-check=full usage/use.out
