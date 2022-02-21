#flag -L@VMODROOT/../target/debug -lcrpgp
#include "@VMODROOT/crpgp.h"

struct C.SecretKeyParamsBuilder {}
struct C.SecretKeyParams {}
struct C.SecretKey {}
struct C.SignedSecretKey {}
struct C.PublicKey {}
struct C.Signature {}

fn C.error_message(&char, int) int
fn C.params_builder_new() &C.SecretKeyParamsBuilder
fn C.params_builder_free(&C.SecretKeyParamsBuilder) char
fn C.params_builder_primary_user_id(&C.SecretKeyParamsBuilder, &char) char
fn C.params_builder_build(&C.SecretKeyParamsBuilder) &C.SecretKeyParams
fn C.params_generate_secret_key_and_free(&C.SecretKeyParams) &C.SecretKey
fn C.secret_key_sign(&C.SecretKey) &C.SignedSecretKey
fn C.secret_key_free(&C.SecretKey) char
fn C.signed_secret_key_public_key(&C.SignedSecretKey) &C.PublicKey
fn C.signed_secret_key_free(&C.SignedSecretKey) char
fn C.signed_secret_key_create_signature(&C.SignedSecretKey, &u8, u64) &C.Signature
fn C.signature_serialize(&C.Signature, &u64) &u8
fn C.ptr_free(&u8) char
fn C.signature_deserialize(&u8, u64) &C.Signature
fn C.signature_free(&C.Signature) char
fn C.public_key_verify(&C.PublicKey, &u8, u64, &C.Signature) char
fn C.public_key_free(&C.PublicKey) char
fn C.signed_secret_key_decrypt(&C.SignedSecretKey, &u8, &u64) &u8
fn C.public_key_encrypt(&C.PublicKey, &u8, &u64) &u8

fn cu8_to_vbytes(ptr &u8, l u64) []byte {
	mut res := []byte{}
	for _ in 0 .. l {
		res << byte(unsafe { *ptr })
		unsafe {
			ptr++
		}
	}
	return res
}
fn str_to_bytes(s string) []byte {
	mut res := []byte{}
	for c in s {
		res << byte(c)
	}
	return res
}

fn construct_error() ?int {
	// todo: call the func to get the error length
	err_buf := unsafe { malloc(1024) }
	C.error_message(err_buf, 1024)
	str := unsafe {cstring_to_vstring(err_buf)}
	unsafe { free(err_buf) }
	return error(str)

}
struct SecretKeyParamsBuilder {
	internal &C.SecretKeyParamsBuilder
}

struct SecretKeyParams {
	internal &C.SecretKeyParams
}

struct SecretKey {
	internal &C.SecretKey
}

struct SignedSecretKey {	
	internal &C.SignedSecretKey
}

struct PublicKey {
	internal &C.PublicKey
}

struct Signature {	
	internal &C.Signature
}

fn new_secret_key_param_builder() ?SecretKeyParamsBuilder {
	builder := C.params_builder_new()
	if u64(builder) == 0 {
		construct_error()?
		return error("")
	}
	return SecretKeyParamsBuilder{
		internal: builder
	}
}
fn (b &SecretKeyParamsBuilder) primary_key_id(primary_key_id string) ? {
	if C.params_builder_primary_user_id(b.internal, &char(primary_key_id.str)) != 0 {
		construct_error()?
	}
}
fn (b &SecretKeyParamsBuilder) build() ?SecretKeyParams {
	params1 := C.params_builder_build(b.internal)
	if u64(params1) == 0 {
		println("failed to build secret key params")
		construct_error()?
		return error("")
	}
	return SecretKeyParams {
		internal: params1
	}
}

fn (s &SecretKeyParams) generate_and_free() ?SecretKey {
	sk := C.params_generate_secret_key_and_free(s.internal)
	if u64(sk) == 0 {
		construct_error()?
		return error("")
	}
	return SecretKey {
		internal: sk
	}
}

fn (s &SecretKey) sign() ?SignedSecretKey {
	ssk := C.secret_key_sign(s.internal)
	if u64(ssk) == 0 {
		construct_error()?
		return error("")
	}
	return SignedSecretKey {
		internal: ssk
	}
}

fn (s &SignedSecretKey) create_signature(data []byte) ?Signature {
	sig := C.signed_secret_key_create_signature(s.internal, &u8(&data[0]), data.len)
	if u64(sig) == 0 {
		construct_error()?
		return error("")
	}
	return Signature {
		internal: sig
	}
}

fn (s &SignedSecretKey) decrypt(data []byte) ?[]byte {
	len := u64(data.len)
	decrypted := C.signed_secret_key_decrypt(s.internal, &u8(&data[0]), &len)
	if u64(decrypted) == 0 {
		construct_error()?
		return error("")
	}
	return cu8_to_vbytes(decrypted, len)
}

fn (s &SignedSecretKey) public_key() ?PublicKey {
	pk := C.signed_secret_key_public_key(s.internal)
	if u64(pk) == 0 {
		construct_error()?
		return error("")
	}
	return PublicKey {
		internal: pk
	}
}

fn (s &Signature) serialize() ?[]byte {
	len := u64(0)
	ser := C.signature_serialize(s.internal, &len)
	if u64(ser) == 0 {
		construct_error()?
		return error("")
	}
	res := cu8_to_vbytes(ser, len) 
	C.ptr_free(ser)
	return res
}

fn deserialize_signature(bytes []byte) ?Signature {
	// TODO: is the pointer arith here ok?
	sig := C.signature_deserialize(&u8(&bytes[0]), bytes.len)
	if u64(sig) == 0 {
		construct_error()?
		return error("")
	}
	return Signature {
		internal: sig
	}
}

fn (p &PublicKey) verify(data []byte, sig &Signature) ? {
	ok := C.public_key_verify(p.internal, &u8(&data[0]), data.len, sig.internal)
	if ok != 0 {
		construct_error()?
		return error("")
	}
}

fn (s &PublicKey) encrypt(data []byte) ?[]byte {
	len := u64(data.len)
	encrypted := C.public_key_encrypt(s.internal, &u8(&data[0]), &len)
	if u64(encrypted) == 0 {
		construct_error()?
		return error("")
	}
	return cu8_to_vbytes(encrypted, len)
}


fn main() {
	builder := new_secret_key_param_builder()?
	builder.primary_key_id("Omar Elawady <elawadio@incubaid.com>")?
	params := builder.build()?
	sk := params.generate_and_free()?
	ssk := sk.sign()?
	pk := ssk.public_key()?
	mut sig := ssk.create_signature(str_to_bytes("omar"))?
	sig = deserialize_signature(sig.serialize()?)?
	pk.verify(str_to_bytes("omar"), sig)?
	println("verification succeeded")
	pk.verify(str_to_bytes("khaled"), sig) or {
		print("verification failed as expected for invalid sig:")
		println(err)
	}

	encrypted := pk.encrypt(str_to_bytes("omar\0"))?
	decrypted := ssk.decrypt(encrypted)?
	print("decrypted (should be omar): ")
	println(unsafe { cstring_to_vstring(&char(&decrypted[0])) })
}