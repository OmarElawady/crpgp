#flag -L@VMODROOT/../target/debug -lcrpgp
#include "@VMODROOT/crpgp.h"

struct C.SecretKeyParamsBuilder {}
struct C.SecretKeyParams {}
struct C.SecretKey {}
struct C.SignedSecretKey {}
struct C.PublicKey {}
struct C.Signature {}

fn C.malloc(int) &char
fn C.free(&char)

fn C.error_message(&char, int) int
fn C.params_builder_new() &C.SecretKeyParamsBuilder
fn C.params_builder_free(&C.SecretKeyParamsBuilder) char
fn C.params_builder_primary_user_id(&C.SecretKeyParamsBuilder, &char) char
fn C.params_builder_build(&C.SecretKeyParamsBuilder) &C.SecretKeyParams
fn C.params_generate_secret_key_and_free(&C.SecretKeyParams) &C.SecretKey
fn C.secret_key_sign(&C.SecretKey) &C.SignedSecretKey
fn C.signed_secret_key_public_key(&C.SignedSecretKey) &C.PublicKey
fn C.signed_secret_key_create_signature(&C.SignedSecretKey, &u8, u64) &C.Signature
fn C.signature_serialize(&C.Signature, &u64) &u8
fn C.signature_serialization_free(&u8) char
fn C.signature_deserialize(&u8, u64) &C.Signature
fn C.signature_free(&C.Signature) char
fn C.public_key_verify(&C.PublicKey, &u8, u64, &C.Signature) char
fn C.public_key_free(&C.PublicKey) char

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
	err_buf := C.malloc(1024)
	C.error_message(err_buf, 1024)
	str := unsafe {cstring_to_vstring(err_buf)}
	C.free(err_buf)
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
		internal: C.params_builder_new()
	}
}
fn (b SecretKeyParamsBuilder) primary_key_id(primary_key_id string) ? {
	if C.params_builder_primary_user_id(b.internal, &char(primary_key_id.str)) != 0 {
		construct_error()?
	}
}
fn (b SecretKeyParamsBuilder) build() ?SecretKeyParams {
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
// TODO: why free is not called?
[unsafe]
fn (b &SecretKeyParamsBuilder) free() {
	println("hello")
	if C.params_builder_free(b.internal) != 0 {
		// TODO: how to handle errors in free mthods
	}
}

fn (s SecretKeyParams) generate_and_free() ?SecretKey {
	sk := C.params_generate_secret_key_and_free(s.internal)
	if u64(sk) == 0 {
		construct_error()?
		return error("")
	}
	return SecretKey {
		internal: sk
	}
}
fn (s SecretKey) sign() ?SignedSecretKey {
	ssk := C.secret_key_sign(s.internal)
	if u64(ssk) == 0 {
		construct_error()?
		return error("")
	}
	return SignedSecretKey {
		internal: ssk
	}
}

fn (s SignedSecretKey) create_signature(data []byte) ?Signature {
	sig := C.signed_secret_key_create_signature(s.internal, &u8(&data[0]), data.len)
	if u64(sig) == 0 {
		construct_error()?
		return error("")
	}
	return Signature {
		internal: sig
	}
}

fn (s SignedSecretKey) public_key() ?PublicKey {
	pk := C.signed_secret_key_public_key(s.internal)
	if u64(pk) == 0 {
		construct_error()?
		return error("")
	}
	return PublicKey {
		internal: pk
	}
}

fn (s Signature) serialize() []byte {
	len := u64(0)
	ser := C.signature_serialize(s.internal, &len)
	res := cu8_to_vbytes(ser, len) 
	C.signature_serialization_free(ser)
	return res
}

fn (s Signature) deserialize(bytes []byte) ?Signature {
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
// TODO: if unsafe free worked would passing wrappers by value
//       result in double-free?
//       and would defining destructors on c types solve the problem?
//       or is there a way to declare a type uncopyable (~ !Clone in rust)
fn (p PublicKey) verify(data []byte, sig &Signature) ? {
	ok := C.public_key_verify(p.internal, &u8(&data[0]), data.len, sig.internal)
	if ok != 0 {
		construct_error()?
		return error("")
	}
}

fn test() ? {
	secret_key_param_builder := new_secret_key_param_builder()?
	secret_key_param_builder.primary_key_id("Omar Elawady <elawadio@incubaid.com>")?
	secret_key_param_builder.primary_key_id("Omar Elawady <elawadio@incubaid.com>")?
}
fn main() {
	builder := new_secret_key_param_builder()?
	builder.primary_key_id("Omar Elawady <elawadio@incubaid.com>")?
	params := builder.build()?
	sk := params.generate_and_free()?
	ssk := sk.sign()?
	pk := ssk.public_key()?
	sig := ssk.create_signature(str_to_bytes("omar"))?
	pk.verify(str_to_bytes("omar"), sig)?
	println("verification succeeded")
	pk.verify(str_to_bytes("khaled"), sig) or {
		println("verification failed as expected for invalid sig: {}")
		println(err)
		return
	}
}
