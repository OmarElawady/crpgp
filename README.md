# rPGP vlang & c binginds

Bindings for signing/encryption functionalities in rPGP rust crate.

## Requirements

- cbindgen: developed with 0.20.0, some tweaks were needed to produce a valid C header file (can be found in Makefile). So it's not guaranteed to work with other versions.
- rust & v & c

### OSX

- cbindgen
```
cargo install --force cbindgen
```

- libgc
```
brew install libgc
```

to run included Make file for now on MacOS, it require GNU version of sed. see (this issue)[https://github.com/threefoldtech/crpgp/issues/2] for more context.
```
brew install gnu-sed
# before runing the makefile scripts, make gnu-sed temporarily the default sed version.
export PATH="/usr/local/opt/gnu-sed/libexec/gnubin:$PATH"
```

## Running

```bash
make runv
```
This does the following:
- Builds the rust lib wrapping rPGP providing C-usable methods and type.
- Uses cbindgen to generate usage/crpgp.h.
- Generates usage/v/crpgp.v
- Runs usage/v/use.v

## Status

- C memory leak test can be run by `make valgrindc`. Memory in vlang is managed by vlang garbage collector. Free methods are not exposed in v (can be).
- More things can be parameterized as needed (like hashing algorithm in the signature).
