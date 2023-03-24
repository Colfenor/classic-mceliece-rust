#!/bin/bash

declare -A variants
variants["mceliece348864"]="f932d4f75d1a788ad58e7d20af8defe9"
variants["mceliece348864f"]="70e10264d735abe77a509d853bfc6f6d"
variants["mceliece460896"]="7d2d60f492a8e74a33696a0616f61746"
variants["mceliece460896f"]="5ce8c2ecbb8c94082b475ff090f457c4"
variants["mceliece6688128"]="e7ad02c431ac9019820b7ce96654b240"
variants["mceliece6688128f"]="39984724cdabb810cdc76ade08a9bf52"
variants["mceliece6960119"]="819e4a4748f201e47d70f28f5b639303"
variants["mceliece6960119f"]="59426af22ec3a5e5dddc0969782832a6"
variants["mceliece8192128"]="9dc71f8a9f8a6492e2b7c341b8a0801b"
variants["mceliece8192128f"]="8022c8ffd8d938e56840261c91d1e59a"

RET=0
TMPDIR=$(mktemp -d)
for var in "${!variants[@]}"
do
    cargo test --release --features "$var kem" --package classic-mceliece-rust --lib -- tests::test_katkem $TMPDIR/$var.req $TMPDIR/$var.rsp
    MD5HASH=$(md5sum ${TMPDIR}/${var}.rsp | awk '{print $1}')
    if [[ "$MD5HASH" != "${variants[$var]}" ]]; then
        echo "KAT not as expected for ${var}."
        RET=1
    fi
done
rm -R $TMPDIR
exit $RET
    


