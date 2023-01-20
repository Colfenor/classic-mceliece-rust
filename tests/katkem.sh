#!/bin/bash

declare -A variants
variants["mceliece348864"]="d2def196fde89e938d3d45b2c6f806aa"
variants["mceliece348864f"]="84b5357d8dd656bed9297e28beb15057"
variants["mceliece460896"]="8aac2122916b901172e49e009efeede6"
variants["mceliece460896f"]="d84d3b179e303b9f3fc32ccb6befb886"
variants["mceliece6688128"]="b86987d56c45da2e326556864e66bda7"
variants["mceliece6688128f"]="ae1e42cac2a885a87a2c241e05391481"
variants["mceliece6960119"]="9d9b3c9e8d7595503248131c584394be"
variants["mceliece6960119f"]="c79b1bd28fd307f8d157bd566374bfb3"
variants["mceliece8192128"]="b233e2585359a1133a1135c66fa48282"
variants["mceliece8192128f"]="d21bcb80dde24826e2c14254da917df3"

RET=0
TMPDIR=$(mktemp -d) 
for var in "${!variants[@]}" 
do
    cargo test --release --features "$var" --package classic-mceliece-rust --lib -- tests::test_katkem $TMPDIR/$var.req $TMPDIR/$var.rsp --nocapture
    # cargo run --release --features "$var" --example katkem -- $TMPDIR/$var.req $TMPDIR/$var.rsp
    MD5HASH=$(md5sum ${TMPDIR}/${var}.rsp | awk '{print $1}')
    if [[ "$MD5HASH" != "${variants[$var]}" ]]; then
        echo "KAT not as expected for ${var}."
        RET=1
    fi
done
rm -R $TMPDIR
exit $RET
    


