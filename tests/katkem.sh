#!/bin/bash

declare -A variants
variants["mceliece348864"]="187255d64e8139fe729dce3851f05ba3"
variants["mceliece348864f"]="1f44974b7f792f31dc702e57372d1d0e"
variants["mceliece460896"]="5734a1bfa0978d51d226c1cfb1927626"
variants["mceliece460896f"]="f0e45c122c6af7fb71907e237f61b9e1"
variants["mceliece6688128"]="cd8d87674bfa9dac99295645ada4b4e5"
variants["mceliece6688128f"]="0fe9b57183ed7a9f8696c87b199972a0"
variants["mceliece6960119"]="5dcd52afbd4e8f4828d6d5fe3bc6f873"
variants["mceliece6960119f"]="2d0d8634eae40e009ca5deffe167d912"
variants["mceliece8192128"]="3adb51bd37e72d4fb47ef128505e2e53"
variants["mceliece8192128f"]="f295355034e5ae6b1274aaf7c0a36730"

RET=0
TMPDIR=$(mktemp -d) 
for var in "${!variants[@]}" 
do
    cargo test --release --features "$var" --package classic-mceliece-rust --lib -- tests::test_katkem $TMPDIR/$var.req $TMPDIR/$var.rsp
    MD5HASH=$(md5sum ${TMPDIR}/${var}.rsp | awk '{print $1}')
    if [[ "$MD5HASH" != "${variants[$var]}" ]]; then
        echo "KAT not as expected for ${var}."
        RET=1
    fi
done
rm -R $TMPDIR
exit $RET
    


