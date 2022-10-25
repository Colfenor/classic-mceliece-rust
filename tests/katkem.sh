#!/bin/bash

declare -A variants
variants["mceliece348864f"]="7a6f5262fa013fe7eedda0765a625789"
variants["mceliece348864"]="11fd67ba1e2b93cceaec6f5e6fe4ddd1"
variants["mceliece460896f"]="cb08e0e3f2122c62692111d684f1cbe7"
variants["mceliece460896"]="c9acefa82aa705cd324f12df532744c2"
variants["mceliece6688128f"]="6d959c2bf54f7d3576a8e49475a74df5"
variants["mceliece6688128"]="7e300cc0990b05f5edca3219ac769023"
variants["mceliece6960119f"]="2f5d759cb579c6f85c1ee1306082ffdf"
variants["mceliece6960119"]="b4960a35e249d55fd48371f793608aa5"
variants["mceliece8192128f"]="a4cd676dc2c774d644f18de05762c51c"
variants["mceliece8192128"]="26a47e6d01eec28e91abfdbdf19c3067"

RET=0
TMPDIR=$(mktemp -d) 
for var in "${!variants[@]}" 
do
    cargo run --release --features "$var" --example katkem -- $TMPDIR/$var.req $TMPDIR/$var.rsp
    MD5HASH=$(md5sum ${TMPDIR}/${var}.rsp | awk '{print $1}')
    if [[ "$MD5HASH" != "${variants[$var]}" ]]; then
        echo "KAT not as expected for ${var}."
        RET=1
    fi
done
rm -R $TMPDIR
exit $RET
    


