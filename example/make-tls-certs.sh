#!/bin/sh

out="$(pwd)/example"

if [ ! -d "$out" ]; then
  >&2 echo "ERROR: run this from the top-level directory"
  exit 1
fi

openssl genrsa \
        -out "$out/key.pem" \
        4096

openssl req \
        -batch \
        -new -key "$out/key.pem" \
        -out "$out/cert.csr"

openssl x509 \
        -req -in "$out/cert.csr" \
        -signkey "$out/key.pem" \
        -out "$out/cert.pem"
