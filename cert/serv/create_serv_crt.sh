#!/bin/bash
set -e

echo "create root private key"
echo
openssl genrsa -out root.key 2048 

echo "create root cert"
echo
openssl req -x509 -new -nodes -key root.key  -days 3650  -out root.crt -config root.cnf 

echo "create server private key"
echo
openssl genrsa  -out server.key 2048

echo "create server sign request"
echo
openssl req -new -key server.key  -config serv.cnf  -extensions v3_ext  -out server.csr

echo "sign"
echo
openssl x509 -req -days 3650 -in server.csr   -CA root.crt -CAkey root.key  -out server.crt -CAcreateserial -extensions v3_ext -extfile serv.cnf

rm server.csr
rm root.srl


