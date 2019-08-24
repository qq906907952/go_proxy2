#!/bin/bash
set -e

if [ "$#" -eq 0 ];then
    openssl genrsa  -out client.key 2048

    openssl req -x509 -new -nodes -key client.key  -days 3650  -out client.crt -config cli.cnf -extensions v3_ext

    exit 0
fi

re='^[0-9]+$'
if ! [[ $1 =~ $re ]] ; then
   echo "param 1 must a number"
   exit 1
fi

for i in `seq  1 1 $1`;do

    openssl genrsa  -out client_$i.key 2048

    openssl req -x509 -new -nodes -key client_$i.key  -days 3650  -out client_$i.crt -config cli.cnf -extensions v3_ext


done








