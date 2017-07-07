#!/usr/bin/env bash
rm dsa*
rm rsa*
rm ecdsa*
ssh-keygen -q -b 1024 -t dsa -f dsa1024 -N "" -C "dsa test key."
ssh-keygen -q -b 1024 -t rsa -f rsa1024 -N "" -C "rsa 1024 test key."
ssh-keygen -q -b 2048 -t rsa -f rsa2048 -N "" -C "rsa 2048 test key."
ssh-keygen -q -b 4096 -t rsa -f rsa4096 -N "" -C "rsa 4094 test key."
ssh-keygen -q -b 3072 -t rsa -f rsa3072 -N "" -C "rsa 3072 test key."
ssh-keygen -q -b 256 -t ecdsa -f ecdsa256 -N "" -C "ecdsa 256 test key."
ssh-keygen -q -b 384 -t ecdsa -f ecdsa384 -N "" -C "ecdsa 384 test key."
ssh-keygen -q -b 521 -t ecdsa -f ecdsa521 -N "" -C "ecdsa 521 test key."
