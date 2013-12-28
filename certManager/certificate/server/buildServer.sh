#!/bin/bash

openssl genrsa -out serverPriv.pem 2048
openssl rsa -in serverPriv.pem -pubout -out serverPub.pem
openssl req -new -key serverPriv.pem -out serverCert.csr
cd ..
openssl ca -in server/serverCert.csr -out server/serverCert.pem

