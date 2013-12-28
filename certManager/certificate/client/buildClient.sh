#!/bin/bash

openssl genrsa -out clientPriv.pem 2048
openssl rsa -in clientPriv.pem -pubout -out clientPub.pem
openssl req -new -key clientPriv.pem -out clientCert.csr
cd ..
openssl ca -in client/clientCert.csr -out client/clientCert.pem

