#!/bin/bash

openssl genrsa -out clientPriv.pem 2048
openssl req -new -key clientPriv.pem -out clientCert.csr
cd ..
openssl ca -in client/clientCert.csr -out client/clientCert.pem

