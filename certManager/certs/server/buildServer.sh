#!/bin/bash

openssl genrsa -out serverPriv.pem 2048
openssl req -new -key serverPriv.pem -out serverCert.csr
cd ..
openssl ca -in server/serverCert.csr -out server/serverCert.pem

