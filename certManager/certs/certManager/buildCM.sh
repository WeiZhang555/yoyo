#!/bin/bash

openssl genrsa -out certManagerPriv.pem 2048
openssl req -new -key certManagerPriv.pem -out certManagerCert.csr
cd ..
openssl ca -in certManager/certManagerCert.csr -out certManager/certManagerCert.pem
cd -
cat certManagerCert.pem certManagerPriv.pem > CMCert.pem
mv CMCert.pem ../
