#!/bin/bash

if [ ! $# -eq 2 ]
then
	echo "Usage: $0 CommonName Email";
	exit -1;
fi

commonName=$1;
email=$2;
privFile="${commonName}Priv.pem";
csrFile="${commonName}Cert.csr";
certFile="${commonName}Cert.pem";
echo $privFile $csrFile $certFile;

openssl genrsa -out $privFile 2048
openssl req -new -key $privFile -out $csrFile -subj /C=CN/ST=BJ/L=BJ/O=Cookie/OU=Cookie/CN=${commonName}/emailAddress=${email}

cd ..
openssl ca -batch -in client/$csrFile -out client/$certFile

