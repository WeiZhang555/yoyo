#!/bin/bash

if [ ! $# -eq 2 ]
then
	echo "Usage: $0 CommonName Email";
	exit -1;
fi

commonName=$1;
email=$2;
privFile="${commonName}Priv.pem";
pubFile="${commonName}Pub.pem";
csrFile="${commonName}Cert.csr";
certFile="${commonName}Cert.pem";
echo $privFile $csrFile $certFile;

openssl genrsa -out $privFile 2048
openssl rsa -inform pem -in ${privFile} -pubout -out ${pubFile}
openssl req -new -key $privFile -out $csrFile -subj /C=CN/ST=BJ/L=BJ/O=Cookie/OU=Cookie/CN=${commonName}/emailAddress=${email}

cd ..
openssl ca -batch -in client/$csrFile -out client/$certFile -notext

cd -
if [ -f $certFile -a -f $privFile ]
then
	cat $privFile >> $certFile
	rm -fv $privFile $csrFile
fi
