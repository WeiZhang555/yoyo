main:	Main.o Net_Service.o ../lib/SSL_Wrapper.o
	cc -g -o main Main.o Net_Service.o ../lib/SSL_Wrapper.o -lssl -lcrypto
	rm -rfv *.o

clean:
	rm -fv *.o main
