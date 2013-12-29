main:	main.o Net_Service.o SSL_Wrapper.o
	cc -g -o main main.o Net_Service.o SSL_Wrapper.o -lssl -lcrypto
	rm -rfv *.o

clean:
	rm -fv *.o main
