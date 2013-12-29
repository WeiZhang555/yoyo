main: main.o Net_Service.o ../lib/SSL/SSL_Wrapper.o 
	gcc -g -o main main.o Net_Service.o ../lib/SSL/SSL_Wrapper.o -lssl -lcrypto
	rm -fv *.o
clean:
	rm -fv *.o main
