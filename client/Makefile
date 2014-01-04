main: main.o Net_Service.o ../lib/SSL_Wrapper.o ../lib/cJSON/cJSON.o
	gcc -g -o main main.o Net_Service.o ../lib/SSL_Wrapper.o ../lib/cJSON/cJSON.o -lssl -lcrypto -lm
	rm -fv *.o
clean:
	rm -fv *.o main
