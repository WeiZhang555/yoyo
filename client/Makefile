OBJECTS=main.o Net_Service.o ../lib/SSL_Wrapper.o ../lib/cJSON/cJSON.o Security.o Json.o ../lib/Math.o ../lib/Security.o ../lib/Base64.o

main: $(OBJECTS)
	gcc -g -o main $(OBJECTS) -lssl -lcrypto -lm
	rm -fv *.o
clean:
	rm -fv *.o main
