main:	Main.o Net_Service.o Database.o ../lib/SSL_Wrapper.o ../lib/cJSON/cJSON.o ../lib/Security.o
	cc -g -o main Main.o Net_Service.o Database.o ../lib/SSL_Wrapper.o ../lib/cJSON/cJSON.o ../lib/Security.o -lssl -lcrypto -lm `mysql_config --cflags --libs`
	rm -rfv *.o

Database.o: Database.c
	cc -c -g Database.c `mysql_config --cflags --libs`

clean:
	rm -fv *.o main
