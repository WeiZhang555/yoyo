MAIN_OBJECTS=Main.o Net_Service.o Database.o ../lib/SSL_Wrapper.o ../lib/cJSON/cJSON.o ../lib/Security.o \
			 ../lib/Base64.o Session.o File.o ../lib/Math.o Json.o
MYSQL_FLAG=`mysql_config --cflags --libs`

main:	$(MAIN_OBJECTS)		
	cc -g -o main $(MAIN_OBJECTS) -lssl -lcrypto -lm $(MYSQL_FLAG)
	rm -rfv *.o

Database.o: Database.c
	cc -c -g Database.c $(MYSQL_FLAG)

clean:
	rm -fv *.o main
