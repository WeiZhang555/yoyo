MAIN_OBJECTS=Main.o Net_Service.o ../lib/SSL_Wrapper.o ../lib/cJSON/cJSON.o
LD_FLAG= -lssl -lcrypto -lm
main:	$(MAIN_OBJECTS)
	cc -g -o main $(MAIN_OBJECTS) $(LD_FLAG)
	rm -rfv *.o

clean:
	rm -fv *.o main
