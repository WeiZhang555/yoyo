#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "util.h"

extern int Client_Service_Start(char *ip, int port);

int main(int argc, char **argv)
{
	if(argc<3)
	{
		printf("Usage: %s IP PORT\n", argv[0]);
		exit(-1);
	}

	return Client_Service_Start(argv[1], atoi(argv[2]));
}
