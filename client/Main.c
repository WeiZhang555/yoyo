#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern int Client_Service_Start(char *ip, int port);

int main(int argc, char **argv)
{
	return Client_Service_Start(argv[1], atoi(argv[2]));
}
