#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "Database.h"

extern int NetworkServiceStart();

int main(int argc, char **argv)
{
	if(DB_Init()<0)
	{
		printf("Database Init error!\n");
		exit(-1);
	}
	NetworkServiceStart();
	
	DB_DeInit();
	return 0;
}
