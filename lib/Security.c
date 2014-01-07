#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void Get_RandStr(char s[],int num)
{
	char *str = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+-,.<>";
	int i,lstr;
	char ss[2] = {0};
	lstr = strlen(str);
	bzero(s, num);
	srand((unsigned int)time((time_t *)NULL));
	for(i = 0; i < num-1; i++){
		sprintf(ss,"%c",str[(rand()%lstr)]);
  		strcat(s,ss);
 	}
}

