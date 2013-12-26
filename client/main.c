#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "util.h"

int main(int argc, char **argv)
{
	if(argc<3)
	{
		printf("Usage: %s IP PORT\n", argv[0]);
		exit(-1);
	}

	int sockfd;
	int servport;
	struct sockaddr_in servaddr;
	char buffer[1024];
	int sendLen, recvLen;

	servport = atoi(argv[2]);
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if(sockfd < 0)
	{
		perror("socket() failed!");
		exit(-1);
	}

	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = inet_addr(argv[1]);
	servaddr.sin_port = htons(servport);
	inet_pton(AF_INET, argv[1], &servaddr.sin_addr);

	if(connect(sockfd, (struct sockaddr*)&servaddr, sizeof(servaddr)) < 0)
	{
		perror("connect() failed!");
		exit(-1);
	}

	sprintf(buffer, "%s", "This is a client test!");	
	send(sockfd, buffer, strlen(buffer)+1, 0);
	bzero(buffer, 1024);
	recvLen = recv(sockfd, buffer, 1024, 0);
	if(recvLen>0)
	{
		printf("From server: %s\n", buffer);
		fflush(NULL);
	}
	close(sockfd);
}
