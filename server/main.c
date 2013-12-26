#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/epoll.h>

#include "../util/util.h"

#define MAX_EVENTS 10

void HandleClientMsg(int connfd)
{
	char buffer[1024];
	int recvLen;
	bzero(buffer, 1024);
	recvLen = recv(connfd, buffer, 1024, 0);
	if(recvLen <= 0 || strncmp(buffer, "quit", 4)==0)
	{
		printf("client quit!\n");
		close(connfd);
		return;
	}
	printf("Receive from client %d: %s\n", connfd, buffer);
	fflush(NULL);
	send(connfd, "Hello client!\n", 14, 0);
}

int main(int argc, char **argv)
{
	int listenfd, connfd;
	int recvLen, sendLen;
	int epollfd, nfds, n;
	socklen_t client_len;
	struct sockaddr_in cliaddr, servaddr;
	char buffer[1024];
	struct epoll_event ev, events[MAX_EVENTS];

	listenfd = socket(AF_INET, SOCK_STREAM, 0);
	if(listenfd<0)
	{
		perror("socket() failed!");
		exit(-1);
	}

	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	servaddr.sin_port = htons(SERVER_PORT);

	int optVal = 1;
	setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &optVal, sizeof(optVal));
	
	if(bind(listenfd, (struct sockaddr*)&servaddr, sizeof(servaddr)) < 0)
	{
		perror("bind() failed!");
		exit(-1);
	}

	if(listen(listenfd, 10) < 0)
	{
		perror("listen() error!");
		exit(-1);
	}

	epollfd = epoll_create(MAX_EVENTS);
	if (epollfd == -1) {
		perror("epoll_create()");
		exit(EXIT_FAILURE);
	}

	ev.events = EPOLLIN;
	ev.data.fd = listenfd;
	if (epoll_ctl(epollfd, EPOLL_CTL_ADD, listenfd, &ev) == -1) {
		perror("epoll_ctl()");
		exit(EXIT_FAILURE);
	}
	
	while(1){
		nfds = epoll_wait(epollfd, events, MAX_EVENTS, -1);
		if (nfds == -1) {
			perror("epoll_wait()");
			exit(EXIT_FAILURE);
		}

		for(n = 0; n < nfds; ++n) {
			if (events[n].data.fd == listenfd) {
				connfd = accept(listenfd, (struct sockaddr*)&cliaddr, &client_len);
				if(connfd < 0)
				{
					perror("accept()");
					exit(EXIT_FAILURE);
				}
				printf("accept successfully!\n");
				ev.events = EPOLLIN;
				ev.data.fd = connfd;
				if (epoll_ctl(epollfd, EPOLL_CTL_ADD, connfd, &ev) == -1) {
					perror("epoll_ctl()");
					exit(EXIT_FAILURE);
				}
			}else{
				HandleClientMsg(events[n].data.fd);
			}
		} /*end for loop*/
	} /*end while*/
	close(listenfd);
}
