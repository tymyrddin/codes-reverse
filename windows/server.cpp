// server.cpp : Defines the entry point for the console application.
// For Windows, the socket library needs to be initiated by using
// the WSAStartup API before using socket APIs.
//

#include "stdafx.h"
#include "winsock2.h"
#include "ws2tcpip.h"

#pragma comment(lib, "Ws2_32.lib")
#pragma warning(disable:4996)

int main()
{
	int listenfd = 0, connfd = 0;
	struct sockaddr_in serv_addr;
	struct sockaddr_in ctl_addr;
	int addrlen;
	char sendBuff[1025];

	
	WSADATA WSAData;

	if (WSAStartup(MAKEWORD(2, 2), &WSAData) == 0)
	{
		listenfd = socket(AF_INET, SOCK_STREAM, 0);
		if (listenfd != INVALID_SOCKET)
		{
			memset(&serv_addr, '0', sizeof(serv_addr));
			memset(sendBuff, '0', sizeof(sendBuff));
			serv_addr.sin_family = AF_INET;
			serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
			serv_addr.sin_port = htons(9999);
			if (bind(listenfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) == 0)
			{
				if (listen(listenfd, SOMAXCONN) == 0)
				{
					printf("Genie is waiting for connections to port 9999.\n");
					while (1)
					{
						addrlen = sizeof(ctl_addr);
						connfd = accept(listenfd, (struct sockaddr*)&ctl_addr, &addrlen);
						if (connfd != INVALID_SOCKET)
						{
							printf("%s has connected.\n", inet_ntoa(ctl_addr.sin_addr));

							snprintf(sendBuff, sizeof(sendBuff), "You have connected to the Genie. Nothing to see here.\n\n");
							send(connfd, sendBuff, strlen(sendBuff), 0);
							closesocket(connfd);
						}
					}
				}
			}
			closesocket(listenfd);
		}
		WSACleanup();
	}
	return 0;
}

