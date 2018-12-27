#include "Network.h"

int iTCPPort;
int iUDPPort;

HANDLE StartNetTCPLoopThread(int port)
{
	iTCPPort = port;
	return CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)netTCPLoop, NULL, 0, NULL);
	//netTCPLoop(NULL);
	//return 0;
}

DWORD netTCPLoop(LPVOID lpParameter)
{
	struct sockaddr_in server;
	struct sockaddr_in connected_client;

	SOCKET connectedSocket, acceptSocket;
	char buffer[2049];
	int client_len, rc, data_len;
	basic_string <char>::size_type index;

	client_len = sizeof(connected_client);

	// Erzeuge das Socket
	acceptSocket = socket(AF_INET, SOCK_STREAM, 0);
	if (acceptSocket == INVALID_SOCKET) {
		return 2;
	}

	memset(&server, 0, sizeof(sockaddr_in));
	server.sin_family = AF_INET;
	server.sin_port = htons(iTCPPort);
	server.sin_addr.s_addr = INADDR_ANY;

	// bind server-socket
	rc = bind(acceptSocket, (SOCKADDR*)&server, sizeof(sockaddr_in));

	if (rc == SOCKET_ERROR)
	{
		return 3;
	}

	// Auf Verbindungen warten
	rc = listen(acceptSocket, 10);
	if (rc == SOCKET_ERROR)
	{
		return 4;
	}

	std::string message;

	// Endlos auf neue Verbindugen warten
	while (true)
	{
		message = "";

		// TCP Sitzung verbinden
		connectedSocket = accept(acceptSocket, (sockaddr*)&connected_client, &client_len);
		if (connectedSocket == INVALID_SOCKET)
		{
#if _DEBUG
			printf("accept failed: %d\n", WSAGetLastError());
#endif
			return 5;
		}

		// recieve data
		do
		{
			data_len = recv(connectedSocket, buffer, 2048, 0);

			if (data_len > 0)
			{
				// terminate string
				buffer[data_len] = '\0';
				message.append(buffer);

				index = message.find("\n");

				if (index != string::npos)
				{
					string tmp = message.substr(0, index);
					message.clear();

					std::string ret = MessageRecieved(tmp.c_str(), connected_client.sin_addr);
					send(connectedSocket, ret.c_str(), (int)ret.length(), 0);
				}
			}
		} while (data_len > 0);

		MessageRecieved(message.c_str(), connected_client.sin_addr);
		closesocket(connectedSocket);
	}

	return 0;
}