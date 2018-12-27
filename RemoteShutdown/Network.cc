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
    // Create server socket
    auto acceptSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (acceptSocket == INVALID_SOCKET)
    {
        return 2;
    }

    struct sockaddr_in server;
    memset(&server, 0, sizeof(sockaddr_in));
    server.sin_family = AF_INET;
    server.sin_port = htons(iTCPPort);
    server.sin_addr.s_addr = INADDR_ANY;

    // Bind to server socket
    int rc = bind(acceptSocket, reinterpret_cast<sockaddr*>(&server), sizeof(sockaddr_in));
    if (rc == SOCKET_ERROR)
    {
        return 3;
    }

	// Listen for clients to connect
	rc = listen(acceptSocket, 10);
	if (rc == SOCKET_ERROR)
	{
		return 4;
	}
    
	// Endless loop
	while (true)
	{
        std::string message = "";
        struct sockaddr_in connected_client;
        int client_len = sizeof(connected_client);

		// Wait for client to connect
        auto connectedSocket = accept(acceptSocket, reinterpret_cast<sockaddr*>(&connected_client), &client_len);
		if (connectedSocket == INVALID_SOCKET)
		{
#if _DEBUG
			printf("accept failed: %d\n", WSAGetLastError());
#endif
			return 5;
		}

		// Recieve data
        int data_len = 0;
		do
		{
            char buffer[4096];
			data_len = recv(connectedSocket, buffer, 4096, 0);

			if (data_len > 0)
			{
				// terminate string
				buffer[data_len] = '\0';
				message.append(buffer);

				auto index = message.find("\n");

				if (index != string::npos)
				{
					auto tmp = message.substr(0, index);
					message.clear();

					auto response = MessageRecieved(tmp.c_str(), connected_client.sin_addr);
                    send(connectedSocket, response.c_str(), static_cast<int>(response.length()), 0U);
				}
			}
		} while (data_len > 0);

		MessageRecieved(message.c_str(), connected_client.sin_addr);
		closesocket(connectedSocket);
	}

	return 0;
}