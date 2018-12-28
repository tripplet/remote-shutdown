#include "Network.h"
#include "GlobalConst.h"
#include "RemoteShutdown.h"

#include <winsock.h>
#include <string>
#include <exception>

extern Logger logger;

int tcpPort;
HANDLE networkThread = nullptr;

DWORD netTCPLoop(LPVOID lpParameter);

HANDLE StartNetTCPLoopThread(int port)
{
    if (networkThread != nullptr)
    {
        logger.error("TCP network thread already running");
        return nullptr;
    }

    tcpPort = port;
    networkThread = CreateThread(nullptr, 0U, (LPTHREAD_START_ROUTINE)netTCPLoop, nullptr, 0U, nullptr);
    return networkThread;
}

DWORD netTCPLoop(LPVOID lpParameter)
{
    // Create server socket
    const auto acceptSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (acceptSocket == INVALID_SOCKET)
    {
        logger.error("Error creating socket");

        networkThread = nullptr;
        return -1;
    }

    struct sockaddr_in server{};
    server.sin_family = AF_INET;
    server.sin_port = htons(tcpPort);
    server.sin_addr.s_addr = INADDR_ANY;

    // Bind to server socket
    int rc = bind(acceptSocket, reinterpret_cast<sockaddr*>(&server), sizeof(sockaddr_in));
    if (rc == SOCKET_ERROR)
    {
        logger.error("Error binding socket");

        networkThread = nullptr;
        return -1;
    }

	// Listen for clients to connect
	rc = listen(acceptSocket, 10);
	if (rc == SOCKET_ERROR)
	{
        logger.error("Error listening on socket");

        networkThread = nullptr;
        return -1;
	}

	// Endless loop
	while (true)
	{
        std::string message = "";
        struct sockaddr_in connected_client{};
        int client_len = sizeof(connected_client);

		// Wait for client to connect
        const auto connectedSocket = accept(acceptSocket, reinterpret_cast<sockaddr*>(&connected_client), &client_len);
		if (connectedSocket == INVALID_SOCKET)
		{
            logger.error(std::string("Error accepting client connection: ") + std::to_string(WSAGetLastError()));

            networkThread = nullptr;
            return -1;
		}

		// Recieve data
        int data_len = 0;
		do
		{
            char buffer[4096];
			data_len = recv(connectedSocket, buffer, 4096, 0);

			if (data_len > 0)
			{
                for (size_t i = 0; i < data_len - 1; i++)
                {
                    if (buffer[i] == '\0')
                    {
                        break;
                    }
                }

				// terminate string
				buffer[data_len] = '\0';
				message.append(buffer);

				auto index = message.find("\n");

				if (index != std::string::npos)
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