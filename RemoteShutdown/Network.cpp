#include "Network.h"

int iTCPPort;
int iUDPPort;

HANDLE StartNetTCPLoopThread(int Port) {
	iTCPPort = Port;
	return CreateThread(NULL,0,(LPTHREAD_START_ROUTINE)netTCPLoop,NULL,0,NULL);
}

HANDLE StartNetUDPLoopThread(int Port) {
	iUDPPort = Port;
	return CreateThread(NULL,0,(LPTHREAD_START_ROUTINE)netUDPLoop,NULL,0,NULL);
}

DWORD netTCPLoop(LPVOID lpParameter) {
	struct sockaddr_in server;
	struct sockaddr_in connected_client;
	WSADATA wsaData;
	SOCKET connectedSocket, acceptSocket;
	char buffer[2048];
	int client_len, rc, data_len;
	basic_string <char>::size_type index;

	client_len = sizeof(connected_client);

	// Initialisiere TCP für Windows (winsock)
	if (WSAStartup (MAKEWORD( 2, 2 ), &wsaData) != 0) {
			return 1;
	}

	// Erzeuge das Socket
	acceptSocket = socket(AF_INET, SOCK_STREAM, 0);
	if (acceptSocket == INVALID_SOCKET) {
		return 2;
	}

	memset(&server,0,sizeof(sockaddr_in));
	server.sin_family=AF_INET;
	server.sin_port=htons(iTCPPort);
	server.sin_addr.s_addr=INADDR_ANY;

	// bind server-socket
	rc = bind(acceptSocket,(SOCKADDR*)&server,sizeof(sockaddr_in));

	if(rc == SOCKET_ERROR) {
		return 3;
	}

	// Auf Verbindungen warten
	rc = listen(acceptSocket,10);
	if(rc == SOCKET_ERROR) {
		return 4;
	}

	string message;
	// Endlos auf neue Verbindugen warten
	while(true) {
		message = "";	

		// TCP Sitzung verbinden
		connectedSocket = accept(acceptSocket,(sockaddr*)&connected_client,&client_len);
		if(connectedSocket == INVALID_SOCKET) {
			#if _DEBUG
				printf("accept failed: %d\n", WSAGetLastError());
			#endif
			return 5;
		}

		// recieve data
    do {
			data_len = recv(connectedSocket, buffer, 2047, 0);
					
			if (data_len > 0) {
				// terminate string
				buffer[data_len]='\0';
				message.append(buffer);

				index = message.find("\n");

				if (index != string::npos) {
					string tmp = message.substr(0,index); 
					message.clear();

					int ret = MessageRecieved(tmp.c_str(),connected_client.sin_addr,TCP_MESSAGE);
					itoa(ret,buffer,10);

					send(connectedSocket,buffer,strlen(buffer),0);
				}
			}
    } while( data_len > 0 );
		
		MessageRecieved(message.c_str(),connected_client.sin_addr,TCP_MESSAGE);
		closesocket(connectedSocket);
	}

	return 0;
}

DWORD netUDPLoop(LPVOID lpParameter) {
	struct sockaddr_in server;
	
	SOCKADDR_IN remoteAddr;
  int remoteAddrLen=sizeof(SOCKADDR_IN);

	WSADATA wsaData;
	SOCKET acceptSocket;
	char buffer[2048];
	int rc;

	// Initialisiere TCP für Windows (winsock)
	if (WSAStartup (MAKEWORD( 2, 2 ), &wsaData) != 0) {
			return 1;
	}

	// Erzeuge das Socket
	acceptSocket = socket(AF_INET, SOCK_DGRAM, 0);
	if (acceptSocket == INVALID_SOCKET) {
		return 2;
	}

	memset(&server,0,sizeof(sockaddr_in));
	server.sin_family=AF_INET;
	server.sin_port=htons(iUDPPort);
	server.sin_addr.s_addr=INADDR_ANY;

	// bind server-socket
	rc = bind(acceptSocket,(SOCKADDR*)&server,sizeof(sockaddr_in));

	if(rc == SOCKET_ERROR) {
		return 3;
	}

	string message;

	// Endlos auf neue Verbindugen warten
	while(true) {
		message = "";

		rc=recvfrom(acceptSocket,buffer,256,0,(SOCKADDR*)&remoteAddr,&remoteAddrLen);

		if(rc==SOCKET_ERROR) {
      return 4;
    }
    else {
			buffer[rc]='\0';
			MessageRecieved(buffer,remoteAddr.sin_addr,UDP_MESSAGE);	
    }	
	}

	return 0;
}