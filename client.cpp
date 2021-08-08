#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <stdio.h>
#include <io.h>
#include <fcntl.h>
#include <wincrypt.h>


// Need to link with Ws2_32.lib, Mswsock.lib, and Advapi32.lib
#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "Mswsock.lib")
#pragma comment (lib, "AdvApi32.lib")

#define DEFAULT_BUFLEN 4096
#define MAX_SERVERS 15

char sendbuf[DEFAULT_BUFLEN] = { 0 };
char recvbuf[DEFAULT_BUFLEN] = { 0 };


struct server_ctx
{
	int port;
	HCRYPTKEY SessionKey = { 0 };
	DWORD SessionKeyLenght = 0;
	HCRYPTPROV hProv = { 0 }; //дескриптор CSP
	HCRYPTKEY Key = { 0 }; //private + public keys
	HCRYPTKEY PublicKey = { 0 };
	HCRYPTKEY PrivateKey = { 0 };
	DWORD SizeOfPublic = 0;
	BYTE* public_Key;
	SOCKET ConnectSocket = INVALID_SOCKET;
};

struct server_ctx g_ctxs[1 + MAX_SERVERS];
int count_server = 0;

// Поиск прав по маске
void FindRights(unsigned int right)
{
	switch (right)
	{
	case GENERIC_ALL: printf("Generic all"); break;
	case GENERIC_EXECUTE: printf("Generic execute"); break;
	case GENERIC_WRITE: printf("Generic write"); break;
	case GENERIC_READ: printf("Generic read"); break;
	case ACCESS_SYSTEM_SECURITY: printf("Access system security"); break;
	case MAXIMUM_ALLOWED: printf("Maximum allowed"); break;
	default:
		if ((right&DELETE) != 0)
			printf("*Delete access ");
		if ((right&READ_CONTROL) != 0)
			printf("*Read access to the owner, group, and DACL ");
		if ((right&WRITE_DAC) != 0)
			printf("*Write access to the DACL ");
		if ((right&WRITE_OWNER) != 0)
			printf("*Write access to owner ");
		if ((right&SYNCHRONIZE) != 0)
			printf("*Synchronize access ");
		break;
	}
	printf("\n");
}

//Настройка ключей
void SettingKeys(int key)
{
	// Создание контейнера ключей
	if (!CryptAcquireContext(&g_ctxs[key].hProv, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, NULL))
	{
		printf("CreateKeyContainer error\n");
		return;
	}

	// Создание пары закрытый/открытый ключ
	if (!CryptGenKey(g_ctxs[key].hProv, AT_KEYEXCHANGE, 1024 << 16, &g_ctxs[key].Key))
	{
		printf("CreateSessionKey error");
		return;
	}

	// Получение открытого ключа
	if (!CryptGetUserKey(g_ctxs[key].hProv, AT_KEYEXCHANGE, &g_ctxs[key].PublicKey))
	{
		printf("GetPublicKey error");
		return;
	}

	// Получение закрытого ключа
	if (!CryptGetUserKey(g_ctxs[key].hProv, AT_KEYEXCHANGE, &g_ctxs[key].PrivateKey))
	{
		printf("GetPrivateKey error");
		return;
	}

	if (!CryptExportKey(g_ctxs[key].PublicKey, 0, PUBLICKEYBLOB, 0, NULL, &g_ctxs[key].SizeOfPublic))
	{
		printf("ExportPublicKey error_1");
		return;
	}

	g_ctxs[key].public_Key = (BYTE*)malloc(sizeof(BYTE) * g_ctxs[key].SizeOfPublic);
	memset(g_ctxs[key].public_Key, NULL, g_ctxs[key].SizeOfPublic * sizeof(BYTE));

	if (!CryptExportKey(g_ctxs[key].PublicKey, 0, PUBLICKEYBLOB, 0, g_ctxs[key].public_Key, &g_ctxs[key].SizeOfPublic))
	{
		printf("ExportPublicKey error_2");
		return;
	}
}

int FindPort(int port)
{
	for (int i = 0; i <= count_server; i++)
		if (g_ctxs[i].port == port)
			return i;
	return -1;
}

int Client()
{
	// Validate the parameters
	int iResult;
	int recvbuflen = DEFAULT_BUFLEN;
	printf("Enter IP_addr:port\n");
	char buf_address[40] = { 0 };
	char *buf_IP, *buf_port;
	fgets(buf_address, 40, stdin);
	buf_IP = strtok(buf_address, ":");
	buf_port = buf_address + strlen(buf_IP) + 1;
	buf_port[strlen(buf_port) - 1] = 0;
	int key;

	memset(recvbuf, 0, sizeof(recvbuf));
	memset(sendbuf, 0, sizeof(sendbuf));

	if ((key=FindPort(atoi(buf_port)))==-1)
	{
		WSADATA wsaData;
		struct addrinfo *result = NULL, *ptr = NULL, hints;	

		g_ctxs[count_server].port = atoi(buf_port);
		// Initialize Winsock
		iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
		if (iResult != 0) {
			printf(" WSAStartup failed with error: %d\n", iResult);
			return 0;
		}

		ZeroMemory(&hints, sizeof(hints));
		hints.ai_family = AF_UNSPEC;
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_protocol = IPPROTO_TCP;

		// Resolve the server address and port
		iResult = getaddrinfo(buf_IP, buf_port, &hints, &result);
		if (iResult != 0) {
			printf(" getaddrinfo failed with error: %d\n", iResult);
			WSACleanup();
			return 0;
		}

		// Attempt to connect to an address until one succeeds
		for (ptr = result; ptr != NULL; ptr = ptr->ai_next) {

			// Create a SOCKET for connecting to server
			g_ctxs[count_server].ConnectSocket = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
			if (g_ctxs[count_server].ConnectSocket == INVALID_SOCKET) {
				printf(" socket failed with error: %ld\n", WSAGetLastError());
				WSACleanup();
				return 0;
			}

			// Connect to server.
			iResult = connect(g_ctxs[count_server].ConnectSocket, ptr->ai_addr, (int)ptr->ai_addrlen);
			if (iResult == SOCKET_ERROR) {
				closesocket(g_ctxs[count_server].ConnectSocket);
				g_ctxs[count_server].ConnectSocket = INVALID_SOCKET;
				continue;
			}
			break;
		}

		freeaddrinfo(result);

		if (g_ctxs[count_server].ConnectSocket == INVALID_SOCKET) {
			printf(" unable to connect to server!\n");
			WSACleanup();
			return 0;
		}

		// гененрируем пару ключей
		SettingKeys(count_server);

		//отправка длины ключа и ключа
		itoa(g_ctxs[count_server].SizeOfPublic, sendbuf, 10);
		sendbuf[strlen(sendbuf)] = ' ';
		int shift = strlen(sendbuf);
		memcpy(sendbuf + strlen(sendbuf), (char*)g_ctxs[count_server].public_Key, g_ctxs[count_server].SizeOfPublic);
		sendbuf[g_ctxs[count_server].SizeOfPublic + shift] = '\n';

		iResult = send(g_ctxs[count_server].ConnectSocket, sendbuf, g_ctxs[count_server].SizeOfPublic + shift + 1, 0);
		if (iResult == SOCKET_ERROR) {
			printf(" send failed with error: %d\n", WSAGetLastError());
			closesocket(g_ctxs[count_server].ConnectSocket);
			WSACleanup();
			return 0;
		}

		//получения длины ключа и самого ключа (сеансовый)
		iResult = recv(g_ctxs[count_server].ConnectSocket, recvbuf, sizeof(recvbuf), 0);

		char *tmp = strtok(recvbuf, " ");
		g_ctxs[count_server].SessionKeyLenght = atoi(tmp);
		char *key_recv = recvbuf + strlen(tmp) + 1;

		if (!CryptImportKey(g_ctxs[count_server].hProv, (BYTE*)key_recv, g_ctxs[count_server].SessionKeyLenght, g_ctxs[count_server].PrivateKey, NULL, &g_ctxs[count_server].SessionKey))
		{
			printf("ImportPublicKey error");
			return 0;
		}
		key = count_server;
		count_server++;
		printf(" connection successfull\n\n");
	}

	printf("Commands:\n\
		os			-	OS type and version\n\
		time_c			-	current time\n\
		time_b			-	boot time since the OS was launched\n\
		memory			-	information about the memory used\n\
		disk_t			-	types of attached disks\n\
		disk_f			-	free space on local disks\n\
		access PATH		-	access right\n\
		owner PATH		-	owner of the file/folder/registry key\n\
		change_s		-	change server\n\
		exit			-	shut down\n");
	char command[2048] = { 0 };
	while (1)
	{
		printf("# ");
		memset(recvbuf, 0, sizeof(recvbuf));
		memset(sendbuf, 0, sizeof(sendbuf));
		fgets(command, 2048, stdin);
		strcpy(sendbuf, command);

		if (!strncmp(command, "exit", strlen("exit")))
		{
			// shutdown the connection since no more data will be sent
			for (int i = 0; i < count_server; i++)
			{
				iResult = shutdown(g_ctxs[i].ConnectSocket, SD_SEND);
				if (iResult == SOCKET_ERROR) {
					printf("shutdown failed with error: %d\n", WSAGetLastError());
					closesocket(g_ctxs[i].ConnectSocket);
					WSACleanup();
					return 0;
				}
			}
			return 0;
		}
		if (!strncmp(command, "change_s", strlen("change_s")))
		{
			return 1;
		}
		DWORD length = strlen(sendbuf) + 1;
		if (CryptEncrypt(g_ctxs[key].SessionKey, NULL, TRUE, NULL, (BYTE*)sendbuf, &length, sizeof(sendbuf)))
		{
			// Send an initial buffer
			iResult = send(g_ctxs[key].ConnectSocket, sendbuf, length, 0);
			if (iResult == SOCKET_ERROR) {
				printf(" send failed with error: %d\n", WSAGetLastError());
				closesocket(g_ctxs[key].ConnectSocket);
				WSACleanup();
				return 0;
			}
			iResult = send(g_ctxs[key].ConnectSocket, "\n", 1, 0);
			memset(sendbuf, 0, sizeof(sendbuf));
		}
		else
		{
			printf("Encryption error\n");
			return 0;
		}

		// Receive until the peer closes the connection
		memset(recvbuf, 0, sizeof(recvbuf));
		iResult = recv(g_ctxs[key].ConnectSocket, recvbuf, recvbuflen, 0);
		if (iResult == 0)
		{
			printf(" connection closed\n");
		}
		else if (iResult < 0)
		{
			printf(" recv failed with error: %d\n", WSAGetLastError());
			break;
		}

		for (length = DEFAULT_BUFLEN; length >= 0; length--)
			if (recvbuf[length] == '\n')
				break;

		if (!CryptDecrypt(g_ctxs[key].SessionKey, NULL, TRUE, NULL, (BYTE*)recvbuf, &length))
		{
			printf("Decryption error\n");
			return 0;
		}

		if (!strncmp(recvbuf, "path entered incorrectly", strlen("path entered incorrectly")))
			printf("%s", recvbuf);
		else if (!strncmp(recvbuf, "unknow command", strlen("unknow command")))
			printf("%s", recvbuf);
		else if (!strncmp(command, "owner", strlen("owner")))
		{
			char *SID, *name_tmp, *lenName;
			wchar_t name[100] = { 0 };
			SID = strtok(recvbuf, " ");
			lenName = strtok(NULL, " ");
			name_tmp = recvbuf + strlen(SID) + +strlen(lenName) + 2;
			name_tmp = strtok(name_tmp, "*");
			for (int i = 0; i < atoi(lenName); i++)
			{
				name[i] = atoi(name_tmp);
				name_tmp = strtok(NULL, "*");
			}
			//name = recvbuf + strlen(SID)+1;
			printf("SID: %s  name: ", SID);
			_setmode(_fileno(stdout), _O_U16TEXT);
			wprintf((wchar_t*)name);
			_setmode(_fileno(stdout), _O_TEXT);
			printf("\n\n");
		}
		else if (!strncmp(command, "access", strlen("access")))
		{
			int lenRight = 0, lenRecv = strlen(recvbuf) - 1;
			while (lenRight < lenRecv)
			{
				char *SID, *typeACE, *lenName, *Mask, *name_tmp;
				wchar_t name[100] = { 0 };
				SID = strtok(recvbuf + lenRight, " ");
				typeACE = strtok(NULL, " ");
				Mask = strtok(NULL, " ");
				lenName = strtok(NULL, " ");
				lenRight += strlen(SID) + strlen(typeACE) + strlen(Mask) + strlen(lenName) + 5;
				name_tmp = strtok(NULL, ";");
				//strncpy(name, recvbuf + lenRight, atoi(lenName));
				lenRight += strlen(name_tmp) + 1;
				//printf("name: %s\n", name_tmp);
				name_tmp = strtok(name_tmp, "*");
				for (int i = 0; i < atoi(lenName); i++)
				{
					name[i] = atoi(name_tmp);
					name_tmp = strtok(NULL, "*");
				}
				printf("SUD: %s; ", SID);
				_setmode(_fileno(stdout), _O_U16TEXT);
				wprintf((wchar_t*)name);
				_setmode(_fileno(stdout), _O_TEXT);
				printf("; TypeACE: %s\n", typeACE);
				FindRights(atoi(Mask));
			}
			printf("\n");
		}
		else
			printf("%s", recvbuf);
	}
	// cleanup
	closesocket(g_ctxs[key].ConnectSocket);
	WSACleanup();
}

int main()
{
	memset(g_ctxs, 0, sizeof(g_ctxs));
	while (1)
	{
		if (!Client())
			break;
	}

	return 0;
}