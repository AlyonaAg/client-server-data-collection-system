#include <winsock2.h>
#include <iostream>
#include <windows.h>
#include <mswsock.h>
#include <AclAPI.h>
#include <stdio.h>
#include <VersionHelpers.h>
#include <string>
#include <string.h>
#include <conio.h>
#include <ws2tcpip.h> 
#include <fcntl.h>
#include <io.h>
#include <wincrypt.h>
#include <Sddl.h>
#include <locale.h>


#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "mswsock.lib")

#define MAX_CLIENTS (100)
#define WIN32_LEAN_AND_MEAN
#define DEFAULT_BUFLEN 4096


HCRYPTPROV hProv = 0;
HCRYPTKEY publicKey = 0;
//HCRYPTKEY sessionKey = 0;
HCRYPTKEY Key = 0;

DWORD publicKeyLength = 0;

using namespace std;

struct client_ctx
{
	int socket;
	CHAR buf_recv[DEFAULT_BUFLEN];					// Буфер приема
	CHAR buf_send[DEFAULT_BUFLEN];					// Буфер отправки
	unsigned int sz_recv = { 0 };			// Принято данных
	unsigned int sz_send_total = { 0 };		// Данных в буфере отправки
	unsigned int sz_send = { 0 };			// Данных отправлено

	// Структуры OVERLAPPED для уведомлений о завершении
	OVERLAPPED overlap_recv;
	OVERLAPPED overlap_send;
	OVERLAPPED overlap_cancel;

	char SessionKey;				// флажок
	HCRYPTKEY hSessionKey;
	DWORD SessionKeyLength = 0;

	DWORD flags_recv;				// Флаги для WSARecv
};

// Прослушивающий сокет и все сокеты подключения хранятся
// в массиве структур (вместе с overlapped и буферами)
struct client_ctx g_ctxs[1 + MAX_CLIENTS];
int g_accepted_socket;
HANDLE g_io_port;

// Функция стартует операцию чтения из сокета
void schedule_read(DWORD idx)
{
	WSABUF buf;														//Структура WSABUF позволяет создавать или манипулировать буфером данных
	buf.buf = g_ctxs[idx].buf_recv + g_ctxs[idx].sz_recv;			//указатель на буфер
	buf.len = sizeof(g_ctxs[idx].buf_recv) - g_ctxs[idx].sz_recv;	//длина буфера
	memset(&g_ctxs[idx].overlap_recv, 0, sizeof(OVERLAPPED));
	g_ctxs[idx].flags_recv = 0;
	WSARecv(g_ctxs[idx].socket, &buf, 1, NULL, &g_ctxs[idx].flags_recv, &g_ctxs[idx].overlap_recv, NULL);
}

// Функция стартует операцию отправки подготовленных данных в сокет
void schedule_write(DWORD idx)
{
	WSABUF buf; 													//Структура WSABUF позволяет создавать или манипулировать буфером данных
	buf.buf = g_ctxs[idx].buf_send + g_ctxs[idx].sz_send;			//указатель на буфер
	buf.len = g_ctxs[idx].sz_send_total - g_ctxs[idx].sz_send;		//длина буфера
	memset(&g_ctxs[idx].overlap_send, 0, sizeof(OVERLAPPED));
	WSASend(g_ctxs[idx].socket, &buf, 1, NULL, 0, &g_ctxs[idx].overlap_send, NULL);
}

// Функция добавляет новое принятое подключение клиента
void add_accepted_connection()
{
	DWORD i; // Поиск места в массиве g_ctxs для вставки нового подключения
	for (i = 0; i < sizeof(g_ctxs) / sizeof(g_ctxs[0]); i++)
	{
		if (g_ctxs[i].socket == 0)
		{
			unsigned int ip = 0;
			struct sockaddr_in* local_addr = 0, *remote_addr = 0;
			int local_addr_sz, remote_addr_sz;

			// Функция GetAcceptExSockaddrs(), необходима для преобразования 
			//локального и удаленного адресов, полученных при вызове AcceptEx() 
			//и расположенных во входном буфере lpOutputclosed.
			GetAcceptExSockaddrs(g_ctxs[0].buf_recv, g_ctxs[0].sz_recv, sizeof(struct sockaddr_in) + 16,
				sizeof(struct sockaddr_in) + 16, (struct sockaddr **) &local_addr, &local_addr_sz, (struct sockaddr **) &remote_addr,
				&remote_addr_sz);

			if (remote_addr) ip = ntohl(remote_addr->sin_addr.s_addr);
			printf(" connection %u created, remote IP: %u.%u.%u.%u\n", i, (ip >> 24) & 0xff, (ip >> 16) & 0xff, (ip >> 8) & 0xff, (ip)& 0xff);

			g_ctxs[i].socket = g_accepted_socket;
			g_ctxs[i].SessionKey = 0;
			// Связь сокета с портом IOCP, в качестве key используется индекс массива
			if (NULL == CreateIoCompletionPort((HANDLE)g_ctxs[i].socket, g_io_port, i, 0))
			{
				printf("CreateIoCompletionPort error: %x\n", GetLastError());
				return;
			}
			// Ожидание данных от сокета
			schedule_read(i);
			return;
		}
	}
	// Место не найдено => нет ресурсов для принятия соединения
	closesocket(g_accepted_socket);
	g_accepted_socket = 0;
}

// Функция стартует операцию приема соединения
void schedule_accept()
{
	// Создание сокета для принятия подключения (AcceptEx не создает сокетов)
	g_accepted_socket = WSASocket(AF_INET, SOCK_STREAM, 0, NULL, 0, WSA_FLAG_OVERLAPPED);
	memset(&g_ctxs[0].overlap_recv, 0, sizeof(OVERLAPPED));
	// Принятие подключения.
	// Как только операция будет завершена - порт завершения пришлет уведомление. 
	// Размеры буферов должны быть на 16 байт больше размера адреса согласно документации разработчика ОС
	AcceptEx(g_ctxs[0].socket, g_accepted_socket, g_ctxs[0].buf_recv, 0, sizeof(struct sockaddr_in) + 16, sizeof(struct sockaddr_in) + 16, NULL, &g_ctxs[0].overlap_recv);
}

// Проверяем, что строка пришла полностью
int is_string_received(DWORD idx, int* len)
{
	DWORD i;
	// Ищем '\n'
	for (i = 0; i < g_ctxs[idx].sz_recv; i++)
	{
		if (g_ctxs[idx].buf_recv[i] == '\n')
		{
			*len = (int)(i + 1);
			return 1;
		}
	}
	// Если заполнен на максимум
	if (g_ctxs[idx].sz_recv == sizeof(g_ctxs[idx].buf_recv))
	{

		*len = sizeof(g_ctxs[idx].buf_recv);
		return 1;
	}
	return 0; // Строка отправлена не до конца
}

// Информация об ОС
void OS_version(ULONG_PTR key)
{
	HKEY rKey;
	WCHAR Reget[512];
	DWORD RegetPath = sizeof(Reget);
	if (!RegOpenKeyEx(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", 0, KEY_QUERY_VALUE, &rKey))
	{
		RegQueryValueEx(rKey, L"ProductName", NULL, NULL, (LPBYTE)Reget, &RegetPath);
		RegCloseKey(rKey);

		sprintf(g_ctxs[key].buf_send, "%ls\n", Reget);
	}
	else
		printf(" error getting data about the operating system\n");
}

// Текущее время
void time_current(ULONG_PTR key)
{
	SYSTEMTIME sm;
	GetSystemTime(&sm);

	char time_buf[8] = { 0 };

	if (sm.wDay<10)
		strcat(g_ctxs[key].buf_send, "0");
	itoa(sm.wDay, time_buf, 10);
	strcat(g_ctxs[key].buf_send, time_buf);
	strcat(g_ctxs[key].buf_send, ".");

	if (sm.wMonth<10)
		strcat(g_ctxs[key].buf_send, "0");
	itoa(sm.wMonth, time_buf, 10);
	strcat(g_ctxs[key].buf_send, time_buf);
	strcat(g_ctxs[key].buf_send, ".");

	itoa(sm.wYear, time_buf, 10);
	strcat(g_ctxs[key].buf_send, time_buf);
	strcat(g_ctxs[key].buf_send, " ");

	if (sm.wHour + 3<10)
		strcat(g_ctxs[key].buf_send, "0");
	itoa(sm.wHour + 3, time_buf, 10);
	strcat(g_ctxs[key].buf_send, time_buf);
	strcat(g_ctxs[key].buf_send, ":");

	if (sm.wMinute<10)
		strcat(g_ctxs[key].buf_send, "0");
	itoa(sm.wMinute, time_buf, 10);
	strcat(g_ctxs[key].buf_send, time_buf);
	strcat(g_ctxs[key].buf_send, ":");

	if (sm.wSecond<10)
		strcat(g_ctxs[key].buf_send, "0");
	itoa(sm.wSecond, time_buf, 10);
	strcat(g_ctxs[key].buf_send, time_buf);
	strcat(g_ctxs[key].buf_send, ".");

	if (sm.wMilliseconds<10)
		strcat(g_ctxs[key].buf_send, "0");
	itoa(sm.wMilliseconds, time_buf, 10);
	strcat(g_ctxs[key].buf_send, time_buf);
	g_ctxs[key].buf_send[strlen(g_ctxs[key].buf_send)] = '\n';
}

// Время прошедшее от запуска ОС
void time_bool(ULONG_PTR key)
{
	unsigned int hour, min, sec, msec = GetTickCount();
	char time_buf[8] = { 0 };

	itoa(hour = msec / (1000 * 60 * 60), time_buf, 10);
	strcat(g_ctxs[key].buf_send, time_buf);
	strcat(g_ctxs[key].buf_send, ":");

	itoa(min = msec / (1000 * 60) - hour * 60, time_buf, 10);
	if (min < 10)
		strcat(g_ctxs[key].buf_send,"0");
	strcat(g_ctxs[key].buf_send, time_buf);
	strcat(g_ctxs[key].buf_send, ":");

	itoa(sec = (msec / 1000) - (hour * 60 * 60) - min * 60, time_buf, 10);
	if (sec < 10)
		strcat(g_ctxs[key].buf_send, "0");
	strcat(g_ctxs[key].buf_send, time_buf);
	g_ctxs[key].buf_send[strlen(g_ctxs[key].buf_send)] = '\n';
}

// Используемая память
void memory(ULONG_PTR key)
{
	MEMORYSTATUS stat;
	GlobalMemoryStatus(&stat);
	sprintf(g_ctxs[key].buf_send, "%lu%% load\n%lub/%lub TOTAL/FREE PHYS.MEMORY\n%lub/%lub MAX/FREE FOR PROGRAMMS\n%lub/%lub MAX/FREE VIRT.MEMORY\n", stat.dwMemoryLoad, stat.dwTotalPhys, stat.dwAvailPhys, stat.dwTotalPageFile, stat.dwAvailPageFile, stat.dwTotalVirtual, stat.dwAvailVirtual);
}

// Типы дисков
void disk_type(ULONG_PTR key)
{
	int n;
	bool Flag;
	DWORD dr = GetLogicalDrives(); // функция возвращает битовую маску
	char disks[26][4] = { 0 }, str[15] = { 0 };
	for (int x = 0; x < 26; x++) // проходимся циклом по битам
	{
		n = ((dr >> x) & 1); // узнаём значение текущего бита
		if (n) // если единица - диск с номером x есть
		{
			disks[x][0] = ((char)(65 + x)); // получаем литеру диска
			disks[x][1] = ':';
			disks[x][2] = '\\';

			strcat(g_ctxs[key].buf_send, disks[x]);
			UINT drive_type = GetDriveTypeA(disks[x]); // узнаём тип диска
			if (drive_type == DRIVE_REMOVABLE)		strcat(g_ctxs[key].buf_send, " REMOVABLE");
			else if (drive_type == DRIVE_FIXED)		strcat(g_ctxs[key].buf_send, " FIXED");
			else if (drive_type == DRIVE_REMOTE)	strcat(g_ctxs[key].buf_send, " REMOTE");
			else if (drive_type == DRIVE_CDROM)		strcat(g_ctxs[key].buf_send, " CD-ROM");
			else if (drive_type == DRIVE_RAMDISK)	strcat(g_ctxs[key].buf_send, " RAMDISK");
			else strcat(g_ctxs[key].buf_send, " UNKNOW");

			char buf[64] = { '\0' };
			char fsname_buf[64] = { '\0' };
			DWORD snumber = 0;
			GetVolumeInformationA(disks[x], NULL, NULL, &snumber, NULL, NULL, fsname_buf, sizeof(fsname_buf));
			sprintf(g_ctxs[key].buf_send + strlen(g_ctxs[key].buf_send), " %s\n", fsname_buf);
		}
	}
}

// Свободное пространство на дисках
void disk_free(ULONG_PTR key)
{
	int n;
	bool Flag;
	DWORD dr = GetLogicalDrives(); // функция возвращает битовую маску
	char disks[26][4] = { 0 }, str[15] = { 0 };
	for (int x = 0; x < 26; x++) // проходимся циклом по битам
	{
		n = ((dr >> x) & 1); // узнаём значение текущего бита
		if (n) // если единица - диск с номером x есть
		{
			disks[x][0] = char(65 + x);
			disks[x][1] = ':';
			disks[x][2] = '\\';
			unsigned long long  s, b, f, c;
			if (GetDriveTypeA(disks[x]) == DRIVE_FIXED)
			{
				strcat(g_ctxs[key].buf_send, "FREE SPACE ");
				strcat(g_ctxs[key].buf_send, disks[x]);
				GetDiskFreeSpaceA(disks[x], (LPDWORD)&s, (LPDWORD)&b, (LPDWORD)&f, (LPDWORD)&c);
				unsigned long long freeSpace = (double)f * (double)s * (double)b / 1024.0 / 1024.0 / 1024.0 / 1024.0;
				sprintf(g_ctxs[key].buf_send + strlen(g_ctxs[key].buf_send), " %llu\n", freeSpace);
			}
		}
	}
}

// Типы ACE
void AceType(short type, ULONG_PTR key)
{
	switch (type)
	{
	case ACCESS_ALLOWED_ACE_TYPE:					strcat(g_ctxs[key].buf_send, " ACCESS_ALLOWED_ACE_TYPE "); break;
	case ACCESS_ALLOWED_CALLBACK_ACE_TYPE:			strcat(g_ctxs[key].buf_send, " ACCESS_ALLOWED_CALLBACK_ACE_TYPE "); break;
	case ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE:	strcat(g_ctxs[key].buf_send, " ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE "); break;
	case ACCESS_ALLOWED_COMPOUND_ACE_TYPE:			strcat(g_ctxs[key].buf_send, " ACCESS_ALLOWED_COMPOUND_ACE_TYPE "); break;
	case ACCESS_ALLOWED_OBJECT_ACE_TYPE:			strcat(g_ctxs[key].buf_send, " ACCESS_ALLOWED_OBJECT_ACE_TYPE "); break;
	case ACCESS_DENIED_ACE_TYPE:					strcat(g_ctxs[key].buf_send, " ACCESS_DENIED_ACE_TYPE "); break;
	case ACCESS_DENIED_CALLBACK_ACE_TYPE:			strcat(g_ctxs[key].buf_send, " ACCESS_DENIED_CALLBACK_ACE_TYPE "); break;
	case ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE:	strcat(g_ctxs[key].buf_send, " ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE "); break;
	case ACCESS_DENIED_OBJECT_ACE_TYPE:				strcat(g_ctxs[key].buf_send, " ACCESS_DENIED_OBJECT_ACE_TYPE "); break;
	case ACCESS_MAX_MS_ACE_TYPE:					strcat(g_ctxs[key].buf_send, " ACCESS_MAX_MS_ACE_TYPE "); break;
	case ACCESS_MAX_MS_V2_ACE_TYPE:					strcat(g_ctxs[key].buf_send, " ACCESS_MAX_MS_V2_ACE_TYPE "); break;
	case SYSTEM_ALARM_CALLBACK_ACE_TYPE:			strcat(g_ctxs[key].buf_send, " SYSTEM_ALARM_CALLBACK_ACE_TYPE "); break;
	case SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE:		strcat(g_ctxs[key].buf_send, " SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE "); break;
	case SYSTEM_AUDIT_ACE_TYPE:						strcat(g_ctxs[key].buf_send, " SYSTEM_AUDIT_ACE_TYPE "); break;
	case SYSTEM_AUDIT_CALLBACK_ACE_TYPE:			strcat(g_ctxs[key].buf_send, " SYSTEM_AUDIT_CALLBACK_ACE_TYPE "); break;
	case SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE:		strcat(g_ctxs[key].buf_send, " SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE "); break;
	case SYSTEM_AUDIT_OBJECT_ACE_TYPE:				strcat(g_ctxs[key].buf_send, " SYSTEM_AUDIT_OBJECT_ACE_TYPE "); break;
	case SYSTEM_MANDATORY_LABEL_ACE_TYPE:			strcat(g_ctxs[key].buf_send, " SYSTEM_MANDATORY_LABEL_ACE_TYPE "); break;
	default: strcat(g_ctxs[key].buf_send, " Unknown type of ACE "); break;
	}
	//strcat(g_ctxs[key].buf_send, "\n");
}

// Права доступа к указанному файлу/папке/ключу реестра
void access(ULONG_PTR key)
{
	char path[1024] = { 0 };
	strncpy(path, g_ctxs[key].buf_recv + strlen("access "), strlen(g_ctxs[key].buf_recv) - strlen("access ") - 1);

	PACL a;
	PSECURITY_DESCRIPTOR pSD;

	if (path[1] == ':')
	{
		if (GetNamedSecurityInfoA(path, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, &a, NULL, &pSD) != ERROR_SUCCESS)
		{
			strcpy(g_ctxs[key].buf_send, "path entered incorrectly_1\n\r");
			return;
		}
	}
	else if (!strncmp(path, "HKEY", strlen("HKEY")))
	{
		if (GetNamedSecurityInfoA(path, SE_REGISTRY_KEY, DACL_SECURITY_INFORMATION, NULL, NULL, &a, NULL, &pSD))
		{
			HKEY result = 0;
			int flag = 0;
			if (!strncmp(path, "HKEY_CLASSES_ROOT", strlen("HKEY_CLASSES_ROOT"))) 
				flag = RegOpenKeyA(HKEY_CLASSES_ROOT, (path + strlen("HKEY_CLASSES_ROOT\\")), &result);

			if (!strncmp(path, "HKEY_CURRENT_USER", strlen("HKEY_CURRENT_USER")))
				flag = RegOpenKeyA(HKEY_CURRENT_USER, (path + strlen("HKEY_CURRENT_USER\\")), &result);

			if (!strncmp(path, "HKEY_LOCAL_MACHINE", strlen("HKEY_LOCAL_MACHINE")))
				flag = RegOpenKeyA(HKEY_LOCAL_MACHINE, (path + strlen("HKEY_LOCAL_MACHINE\\")), &result);

			if (!strncmp(path, "HKEY_USERS", strlen("HKEY_USERS")))
				flag = RegOpenKeyA(HKEY_USERS, (path + strlen("HKEY_USERS\\")), &result);

			if (!strncmp(path, "HKEY_CURRENT_CONFIG", strlen("HKEY_CURRENT_CONFIG")))
				flag = RegOpenKeyA(HKEY_CURRENT_CONFIG, (path + strlen("HKEY_CURRENT_CONFIG\\")), &result);

			if (GetSecurityInfo(result, SE_REGISTRY_KEY, DACL_SECURITY_INFORMATION, NULL, NULL, &a, NULL, &pSD) != ERROR_SUCCESS)
			{
				strcpy(g_ctxs[key].buf_send, "path entered incorrectly");
				return;
			}
		}
	}
	else
	{
		strcpy(g_ctxs[key].buf_send, "path entered incorrectly_3\n\r");
		return;
	}

	if (a == NULL)
	{
		strcpy(g_ctxs[key].buf_send, "security descriptor has no DACL\n\r");
		return;
	}

	ACL_REVISION_INFORMATION *buf = (ACL_REVISION_INFORMATION*)malloc(sizeof(ACL_REVISION_INFORMATION));
	GetAclInformation(a, buf, sizeof(ACL_REVISION_INFORMATION), AclRevisionInformation);
	LPVOID AceInfo;

	short Type_ACE = 0;
	memset(g_ctxs[key].buf_send, 0, DEFAULT_BUFLEN);
	
	for (int i = 0; i < a->AceCount; i++)
	{
		GetAce(a, i, &AceInfo);
		ACCESS_ALLOWED_ACE *pACE = (ACCESS_ALLOWED_ACE*)AceInfo;
		PSID pSID;
		pSID = (PSID)(&(pACE->SidStart));
		TCHAR name[500] = { 0 }, Domain[500] = { 0 };
		unsigned int LenName = 500, LenDom = 500;
		SID_NAME_USE Type;
		if (LookupAccountSid(NULL, pSID, (LPWSTR)name, (LPDWORD)&LenName, (LPWSTR)Domain, (LPDWORD)&LenDom, &Type) != 0)//меняются имя и домен владельцев
		{
			itoa(pACE->SidStart, g_ctxs[key].buf_send + strlen(g_ctxs[key].buf_send), 10);
			sprintf(&g_ctxs[key].buf_send[strlen(g_ctxs[key].buf_send)], " ");
			Type_ACE = pACE->Header.AceType;
			AceType(Type, key);	
			sprintf(&g_ctxs[key].buf_send[strlen(g_ctxs[key].buf_send)], "%lu",pACE->Mask);
			strcat(g_ctxs[key].buf_send, " ");
			itoa(LenName, g_ctxs[key].buf_send + strlen(g_ctxs[key].buf_send), 10);
			strcat(g_ctxs[key].buf_send, " ");
			//strcat(g_ctxs[key].buf_send,  (char*)name);
			for (int i = 0; i < LenName; i++)
			{
				sprintf(&g_ctxs[key].buf_send[strlen(g_ctxs[key].buf_send)], "*");
				itoa(name[i], g_ctxs[key].buf_send + strlen(g_ctxs[key].buf_send), 10);
			}
			strcat(g_ctxs[key].buf_send, ";");
			//printf("%s\n", g_ctxs[key].buf_send);
		}
	}
}

// Владелец файла/папки/ключа реестра
void owner(ULONG_PTR key)
{
	char path[1024] = { 0 };
	strncpy(path, g_ctxs[key].buf_recv + strlen("owner "), strlen(g_ctxs[key].buf_recv) - strlen("owner ") - 1);

	PSID pOwnerSid;
	PSECURITY_DESCRIPTOR pSD;

	if (path[1] == ':')
	{
		if (GetNamedSecurityInfoA(path, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION, &pOwnerSid, NULL, NULL, NULL, &pSD) != ERROR_SUCCESS)
		{
			strcpy(g_ctxs[key].buf_send, "path entered incorrectly_1\n\r");
			return;
		}
	}
	else if (!strncmp(path, "HKEY", strlen("HKEY")))
	{
		if (GetNamedSecurityInfoA(path, SE_REGISTRY_KEY, OWNER_SECURITY_INFORMATION, &pOwnerSid, NULL, NULL, NULL, &pSD))
		{
			HKEY result = 0;
			int flag = 0;
			if (!strncmp(path, "HKEY_CLASSES_ROOT", strlen("HKEY_CLASSES_ROOT")))
				flag = RegOpenKeyA(HKEY_CLASSES_ROOT, (path + strlen("HKEY_CLASSES_ROOT\\")), &result);

			if (!strncmp(path, "HKEY_CURRENT_USER", strlen("HKEY_CURRENT_USER")))
				flag = RegOpenKeyA(HKEY_CURRENT_USER, (path + strlen("HKEY_CURRENT_USER\\")), &result);

			if (!strncmp(path, "HKEY_LOCAL_MACHINE", strlen("HKEY_LOCAL_MACHINE")))
				flag = RegOpenKeyA(HKEY_LOCAL_MACHINE, (path + strlen("HKEY_LOCAL_MACHINE\\")), &result);

			if (!strncmp(path, "HKEY_USERS", strlen("HKEY_USERS")))
				flag = RegOpenKeyA(HKEY_USERS, (path + strlen("HKEY_USERS\\")), &result);

			if (!strncmp(path, "HKEY_CURRENT_CONFIG", strlen("HKEY_CURRENT_CONFIG")))
				flag = RegOpenKeyA(HKEY_CURRENT_CONFIG, (path + strlen("HKEY_CURRENT_CONFIG\\")), &result);

			if (GetSecurityInfo(result, SE_REGISTRY_KEY, OWNER_SECURITY_INFORMATION, &pOwnerSid, NULL, NULL, NULL, &pSD) != ERROR_SUCCESS)
			{
				strcpy(g_ctxs[key].buf_send, "path entered incorrectly");
				return;
			}
		}
	}
	else
	{
		strcpy(g_ctxs[key].buf_send, "path entered incorrectly_3\n\r");
		return;
	}

	if (pOwnerSid == NULL)
	{
		strcpy(g_ctxs[key].buf_send, "security descriptor has no owner SID\n\r");
		return;
	}

	wchar_t name[500] = { 0 }, Domain[500] = { 0 };
	unsigned int LenName = 500, LenDom = 500;
	SID_NAME_USE SidName;
	DWORD SID;
	memcpy(&SID, pOwnerSid, sizeof(PSID));
	sprintf(g_ctxs[key].buf_send, "%i ", SID);
	LookupAccountSid(NULL, pOwnerSid, name, (LPDWORD)&LenName, Domain, (LPDWORD)&LenDom, &SidName);
	itoa(LenName, g_ctxs[key].buf_send + strlen(g_ctxs[key].buf_send), 10);
	strcat(g_ctxs[key].buf_send, " ");
	for (int i = 0; i < LenName; i++)
	{
		sprintf(&g_ctxs[key].buf_send[strlen(g_ctxs[key].buf_send)], "*");
		itoa(name[i], g_ctxs[key].buf_send + strlen(g_ctxs[key].buf_send), 10);
	}
	//strcpy(&g_ctxs[key].buf_send[strlen(g_ctxs[key].buf_send)], (char*)name);
//	strcat(g_ctxs[key].buf_send, "\n\r");
}

// Обработка запросов клиента
void client_request(ULONG_PTR key, int len)
{
	DWORD lenght = sizeof(g_ctxs[key].buf_recv);
	for (lenght = DEFAULT_BUFLEN; lenght >= 0; lenght--)
		if (g_ctxs[key].buf_recv[lenght] == '\n')
			break;
	if (!CryptDecrypt(g_ctxs[key].hSessionKey, NULL, TRUE, NULL, (BYTE*)g_ctxs[key].buf_recv, &lenght))
	{
		printf("Error: Decryption failed\n");
		return;
	}
	len = strlen(g_ctxs[key].buf_recv);
	printf(" request: %s", g_ctxs[key].buf_recv);
	memset(g_ctxs[key].buf_send, 0, sizeof(g_ctxs[key].buf_send));
	if (!strncmp(g_ctxs[key].buf_recv, "os", strlen("os")) && (strlen("os") == (len - 1)))
		OS_version(key);
	else if (!strncmp(g_ctxs[key].buf_recv, "time_c", strlen("time_c")) && (strlen("time_c") == len - 1))
		time_current(key);
	else if (!strncmp(g_ctxs[key].buf_recv, "time_b", strlen("time_b")) && (strlen("time_b") == len - 1))
		time_bool(key);
	else if (!strncmp(g_ctxs[key].buf_recv, "memory", strlen("memory")) && (strlen("memory") == len - 1))
		memory(key);
	else if (!strncmp(g_ctxs[key].buf_recv, "disk_t", strlen("disk_t")) && (strlen("disk_t") == len -1))
		disk_type(key);
	else if (!strncmp(g_ctxs[key].buf_recv, "disk_f", strlen("disk_f")) && (strlen("disk_f") == len - 1))
		disk_free(key);
	else if (!strncmp(g_ctxs[key].buf_recv, "access", strlen("access")) && (strlen("access") < len - 1))
		access(key);
	else if (!strncmp(g_ctxs[key].buf_recv, "owner", strlen("owner")) && (strlen("owner") < len - 1))
		owner(key);
	else
		sprintf(g_ctxs[key].buf_send, "unknow command\n");

	lenght = strlen(g_ctxs[key].buf_send);
	if (!CryptEncrypt(g_ctxs[key].hSessionKey, NULL, TRUE, NULL, (BYTE*)g_ctxs[key].buf_send, &lenght, sizeof(g_ctxs[key].buf_send)))
	{
		printf("Error: Encryption failed\n");
		return;
	}
	else
	{
		g_ctxs[key].sz_send_total = lenght+1;
		g_ctxs[key].sz_send = 0;
		memset(g_ctxs[key].buf_recv, 0, sizeof(g_ctxs[key].buf_recv));
		g_ctxs[key].buf_send[lenght] = '\n';
		schedule_write(key);
	}
}

void create_key_container(void) 
{
	if (CryptAcquireContextW(&hProv, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, NULL)) {
		printf("Cryptographic provider initialized\n");
	}
	else {
		if (GetLastError() == NTE_BAD_KEYSET) {
			// No default container was found. Attempt to create it.
			if (CryptAcquireContextW(&hProv, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, CRYPT_NEWKEYSET))
				printf("New Cryptographic container created\n");
			else
				printf("CreateKeyContainer\n");
		}
	}
}

// Механизм портов завершения ввода-вывода
void io_serv()
{
	WSADATA wsa_data;									// Содержит информацию о реализации сокетов
	if (WSAStartup(MAKEWORD(2, 2), &wsa_data) == 0)		// Инициирует использования библиотеки Winsock, установка в системе версии 2.2 Winsock
	{
		printf("WSAStartup ok\n");
	}
	else
	{
		printf("WSAStartup error\n");
	}
	struct sockaddr_in addr;
	// Создание сокета прослушивания
	SOCKET s = WSASocket(AF_INET, SOCK_STREAM, 0, NULL, 0, WSA_FLAG_OVERLAPPED);
	// Создание порта завершения
	g_io_port = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0); //1й параметр - дескриптор отрытого файла или  INVALID_HANDLE_VALUE(не связываем с дескриптором)
	if (NULL == g_io_port)
	{
		printf("CreateIoCompletionPort error: %x\n", GetLastError());
		return;
	}
	// Обнуление структуры данных для хранения входящих соединений
	memset(g_ctxs, 0, sizeof(g_ctxs));
	memset(&addr, 0, sizeof(addr)); 
	addr.sin_family = AF_INET; 
	printf("Enter port: ");
	int port;
	cin >> port;
	addr.sin_port = htons(port);
	// Связывание локального адреса с сокетом
	if (bind(s, (struct sockaddr*) &addr, sizeof(addr)) < 0 || listen(s, 1) < 0) 
	{ 
		printf("error bind() or listen()\n"); 
		return; 
	}
	printf("Listening: %hu\n", ntohs(addr.sin_port));
	// Присоединение существующего сокета s к порту io_port.
	// В качестве ключа для прослушивающего сокета используется 0
	if (NULL == CreateIoCompletionPort((HANDLE)s, g_io_port, 0, 0))
	{
		printf("CreateIoCompletionPort error: %x\n", GetLastError());
		return;
	}
	g_ctxs[0].socket = s;
	// Старт операции принятия подключения.
	schedule_accept();
	// Бесконечный цикл принятия событий о завершенных операциях
	while (1)
	{
		DWORD transferred;						// Передаваемые байты для ожидания событий
		ULONG_PTR key;							// Код завершения файла для ожидания событий
		OVERLAPPED* lp_overlap;					// Буфер для ожидания событий
		// Ожидание событий в течение 1 секунды
		BOOL b = GetQueuedCompletionStatus(g_io_port, &transferred, &key, &lp_overlap, 5000);
		if (b)
		{
			// Поступило уведомление о завершении операции
			if (key == 0) // ключ 0 - для прослушивающего сокета
			{
				g_ctxs[0].sz_recv += transferred;
				// Принятие нового подключения и начало операции принятия соединения
				add_accepted_connection();
				schedule_accept();
			}
			else
			{
				// Иначе поступило событие по завершению операции от клиента. 
				// Ключ key - индекс в массиве g_ctxs 
				// Сравниваем уведомления на приём данных
				if (&g_ctxs[key].overlap_recv == lp_overlap)
				{
					int len;
					// Данные приняты:
					if (transferred == 0)
					{
						// Соединение разорвано
						// Отмена назавершённых операций
						CancelIo((HANDLE)g_ctxs[key].socket);		
						// Помещает пакет завершения операции ввода - вывода в порт завершения I/O
						PostQueuedCompletionStatus(g_io_port, 0, key, &g_ctxs[key].overlap_cancel);
						continue;
					}
					g_ctxs[key].sz_recv += transferred;
					if (is_string_received(key, &len))
					{
						memset(g_ctxs[key].buf_send, 0, sizeof(g_ctxs[key].buf_send));
						if (!g_ctxs[key].SessionKey)
						{
							// Обработка полученного открытого ключа
							char *tmp = strtok(g_ctxs[key].buf_recv, " ");
							publicKeyLength = atoi(tmp);
							printf("%d\n", publicKeyLength);						
							char *key_recv = g_ctxs[key].buf_recv + strlen(tmp) + 1;
							key_recv[strlen(key_recv)] = 0;

							create_key_container();
							// Генерация сеансового ключа
							if (!CryptGenKey(hProv, CALG_RC4, CRYPT_EXPORTABLE | CRYPT_ENCRYPT | CRYPT_DECRYPT, &g_ctxs[key].hSessionKey))
							{
								printf("CryptGenKey error\n");
								return;
							}

							if (!CryptImportKey(hProv, (BYTE*)key_recv, publicKeyLength, NULL, NULL, &publicKey))
							{
								printf("CryptImportKey error %u\n", GetLastError());
								return;
							}
							if (!CryptExportKey(g_ctxs[key].hSessionKey, publicKey, SIMPLEBLOB, NULL, NULL, &g_ctxs[key].SessionKeyLength))
							{
								printf("CryptExportKey error");
								return;
							}
							
							// Отправка сеансового ключа
							itoa(g_ctxs[key].SessionKeyLength, g_ctxs[key].buf_send, 10);
							g_ctxs[key].buf_send[strlen(g_ctxs[key].buf_send)] = ' ';
							int shift = strlen(g_ctxs[key].buf_send);

							if (!CryptExportKey(g_ctxs[key].hSessionKey, publicKey, SIMPLEBLOB, NULL, (BYTE*)(g_ctxs[key].buf_send + strlen(g_ctxs[key].buf_send)), &g_ctxs[key].SessionKeyLength))
							{
								printf("CryptExportKey error");
								return;
							}

							g_ctxs[key].sz_send_total = g_ctxs[key].SessionKeyLength + shift;
							g_ctxs[key].sz_send = 0;
							memset(g_ctxs[key].buf_recv, 0, sizeof(g_ctxs[key].buf_recv));
							schedule_write(key);
							g_ctxs[key].SessionKey = 1;
						}
						else
						{
							// Если строка полностью пришла, то сформировать ответ и начать его отправлять
							client_request(key, len);
						}
					}
					else
					{
						// Иначе - ждем данные дальше
						schedule_read(key);
					}
				}
				// Сравниваем уведомления на отправку данных
				else if (&g_ctxs[key].overlap_send == lp_overlap)
				{
					// Данные отправлены
					g_ctxs[key].sz_send += transferred;
					if (g_ctxs[key].sz_send < g_ctxs[key].sz_send_total && transferred > 0)
					{
						// Если данные отправлены не полностью - продолжить отправлять
						schedule_write(key);
					}
					else
					{
						// Данные отправлены полностью, прервать все коммуникации,
						// добавить в порт событие на завершение работы
						memset(g_ctxs[key].buf_send, 0, g_ctxs[key].sz_send_total);
						g_ctxs[key].sz_recv = 0;
						memset(g_ctxs[key].buf_send, 0, DEFAULT_BUFLEN);
						schedule_read(key);
					}
				}
				else if (&g_ctxs[key].overlap_cancel == lp_overlap)
				{
					// Все коммуникации завершены, сокет может быть закрыт
					closesocket(g_ctxs[key].socket); 
					memset(&g_ctxs[key], 0, sizeof(g_ctxs[key]));
					printf(" connection %u closed\n", key);
				}
			}
		}

	}
}

int main()
{
	io_serv();
	int a;
	cin >> a;
	return 0;
}