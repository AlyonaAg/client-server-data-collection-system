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
	CHAR buf_recv[DEFAULT_BUFLEN];					// ����� ������
	CHAR buf_send[DEFAULT_BUFLEN];					// ����� ��������
	unsigned int sz_recv = { 0 };			// ������� ������
	unsigned int sz_send_total = { 0 };		// ������ � ������ ��������
	unsigned int sz_send = { 0 };			// ������ ����������

	// ��������� OVERLAPPED ��� ����������� � ����������
	OVERLAPPED overlap_recv;
	OVERLAPPED overlap_send;
	OVERLAPPED overlap_cancel;

	char SessionKey;				// ������
	HCRYPTKEY hSessionKey;
	DWORD SessionKeyLength = 0;

	DWORD flags_recv;				// ����� ��� WSARecv
};

// �������������� ����� � ��� ������ ����������� ��������
// � ������� �������� (������ � overlapped � ��������)
struct client_ctx g_ctxs[1 + MAX_CLIENTS];
int g_accepted_socket;
HANDLE g_io_port;

// ������� �������� �������� ������ �� ������
void schedule_read(DWORD idx)
{
	WSABUF buf;														//��������� WSABUF ��������� ��������� ��� �������������� ������� ������
	buf.buf = g_ctxs[idx].buf_recv + g_ctxs[idx].sz_recv;			//��������� �� �����
	buf.len = sizeof(g_ctxs[idx].buf_recv) - g_ctxs[idx].sz_recv;	//����� ������
	memset(&g_ctxs[idx].overlap_recv, 0, sizeof(OVERLAPPED));
	g_ctxs[idx].flags_recv = 0;
	WSARecv(g_ctxs[idx].socket, &buf, 1, NULL, &g_ctxs[idx].flags_recv, &g_ctxs[idx].overlap_recv, NULL);
}

// ������� �������� �������� �������� �������������� ������ � �����
void schedule_write(DWORD idx)
{
	WSABUF buf; 													//��������� WSABUF ��������� ��������� ��� �������������� ������� ������
	buf.buf = g_ctxs[idx].buf_send + g_ctxs[idx].sz_send;			//��������� �� �����
	buf.len = g_ctxs[idx].sz_send_total - g_ctxs[idx].sz_send;		//����� ������
	memset(&g_ctxs[idx].overlap_send, 0, sizeof(OVERLAPPED));
	WSASend(g_ctxs[idx].socket, &buf, 1, NULL, 0, &g_ctxs[idx].overlap_send, NULL);
}

// ������� ��������� ����� �������� ����������� �������
void add_accepted_connection()
{
	DWORD i; // ����� ����� � ������� g_ctxs ��� ������� ������ �����������
	for (i = 0; i < sizeof(g_ctxs) / sizeof(g_ctxs[0]); i++)
	{
		if (g_ctxs[i].socket == 0)
		{
			unsigned int ip = 0;
			struct sockaddr_in* local_addr = 0, *remote_addr = 0;
			int local_addr_sz, remote_addr_sz;

			// ������� GetAcceptExSockaddrs(), ���������� ��� �������������� 
			//���������� � ���������� �������, ���������� ��� ������ AcceptEx() 
			//� ������������� �� ������� ������ lpOutputclosed.
			GetAcceptExSockaddrs(g_ctxs[0].buf_recv, g_ctxs[0].sz_recv, sizeof(struct sockaddr_in) + 16,
				sizeof(struct sockaddr_in) + 16, (struct sockaddr **) &local_addr, &local_addr_sz, (struct sockaddr **) &remote_addr,
				&remote_addr_sz);

			if (remote_addr) ip = ntohl(remote_addr->sin_addr.s_addr);
			printf(" connection %u created, remote IP: %u.%u.%u.%u\n", i, (ip >> 24) & 0xff, (ip >> 16) & 0xff, (ip >> 8) & 0xff, (ip)& 0xff);

			g_ctxs[i].socket = g_accepted_socket;
			g_ctxs[i].SessionKey = 0;
			// ����� ������ � ������ IOCP, � �������� key ������������ ������ �������
			if (NULL == CreateIoCompletionPort((HANDLE)g_ctxs[i].socket, g_io_port, i, 0))
			{
				printf("CreateIoCompletionPort error: %x\n", GetLastError());
				return;
			}
			// �������� ������ �� ������
			schedule_read(i);
			return;
		}
	}
	// ����� �� ������� => ��� �������� ��� �������� ����������
	closesocket(g_accepted_socket);
	g_accepted_socket = 0;
}

// ������� �������� �������� ������ ����������
void schedule_accept()
{
	// �������� ������ ��� �������� ����������� (AcceptEx �� ������� �������)
	g_accepted_socket = WSASocket(AF_INET, SOCK_STREAM, 0, NULL, 0, WSA_FLAG_OVERLAPPED);
	memset(&g_ctxs[0].overlap_recv, 0, sizeof(OVERLAPPED));
	// �������� �����������.
	// ��� ������ �������� ����� ��������� - ���� ���������� ������� �����������. 
	// ������� ������� ������ ���� �� 16 ���� ������ ������� ������ �������� ������������ ������������ ��
	AcceptEx(g_ctxs[0].socket, g_accepted_socket, g_ctxs[0].buf_recv, 0, sizeof(struct sockaddr_in) + 16, sizeof(struct sockaddr_in) + 16, NULL, &g_ctxs[0].overlap_recv);
}

// ���������, ��� ������ ������ ���������
int is_string_received(DWORD idx, int* len)
{
	DWORD i;
	// ���� '\n'
	for (i = 0; i < g_ctxs[idx].sz_recv; i++)
	{
		if (g_ctxs[idx].buf_recv[i] == '\n')
		{
			*len = (int)(i + 1);
			return 1;
		}
	}
	// ���� �������� �� ��������
	if (g_ctxs[idx].sz_recv == sizeof(g_ctxs[idx].buf_recv))
	{

		*len = sizeof(g_ctxs[idx].buf_recv);
		return 1;
	}
	return 0; // ������ ���������� �� �� �����
}

// ���������� �� ��
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

// ������� �����
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

// ����� ��������� �� ������� ��
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

// ������������ ������
void memory(ULONG_PTR key)
{
	MEMORYSTATUS stat;
	GlobalMemoryStatus(&stat);
	sprintf(g_ctxs[key].buf_send, "%lu%% load\n%lub/%lub TOTAL/FREE PHYS.MEMORY\n%lub/%lub MAX/FREE FOR PROGRAMMS\n%lub/%lub MAX/FREE VIRT.MEMORY\n", stat.dwMemoryLoad, stat.dwTotalPhys, stat.dwAvailPhys, stat.dwTotalPageFile, stat.dwAvailPageFile, stat.dwTotalVirtual, stat.dwAvailVirtual);
}

// ���� ������
void disk_type(ULONG_PTR key)
{
	int n;
	bool Flag;
	DWORD dr = GetLogicalDrives(); // ������� ���������� ������� �����
	char disks[26][4] = { 0 }, str[15] = { 0 };
	for (int x = 0; x < 26; x++) // ���������� ������ �� �����
	{
		n = ((dr >> x) & 1); // ����� �������� �������� ����
		if (n) // ���� ������� - ���� � ������� x ����
		{
			disks[x][0] = ((char)(65 + x)); // �������� ������ �����
			disks[x][1] = ':';
			disks[x][2] = '\\';

			strcat(g_ctxs[key].buf_send, disks[x]);
			UINT drive_type = GetDriveTypeA(disks[x]); // ����� ��� �����
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

// ��������� ������������ �� ������
void disk_free(ULONG_PTR key)
{
	int n;
	bool Flag;
	DWORD dr = GetLogicalDrives(); // ������� ���������� ������� �����
	char disks[26][4] = { 0 }, str[15] = { 0 };
	for (int x = 0; x < 26; x++) // ���������� ������ �� �����
	{
		n = ((dr >> x) & 1); // ����� �������� �������� ����
		if (n) // ���� ������� - ���� � ������� x ����
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

// ���� ACE
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

// ����� ������� � ���������� �����/�����/����� �������
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
		if (LookupAccountSid(NULL, pSID, (LPWSTR)name, (LPDWORD)&LenName, (LPWSTR)Domain, (LPDWORD)&LenDom, &Type) != 0)//�������� ��� � ����� ����������
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

// �������� �����/�����/����� �������
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

// ��������� �������� �������
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

// �������� ������ ���������� �����-������
void io_serv()
{
	WSADATA wsa_data;									// �������� ���������� � ���������� �������
	if (WSAStartup(MAKEWORD(2, 2), &wsa_data) == 0)		// ���������� ������������� ���������� Winsock, ��������� � ������� ������ 2.2 Winsock
	{
		printf("WSAStartup ok\n");
	}
	else
	{
		printf("WSAStartup error\n");
	}
	struct sockaddr_in addr;
	// �������� ������ �������������
	SOCKET s = WSASocket(AF_INET, SOCK_STREAM, 0, NULL, 0, WSA_FLAG_OVERLAPPED);
	// �������� ����� ����������
	g_io_port = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0); //1� �������� - ���������� �������� ����� ���  INVALID_HANDLE_VALUE(�� ��������� � ������������)
	if (NULL == g_io_port)
	{
		printf("CreateIoCompletionPort error: %x\n", GetLastError());
		return;
	}
	// ��������� ��������� ������ ��� �������� �������� ����������
	memset(g_ctxs, 0, sizeof(g_ctxs));
	memset(&addr, 0, sizeof(addr)); 
	addr.sin_family = AF_INET; 
	printf("Enter port: ");
	int port;
	cin >> port;
	addr.sin_port = htons(port);
	// ���������� ���������� ������ � �������
	if (bind(s, (struct sockaddr*) &addr, sizeof(addr)) < 0 || listen(s, 1) < 0) 
	{ 
		printf("error bind() or listen()\n"); 
		return; 
	}
	printf("Listening: %hu\n", ntohs(addr.sin_port));
	// ������������� ������������� ������ s � ����� io_port.
	// � �������� ����� ��� ��������������� ������ ������������ 0
	if (NULL == CreateIoCompletionPort((HANDLE)s, g_io_port, 0, 0))
	{
		printf("CreateIoCompletionPort error: %x\n", GetLastError());
		return;
	}
	g_ctxs[0].socket = s;
	// ����� �������� �������� �����������.
	schedule_accept();
	// ����������� ���� �������� ������� � ����������� ���������
	while (1)
	{
		DWORD transferred;						// ������������ ����� ��� �������� �������
		ULONG_PTR key;							// ��� ���������� ����� ��� �������� �������
		OVERLAPPED* lp_overlap;					// ����� ��� �������� �������
		// �������� ������� � ������� 1 �������
		BOOL b = GetQueuedCompletionStatus(g_io_port, &transferred, &key, &lp_overlap, 5000);
		if (b)
		{
			// ��������� ����������� � ���������� ��������
			if (key == 0) // ���� 0 - ��� ��������������� ������
			{
				g_ctxs[0].sz_recv += transferred;
				// �������� ������ ����������� � ������ �������� �������� ����������
				add_accepted_connection();
				schedule_accept();
			}
			else
			{
				// ����� ��������� ������� �� ���������� �������� �� �������. 
				// ���� key - ������ � ������� g_ctxs 
				// ���������� ����������� �� ���� ������
				if (&g_ctxs[key].overlap_recv == lp_overlap)
				{
					int len;
					// ������ �������:
					if (transferred == 0)
					{
						// ���������� ���������
						// ������ ������������� ��������
						CancelIo((HANDLE)g_ctxs[key].socket);		
						// �������� ����� ���������� �������� ����� - ������ � ���� ���������� I/O
						PostQueuedCompletionStatus(g_io_port, 0, key, &g_ctxs[key].overlap_cancel);
						continue;
					}
					g_ctxs[key].sz_recv += transferred;
					if (is_string_received(key, &len))
					{
						memset(g_ctxs[key].buf_send, 0, sizeof(g_ctxs[key].buf_send));
						if (!g_ctxs[key].SessionKey)
						{
							// ��������� ����������� ��������� �����
							char *tmp = strtok(g_ctxs[key].buf_recv, " ");
							publicKeyLength = atoi(tmp);
							printf("%d\n", publicKeyLength);						
							char *key_recv = g_ctxs[key].buf_recv + strlen(tmp) + 1;
							key_recv[strlen(key_recv)] = 0;

							create_key_container();
							// ��������� ���������� �����
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
							
							// �������� ���������� �����
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
							// ���� ������ ��������� ������, �� ������������ ����� � ������ ��� ����������
							client_request(key, len);
						}
					}
					else
					{
						// ����� - ���� ������ ������
						schedule_read(key);
					}
				}
				// ���������� ����������� �� �������� ������
				else if (&g_ctxs[key].overlap_send == lp_overlap)
				{
					// ������ ����������
					g_ctxs[key].sz_send += transferred;
					if (g_ctxs[key].sz_send < g_ctxs[key].sz_send_total && transferred > 0)
					{
						// ���� ������ ���������� �� ��������� - ���������� ����������
						schedule_write(key);
					}
					else
					{
						// ������ ���������� ���������, �������� ��� ������������,
						// �������� � ���� ������� �� ���������� ������
						memset(g_ctxs[key].buf_send, 0, g_ctxs[key].sz_send_total);
						g_ctxs[key].sz_recv = 0;
						memset(g_ctxs[key].buf_send, 0, DEFAULT_BUFLEN);
						schedule_read(key);
					}
				}
				else if (&g_ctxs[key].overlap_cancel == lp_overlap)
				{
					// ��� ������������ ���������, ����� ����� ���� ������
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