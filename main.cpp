#define _CRT_SECURE_NO_WARNINGS
#include <iostream>
#include <Windows.h>
#include <conio.h>
#include <Ntsecapi.h>
#include <Lm.h>
using namespace std;

#define KEY_ARROW_UP 72
#define KEY_ARROW_DOWN 80
#define KEY_ENTER 13
#define MENU_MIN_ITEM 1
#define MENU_MAX_ITEM 12

NET_API_STATUS(NET_API_FUNCTION* NetUserEnum_)(LPCWSTR, DWORD, DWORD, LPBYTE*, DWORD, LPDWORD, LPDWORD, PDWORD);
//Функция NetUserEnum извлекает информацию обо всех учетных записях пользователей на сервере.
BOOL(WINAPI* LookupAccountNameW_)(LPCWSTR, LPCWSTR, PSID, LPDWORD, LPWSTR, LPDWORD, PSID_NAME_USE);
//Функция LookupAccountName принимает на вход имя системы и учетной записи. Он извлекает идентификатор безопасности (SID) для учетной записи и имя домена, в котором была найдена учетная запись
BOOL(WINAPI* ConvertSidToStringSidW_)(PSID, LPWSTR*);
//Функция ConvertSidToStringSid преобразует идентификатор безопасности (SID) в формат строки, подходящий для отображения, хранения или передачи
NTSTATUS(WINAPI* LsaEnumerateAccountRights_)(LSA_HANDLE, PSID, PLSA_UNICODE_STRING*, PULONG);
//Функция LsaEnumerateAccountRights перечисляет привилегии , назначенные учетной записи
NTSTATUS(WINAPI* LsaOpenPolicy_)(PLSA_UNICODE_STRING, PLSA_OBJECT_ATTRIBUTES, ACCESS_MASK, PLSA_HANDLE);
//Функция LsaOpenPolicy открывает дескриптор объекта Policy в локальной или удаленной системе.
NET_API_STATUS(NET_API_FUNCTION* NetApiBufferFree_)(_Frees_ptr_opt_ LPVOID);
//Функция NetApiBufferFree освобождает память
NET_API_STATUS(NET_API_FUNCTION* NetUserGetLocalGroups_)(LPCWSTR, LPCWSTR, DWORD, DWORD, LPBYTE*, DWORD, LPDWORD, LPDWORD);
//Функция NetUserGetLocalGroups извлекает список локальных групп, к которым принадлежит указанный пользователь
NET_API_STATUS(NET_API_FUNCTION* NetLocalGroupEnum_)(LPCWSTR, DWORD, LPBYTE*, DWORD, LPDWORD, LPDWORD, PDWORD_PTR);
//Функция NetLocalGroupEnum возвращает информацию о каждой учетной записи локальной группы на указанном сервере
NET_API_STATUS(NET_API_FUNCTION* NetUserAdd_)(LPCWSTR, DWORD, LPBYTE, LPDWORD);
//Функция NetUserAdd добавляет учетную запись пользователя и назначает пароль и уровень привилегий
NET_API_STATUS(NET_API_FUNCTION* NetUserDel_)(LPCWSTR, LPCWSTR);
//Функция NetUserDel удаляет учетную запись пользователя с сервера
NET_API_STATUS(NET_API_FUNCTION* NetLocalGroupAdd_)(LPCWSTR, DWORD, LPBYTE, LPDWORD);
//Функция NetLocalGroupAdd создает локальную группу в базе данных безопасности, которая является базой данных диспетчера учетных записей безопасности (SAM)
NET_API_STATUS(NET_API_FUNCTION* NetLocalGroupDel_)(LPCWSTR, LPCWSTR);
//Функция NetLocalGroupDel удаляет учетную запись локальной группы и всех ее членов из базы данных безопасности
NTSTATUS(WINAPI* LsaAddAccountRights_)(LSA_HANDLE, PSID, PLSA_UNICODE_STRING, ULONG);
//Функция LsaAddAccountRights назначает одну или несколько привилегий учетной записи
NTSTATUS(WINAPI* LsaRemoveAccountRights_)(LSA_HANDLE, PSID, BOOLEAN, PLSA_UNICODE_STRING, ULONG);
//Функция LsaRemoveAccountRights удаляет одну или несколько привилегий из учетной записи
NET_API_STATUS(NET_API_FUNCTION* NetLocalGroupAddMembers_)(LPCWSTR, LPCWSTR, DWORD, LPBYTE, DWORD);
//Функция NetLocalGroupAddMembers добавляет членство одной или нескольких существующих учетных записей пользователей или учетных записей глобальных групп в существующую локальную группу
NET_API_STATUS(NET_API_FUNCTION* NetLocalGroupDelMembers_)(LPCWSTR, LPCWSTR, DWORD, LPBYTE, DWORD);
//Функция NetLocalGroupDelMembers удаляет одного или нескольких участников из существующей локальной группы

LSA_OBJECT_ATTRIBUTES ObjectAttributes;
LSA_HANDLE PolicyHandle;

PSID getSID(LPCWSTR name, SID_NAME_USE sid_name_use)
{
	DWORD cbSid = 0;
	DWORD cchReferencedDomainName = 0;
	PSID sid = 0;
	LPWSTR domain = 0;

	LookupAccountNameW_(NULL, name, NULL, &cbSid, NULL, &cchReferencedDomainName, &sid_name_use);
	sid = (PSID)calloc(1, cbSid);
	domain = (LPWSTR)calloc(1, sizeof(TCHAR) * (cchReferencedDomainName));
	LookupAccountNameW_(NULL, name, sid, &cbSid, domain, &cchReferencedDomainName, &sid_name_use);
	return sid;
}

void infoAboutUser()
{
	LPUSER_INFO_0 buffer = NULL;
	DWORD entriesread = 0;
	DWORD totalentries = 0;
	DWORD resume_handle = 0;

	NET_API_STATUS netapi_status = NetUserEnum_(NULL, 0, FILTER_NORMAL_ACCOUNT, (LPBYTE*)&buffer, MAX_PREFERRED_LENGTH, &entriesread, &totalentries, &resume_handle);
	if (netapi_status != NERR_Success)
	{
		cout << "Error getting user list" << endl;
	}
	PSID sid = 0;
	LPWSTR str_sid = NULL;
	for (DWORD i = 0; i < entriesread; i++)
	{
		sid = getSID((buffer + i)->usri0_name, SidTypeUser);
		ConvertSidToStringSidW_(sid, &str_sid);
		wprintf(L"User: %s\n \t%s\n", (buffer + i)->usri0_name, str_sid);
		PLSA_UNICODE_STRING UserRights;
		ULONG CountOfRights = 0;
		LsaEnumerateAccountRights_(PolicyHandle, sid, &UserRights, &CountOfRights);
		cout << "\tRights: " << endl;
		for (ULONG j = 0; j < CountOfRights; j++)
		{
			wprintf(L"\t\t%s\n", UserRights[j].Buffer);
		}
		LPLOCALGROUP_USERS_INFO_0 buff = NULL;
		DWORD group_count = 0;
		DWORD group_count_total = 0;
		PLSA_UNICODE_STRING Rights;
		ULONG CountOfRights_g = 0;
		PSID sid_g;
		LPWSTR name_ = (buffer + i)->usri0_name;
		NetUserGetLocalGroups_(NULL, name_, 0, LG_INCLUDE_INDIRECT, (LPBYTE*)&buff, MAX_PREFERRED_LENGTH, &group_count, &group_count_total);
		cout << "\tGroup: " << endl;
		for (DWORD k = 0; k < group_count; k++)
		{
			wprintf(L"\t\t%s\n", (buff + k)->lgrui0_name);

			sid_g = getSID((buff + k)->lgrui0_name, SidTypeGroup);
			LsaEnumerateAccountRights_(PolicyHandle, sid_g, &Rights, &CountOfRights_g);
			cout << "\tRights (from group): " << endl;
			for (ULONG j = 0; j < CountOfRights_g; j++)
			{
				wprintf(L"\t%s\n", Rights[j].Buffer);
			}
		}
	}
	NetApiBufferFree_(buffer);
}

void infoAboutGroup()
{
	PGROUP_INFO_0 buffer = NULL;
	DWORD entriesread = 0;
	DWORD totalentries = 0;
	PDWORD_PTR resume_handle = 0;
	PSID sid = 0;
	LPWSTR str_sid = NULL;

	NetLocalGroupEnum_(NULL, 0, (LPBYTE*)&buffer, MAX_PREFERRED_LENGTH, &entriesread, &totalentries, resume_handle);

	for (DWORD i = 0; i < entriesread; i++)
	{
		sid = getSID((buffer + i)->grpi0_name, SidTypeGroup);
		ConvertSidToStringSidW_(sid, &str_sid);

		wprintf(L"Group: %s\n \t%s\n", (buffer + i)->grpi0_name, str_sid);


		PLSA_UNICODE_STRING Rights;
		ULONG CountOfRights = 0;
		LsaEnumerateAccountRights_(PolicyHandle, sid, &Rights, &CountOfRights);
		cout << "\tRights: " << endl;
		for (ULONG j = 0; j < CountOfRights; j++)
		{
			wprintf(L"\t\t%s\n", Rights[j].Buffer);
		}
	}
	NetApiBufferFree_(buffer);
}

void addUser()
{
	USER_INFO_1 user;
	wchar_t user_name[128];
	wchar_t password[128];
	cout << "Name: ";
	wscanf(L"%s", &user_name);
	cout << "Password: ";
	wscanf(L"%s", &password);

	user.usri1_name = user_name;
	user.usri1_password = password;
	user.usri1_priv = USER_PRIV_USER;
	user.usri1_home_dir = NULL;
	user.usri1_comment = NULL;
	user.usri1_flags = UF_SCRIPT;
	user.usri1_script_path = NULL;

	NetUserAdd_(NULL, 1, (LPBYTE)&user, NULL);
}

void deleteUser()
{
	wchar_t user_name[128];
	cout << "name: ";
	wscanf(L"%s", &user_name);
	NetUserDel_(NULL, user_name);
}

void addGroup()
{
	_LOCALGROUP_INFO_0 buffer;
	wchar_t group_name[128];
	cout << "Name: ";
	wscanf(L"%s", &group_name);
	buffer.lgrpi0_name = group_name;
	NetLocalGroupAdd_(NULL, 0, (LPBYTE)&buffer, NULL);
}

void deleteGroup()
{
	wchar_t group_name[128];
	cout << "name: ";
	wscanf(L"%s", &group_name);
	NetLocalGroupDel_(NULL, group_name);
}

LSA_UNICODE_STRING InitLsaStr(PWSTR str)
{
	LSA_UNICODE_STRING ret;
	ret.Buffer = str;
	ret.MaximumLength = 128;
	ret.Length = wcslen(str) * sizeof(WCHAR);
	return ret;
}

void addRightsToUser()
{
	wchar_t user_name[128];
	wchar_t right_user[128];
	cout << "Name: ";
	wscanf(L"%s", &user_name);
	cout << "Right: ";
	wscanf(L"%s", &right_user);
	LSA_UNICODE_STRING str_right = InitLsaStr(right_user);
	LsaAddAccountRights_(PolicyHandle, getSID(user_name, SidTypeUser), &str_right, 1);
}

void deleteRightsToUser()
{
	wchar_t user_name[128];
	wchar_t right_user[128];
	cout << "Name: ";
	wscanf(L"%s", &user_name);
	cout << "Right: ";
	wscanf(L"%s", &right_user);
	LSA_UNICODE_STRING str_right = InitLsaStr(right_user);
	LsaRemoveAccountRights_(PolicyHandle, getSID(user_name, SidTypeUser), FALSE, &str_right, 1);
}

void addRightsToGroup()
{
	wchar_t group_name[128];
	wchar_t right_user[128];
	cout << "Name: ";
	wscanf(L"%s", &group_name);
	cout << "Right: ";
	wscanf(L"%s", &right_user);
	LSA_UNICODE_STRING str_right = InitLsaStr(right_user);
	LsaAddAccountRights_(PolicyHandle, getSID(group_name, SidTypeGroup), &str_right, 1);
}

void deleteRightsToGroup()
{
	wchar_t group_name[128];
	wchar_t right_user[128];
	cout << "Name: ";
	wscanf(L"%s", &group_name);
	cout << "Right: ";
	wscanf(L"%s", &right_user);
	LSA_UNICODE_STRING str_right = InitLsaStr(right_user);
	LsaRemoveAccountRights_(PolicyHandle, getSID(group_name, SidTypeGroup), FALSE, &str_right, 1);
}

void addUserInGroup()
{
	wchar_t user_name[128];
	wchar_t group_name[128];
	cout << "User name: ";
	wscanf(L"%s", &user_name);
	cout << "Group name: ";
	wscanf(L"%s", &group_name);
	_LOCALGROUP_MEMBERS_INFO_0 buffer;
	buffer.lgrmi0_sid = getSID(user_name, SidTypeUser);
	NetLocalGroupAddMembers_(NULL, group_name, 0, (LPBYTE)&buffer, 1);
}

void deleteUserFromGroup()
{
	wchar_t user_name[128];
	wchar_t group_name[128];
	cout << "User name: ";
	wscanf(L"%s", &user_name);
	cout << "Group name: ";
	wscanf(L"%s", &group_name);
	_LOCALGROUP_MEMBERS_INFO_0 buffer;
	buffer.lgrmi0_sid = getSID(user_name, SidTypeUser);
	NetLocalGroupDelMembers_(NULL, group_name, 0, (LPBYTE)&buffer, 1);
}

void printMenu(int currentSelection) {
	system("cls");
	cout << "**************************************************************\n";
	cout << (currentSelection == 1 ? "> " : "  ") << "1. Информация о пользовательских SID, привилегиях, группах" << endl;
	cout << (currentSelection == 2 ? "> " : "  ") << "2. Информация о групповых SID, привилегиях, группах" << endl;
	cout << (currentSelection == 3 ? "> " : "  ") << "3. Добавить пользователя" << endl;
	cout << (currentSelection == 4 ? "> " : "  ") << "4. Добавить группу" << endl;
	cout << (currentSelection == 5 ? "> " : "  ") << "5. Удалить пользователя" << endl;
	cout << (currentSelection == 6 ? "> " : "  ") << "6. Удалить группу" << endl;
	cout << (currentSelection == 7 ? "> " : "  ") << "7. Добавить привилегии пользователю" << endl;
	cout << (currentSelection == 8 ? "> " : "  ") << "8. Добавить привилегии группе" << endl;
	cout << (currentSelection == 9 ? "> " : "  ") << "9. Удалить привелегии пользователя" << endl;
	cout << (currentSelection == 10 ? "> " : "  ") << "10. Удалить привелегии группы" << endl;
	cout << (currentSelection == 11 ? "> " : "  ") << "11. Добавить пользователя в группу" << endl;
	cout << (currentSelection == 12 ? "> " : "  ") << "12. Удалить пользователя из группы" << endl;
	cout << "***************************************************************\n";
}

int main()
{
	setlocale(LC_ALL, "Russian");
	HMODULE netapi32 = LoadLibrary(L"C:\\Windows\\System32\\netapi32.dll");
	HMODULE advapi32 = LoadLibrary(L"C:\\Windows\\System32\\Advapi32.dll");
	if (!netapi32 || !advapi32)
	{
		printf("Error: LoadLibrary (line 299-300)");
	}
	(FARPROC&)NetUserEnum_ = GetProcAddress(netapi32, "NetUserEnum");
	(FARPROC&)LookupAccountNameW_ = GetProcAddress(advapi32, "LookupAccountNameW");
	(FARPROC&)ConvertSidToStringSidW_ = GetProcAddress(advapi32, "ConvertSidToStringSidW");
	(FARPROC&)LsaEnumerateAccountRights_ = GetProcAddress(advapi32, "LsaEnumerateAccountRights");
	(FARPROC&)LsaOpenPolicy_ = GetProcAddress(advapi32, "LsaOpenPolicy");
	(FARPROC&)NetApiBufferFree_ = GetProcAddress(netapi32, "NetApiBufferFree");
	(FARPROC&)NetUserGetLocalGroups_ = GetProcAddress(netapi32, "NetUserGetLocalGroups");
	(FARPROC&)NetLocalGroupEnum_ = GetProcAddress(netapi32, "NetLocalGroupEnum");
	(FARPROC&)NetUserAdd_ = GetProcAddress(netapi32, "NetUserAdd");
	(FARPROC&)NetUserDel_ = GetProcAddress(netapi32, "NetUserDel");
	(FARPROC&)NetLocalGroupAdd_ = GetProcAddress(netapi32, "NetLocalGroupAdd");
	(FARPROC&)NetLocalGroupDel_ = GetProcAddress(netapi32, "NetLocalGroupDel");
	(FARPROC&)LsaAddAccountRights_ = GetProcAddress(advapi32, "LsaAddAccountRights");
	(FARPROC&)LsaRemoveAccountRights_ = GetProcAddress(advapi32, "LsaRemoveAccountRights");
	(FARPROC&)NetLocalGroupAddMembers_ = GetProcAddress(netapi32, "NetLocalGroupAddMembers");
	(FARPROC&)NetLocalGroupDelMembers_ = GetProcAddress(netapi32, "NetLocalGroupDelMembers");

	NTSTATUS ntstatus = 0;
	ntstatus = LsaOpenPolicy_(NULL, &ObjectAttributes, POLICY_LOOKUP_NAMES | POLICY_CREATE_ACCOUNT, &PolicyHandle);

	int N = 1; 
	int key;
	while (1)
	{
		printMenu(N);
		key = _getch(); 
		switch (key) {
		case KEY_ARROW_UP: 
			if (N > MENU_MIN_ITEM) N--;
			break;
		case KEY_ARROW_DOWN: 
			if (N < MENU_MAX_ITEM) N++;
			break;
		case KEY_ENTER:
			switch (N) {
			case 1:
				infoAboutUser(); system("pause");
				break;
			case 2:
				infoAboutGroup(); system("pause");
				break;
			case 3:
				addUser(); system("pause");
				break;
			case 4:
				addGroup(); system("pause");
				break;
			case 5:
				deleteUser(); system("pause");
				break;
			case 6:
				deleteGroup(); system("pause");
				break;
			case 7:
				addRightsToUser(); system("pause");
				break;
			case 8:
				addRightsToGroup(); system("pause");
				break;
			case 9:
				deleteRightsToUser(); system("pause");
				break;
			case 10:
				deleteRightsToGroup(); system("pause");
				break;
			case 11:
				addUserInGroup(); system("pause");
				break;
			case 12:
				deleteUserFromGroup(); system("pause");
				break;
			default:
				break;
			}
		}
	}
}
