#pragma once
#include <windows.h>
#include <stdio.h>
#include <winternl.h>
#include <intrin.h>
#include "flower.h"
#include "aplib.h"
#pragma comment(lib, "D:/��Ŀ/DemonsPack/pack/aplib.lib")
#pragma comment(lib,"ntdll.lib")

#define MAX_SIZE 1024

//������Ϣ
struct mSize
{
	DWORD oldSectionSize;
};

typedef struct _TYPEOFFSET
{
	WORD wOffset : 12;
	WORD wType : 4;
}TYPEOFFSET, *PTYPEOFFSET;

// �ڼӿ����ͿǴ���֮�䴫������
typedef struct _SHAREDATA
{
	// ����ԭʼ�����OEP
	int nOldOep;
	DWORD dwSrcOep;			// ��ڵ�

	DWORD dwTextScnRVA;		// �����RVA
	DWORD dwTextScnSize;	// ����δ�С
	DWORD dwKey;			// ������Կ

	DWORD dwStartRVA;		// ��ʼ�����ַ
	DWORD dwEndRVA;			// ���������ַ

	DWORD dwDataDir[20][2];	// ����Ŀ¼���RVA��size
	DWORD dwNumOfDataDir;	// ����Ŀ¼��ĸ���

	char pCpuId[50];
	char pOldCpuId[50];		// �����Լ���CPUID
	DWORD dwCpuSize;		// �����С
	DWORD dwCpuKey;			// ����CPU �� key

	DWORD RelocRva;

	//����ԭʼ��С
	mSize oldSize[10];

	DWORD tlsFuncs[MAX_PATH];	// tls
	IMAGE_DATA_DIRECTORY HostTLS;
}SHAREDATA, *PSHAREDATA;

typedef struct _WINDOWSINFO
{
	HWND	hWnd;
	HMENU	hMenu;
}WINDOWSINFO, *PWINDOWSINFO;

typedef struct _DOSSTUB
{
	DWORD dwOldImageBase;	// ���ӿǳ�������ǰĬ�ϵļ��ػ�ַ
	DWORD dwStubTextSectionRva;	// ���ڿ������text�ε�RVA
	DWORD dwStubRelocSectionRva;	// �ǵ��ض�λ����text�κϲ��󱻼ӿǳ����Rva
}DOSSTUB, *PDOSSTUB;

typedef void* (WINAPI* fnGetProcAddress)(_In_ HMODULE hModule, _In_ LPCSTR lpProcName);
typedef HMODULE(WINAPI* fnLoadLibraryExA)(_In_ LPCSTR lpLibFileName, HANDLE file, DWORD mode);
typedef HMODULE(WINAPI* fnLoadLibraryA)(_In_ LPCSTR lpLibFileName);
typedef BOOL(WINAPI* fnVirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef LPVOID(WINAPI* fnVirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL(WINAPI* fnVirtualFree)(
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD dwFreeType);
typedef HMODULE(WINAPI* fnGetModuleHandleA)(_In_opt_ LPCWSTR lpModuleName);
typedef void(WINAPI* fnRtlMoveMemory)(void* Destination, const void* Source, size_t Length);
typedef VOID(WINAPI* fnRtlZeroMemory)(LPVOID, SIZE_T);
typedef WORD(WINAPI* fnRegisterClassExW)(_In_ CONST WNDCLASSEXW* lpWndClass);
typedef HWND(WINAPI* fnCreateWindowExW)(
	_In_ DWORD dwExStyle,
	_In_opt_ LPCWSTR lpClassName,
	_In_opt_ LPCWSTR lpWindowName, 
	_In_ DWORD dwStyle, 
	_In_ int X, 
	_In_ int Y, 
	_In_ int nWidth, 
	_In_ int nHeight,
	_In_opt_ HWND hWndParent, 
	_In_opt_ HMENU hMenu, 
	_In_opt_ HINSTANCE hInstance, 
	_In_opt_ LPVOID lpParam);
typedef BOOL(WINAPI* fnShowWindow)(_In_ HWND hWnd, _In_ int nCmdShow);
typedef BOOL(WINAPI* fnUpdateWindow)(_In_ HWND hWnd);
typedef BOOL(WINAPI* fnGetMessageW)(
	_Out_ LPMSG lpMsg, 
	_In_opt_ HWND hWnd, 
	_In_ UINT wMsgFilterMin, 
	_In_ UINT wMsgFilterMax);
typedef BOOL(WINAPI* fnTranslateMessage)(_In_ CONST MSG* lpMsg);
typedef LRESULT(WINAPI* fnDispatchMessageW)(_In_ CONST MSG* lpMsg);
typedef VOID(WINAPI* fnExitProcess)(_In_ UINT uExitCode);
typedef  LRESULT(WINAPI* fnDefWindowProcW)(
	_In_ HWND hWnd, 
	_In_ UINT Msg, 
	_In_ WPARAM wParam, 
	_In_ LPARAM lParam);
typedef VOID(WINAPI* fnPostQuitMessage)(_In_ int nExitCode);
typedef BOOL(WINAPI* fnDestroyWindow)(_In_ HWND hWnd);
typedef UINT(WINAPI* fnGetDlgItemTextA)(
	_In_ HWND hDlg, 
	_In_ int nIDDlgItem, 
	_Out_writes_(cchMax) LPSTR lpString, 
	_In_ int cchMax);
typedef int (WINAPI* fnMessageBoxW)(
	_In_opt_ HWND hWnd, 
	_In_opt_ LPCWSTR lpText, 
	_In_opt_ LPCWSTR lpCaption, 
	_In_ UINT uType);
typedef LPTOP_LEVEL_EXCEPTION_FILTER(WINAPI* fnSetUnhandledExceptionFilter)(
	_In_opt_ LPTOP_LEVEL_EXCEPTION_FILTER lpTopLevelExceptionFilter);
typedef int (WINAPI* fnGetWindowTextW)(
	_In_ HWND hWnd, 
	_Out_writes_(nMaxCount) LPWSTR lpString, 
	_In_ int nMaxCount);
typedef int (WINAPI* fnGetWindowTextA)(
	_In_ HWND hWnd,
	_Out_writes_(nMaxCount) LPSTR lpString,
	_In_ int nMaxCount);
typedef LRESULT(WINAPI* fnSendMessageW)(
	_In_ HWND hWnd,
	_In_ UINT Msg,
	_Pre_maybenull_ _Post_valid_ WPARAM wParam,
	_Pre_maybenull_ _Post_valid_ LPARAM lParam);
typedef HWND(WINAPI* fnFindWindowW)(_In_opt_ LPCWSTR lpClassName, _In_opt_ LPCWSTR lpWindowName);

typedef struct _API
{
	fnGetProcAddress				GetProcAddress;
	fnLoadLibraryExA				LoadLibraryExA;
	fnLoadLibraryA					LoadLibraryA;
	fnVirtualProtect				VirtualProtect;
	fnVirtualAlloc					VirtualAlloc;
	fnVirtualFree					VirtualFree;
	fnGetModuleHandleA				GetModuleHandleA;
	fnRtlMoveMemory					MyRtlMoveMemory;
	fnRtlZeroMemory					MyRtlZeroMemory;
	fnRegisterClassExW				RegisterClassExW;
	fnCreateWindowExW				CreateWindowExW;
	fnShowWindow					ShowWindow;
	fnUpdateWindow					UpdateWindow;
	fnGetMessageW					GetMessageW;
	fnTranslateMessage				TranslateMessage;
	fnDispatchMessageW				DispatchMessageW;
	fnExitProcess					ExitProcess;
	fnDefWindowProcW				DefWindowProcW;
	fnPostQuitMessage				PostQuitMessage;
	fnDestroyWindow					DestroyWindow;
	fnGetDlgItemTextA				GetDlgItemTextA;
	fnMessageBoxW					MessageBoxW;
	fnSetUnhandledExceptionFilter	SetUnhandledExceptionFilter;
	fnGetWindowTextW				GetWindowTextW;
	fnGetWindowTextA				GetWindowTextA;
	fnSendMessageW					SendMessageW;
	fnFindWindowW					FindWindowW;
	DWORD							dwImageBase;
	HWND							hParent;
	DWORD							dwIsTrue;
	WINDOWSINFO						info[2];

}API, *PAPI;