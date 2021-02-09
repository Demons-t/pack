#pragma once
#include "Pe.h"
#include "aplib.h"
#pragma comment(lib, "aplib.lib")

typedef struct _SaveSectionInfo
{
	DWORD dwOldSizeOfRawData;           //ѹ��ǰ�ļ������С
	DWORD dwOldPointerToRawData;        //�ļ�ƫ��
	DWORD dwOldCharcteristics;
}SaveSectionInfo, * pSaveSectionInfo;

class Pack
{
public:
	void	Encrypt(DWORD dwBase, LPCSTR lpSectionName);		// ���ܴ����
	DWORD	HashPassWord(char* pSrc);							// HASh����
	char*	cpuId();											// ��ȡCPUID
	void	EncryptCpuId(char* pStr);							// ����CPUID
	VOID	CompressExe(DWORD dwBase);							// ѹ��Դ����
	VOID	DisposeTLS(DWORD dwFIleBase, DWORD dwDllBase);		// tls

private:
	Pe	m_pe;
	SaveSectionInfo FileInfo[10];
};

