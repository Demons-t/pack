#pragma once
#include "Pe.h"
#include "aplib.h"
#pragma comment(lib, "aplib.lib")

typedef struct _SaveSectionInfo
{
	DWORD dwOldSizeOfRawData;           //压缩前文件对齐大小
	DWORD dwOldPointerToRawData;        //文件偏移
	DWORD dwOldCharcteristics;
}SaveSectionInfo, * pSaveSectionInfo;

class Pack
{
public:
	void	Encrypt(DWORD dwBase, LPCSTR lpSectionName);		// 加密代码段
	DWORD	HashPassWord(char* pSrc);							// HASh加密
	char*	cpuId();											// 获取CPUID
	void	EncryptCpuId(char* pStr);							// 加密CPUID
	VOID	CompressExe(DWORD dwBase);							// 压缩源程序
	VOID	DisposeTLS(DWORD dwFIleBase, DWORD dwDllBase);		// tls

private:
	Pe	m_pe;
	SaveSectionInfo FileInfo[10];
};

