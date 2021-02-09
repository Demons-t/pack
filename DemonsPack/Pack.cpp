#include "pch.h"
#include "Pack.h"

// 加密
void Pack::Encrypt(DWORD dwBase, LPCSTR lpSectionName)
{
	// 代码段数据缓冲区首地址
	BYTE* pTargetText = m_pe.GetSection(dwBase, lpSectionName)->PointerToRawData + (BYTE*)dwBase;

	// 代码段大小
  	DWORD dwTargetTextSize = m_pe.GetSection(dwBase, lpSectionName)->Misc.VirtualSize;

	// 加密代码段
	for (DWORD i = 0; i < dwTargetTextSize; i++)
	{
 		pTargetText[i] ^= 0x15;
	}

	// 保存代码段开始的RVA和大小
	m_pe.GetShareData()->dwTextScnRVA = m_pe.GetSection(dwBase, lpSectionName)->VirtualAddress;
	m_pe.GetShareData()->dwTextScnSize = dwTargetTextSize;
	m_pe.GetShareData()->dwKey = 0x15;
}

// HASH加密
DWORD Pack::HashPassWord(char* pSrc)
{
	DWORD dwRet = 0;
	while (*pSrc)
	{
		dwRet = ((dwRet << 25) | (dwRet >> 7));
		dwRet = dwRet + *pSrc;
		pSrc++;
	}
	return dwRet;
}

// 获取CPUID
char* Pack::cpuId()
{
	unsigned long s1 = 0;
	unsigned long s2 = 0;
	unsigned long s3 = 0;
	unsigned long s4 = 0;
	__asm
	{
		mov eax, 00h
		xor edx, edx
		cpuid
		mov s1, edx
		mov s2, eax
	}
	__asm
	{
		mov eax, 01h
		xor ecx, ecx
		xor edx, edx
		cpuid
		mov s3, edx
		mov s4, ecx
	}

	static char buf[MAX_PATH];
	sprintf(buf, "%08X%08X%08X%08X", s1, s2, s3, s4);

	return buf;
}

// 加密CPUID
void Pack::EncryptCpuId(char* pStr)
{
	DWORD dwSize = strlen(pStr);

	for (DWORD i = 0; i < dwSize; i++)
	{
		pStr[i] ^= 0x15;
		m_pe.GetShareData()->pCpuId[i] = pStr[i];
	}

	m_pe.GetShareData()->dwCpuSize = dwSize;
	m_pe.GetShareData()->dwCpuKey = 0x15;
}

// 解压缩
VOID Pack::CompressExe(DWORD dwBase)
{
	//除了头部 资源段 TLS段
	DWORD SectionNumber = m_pe.GetFileHeader(dwBase)->NumberOfSections;
	auto* Section = m_pe.GetSectionHeader(dwBase);
	DWORD NewFileSection = 0;
	for (int i = 0; i < SectionNumber; i++)
	{
		//保存原来的文件大小 
		FileInfo[i].dwOldSizeOfRawData = Section->SizeOfRawData;
		//保存原来区段的文件偏移
		FileInfo[i].dwOldPointerToRawData = Section->PointerToRawData;
		FileInfo[i].dwOldCharcteristics = Section->Characteristics;

		//压缩区段的文件大小
		unsigned long long nSizeSection = Section->SizeOfRawData;
		//压缩后的大小
		unsigned long long outLength = 0;
		char* packed;
		char* workmem;
		if ((packed = (char*)malloc(aP_max_packed_size(nSizeSection))) == NULL ||
			(workmem = (char*)malloc(aP_workmem_size(nSizeSection))) == NULL)
		{
			ExitProcess(0);
		}
		outLength = aPsafe_pack((void*)(Section->PointerToRawData + dwBase), packed, nSizeSection, workmem, NULL, NULL);
		if (outLength == APLIB_ERROR)
			ExitProcess(0);
		if (NULL != workmem)
		{
			free(workmem);
			workmem = NULL;
		}
		//压缩后的数据存放在packed中
		//压缩区段大小 文件对齐
		DWORD NewSize = m_pe.Alignment(outLength, 0x200);
		//修改区段文件大小
		Section->SizeOfRawData = NewSize;
		m_pe.GetShareData()->oldSize[i].oldSectionSize = FileInfo[i].dwOldSizeOfRawData;
		//修改原来位置的数据为压缩后的数据
		//设置原来数据为0
		memset((void*)(Section->PointerToRawData + dwBase), 0, nSizeSection);
		if (i == 0)
		{
			NewFileSection = Section->PointerToRawData + Section->SizeOfRawData;
			memcpy_s((void*)(Section->PointerToRawData + dwBase), outLength, packed, outLength);
			Section++;
			free(packed);

			continue;
		}
		//修改文件偏移
		Section->PointerToRawData = NewFileSection;
		NewFileSection = Section->PointerToRawData + Section->SizeOfRawData;
		//修改为压缩后的数据
		memcpy_s((void*)(Section->PointerToRawData + dwBase), outLength, packed, outLength);
		Section++;
		free(packed);
	}
}

// tls
VOID Pack::DisposeTLS(DWORD dwFIleBase, DWORD dwDllBase)
{
	if (m_pe.GetOptionalHeader(dwFIleBase)->DataDirectory[9].VirtualAddress == 0)
	{
		return;
	}
	DWORD tlstableRva = m_pe.GetOptionalHeader(dwFIleBase)->DataDirectory[9].VirtualAddress;
	//获取填充到tls表中的临时tls函数的偏移
	DWORD tempTlsRVA = (DWORD)GetProcAddress((HMODULE)dwDllBase, "temTls");
	tempTlsRVA = tempTlsRVA - dwDllBase - m_pe.GetSection(dwDllBase, (LPSTR)".text")->VirtualAddress;
	//临时tls回调函数虚拟地址
	DWORD tempTlsVA = m_pe.GetOptionalHeader(dwFIleBase)->ImageBase + m_pe.GetSection(dwFIleBase, (LPSTR)".demons")->VirtualAddress + tempTlsRVA;
	//解析tls表
	DWORD tlstableFOA = m_pe.RvaToOffset((PIMAGE_NT_HEADERS)dwFIleBase, tlstableRva);
	PIMAGE_TLS_DIRECTORY32 tlsDir = (PIMAGE_TLS_DIRECTORY32)(dwFIleBase + tlstableFOA);
	//获取回调函数数组指针
	DWORD tlsCallBackFoa = m_pe.RvaToOffset((PIMAGE_NT_HEADERS)dwFIleBase, (tlsDir->AddressOfCallBacks) - m_pe.GetOptionalHeader(dwFIleBase)->ImageBase);
	DWORD* tlsCallBacks = (DWORD*)(tlsCallBackFoa + dwFIleBase);
	int i = 0;
	//循环遍历tls回调函数数组，保存地址并用临时回调函数覆盖
	while (*tlsCallBacks)
	{
		m_pe.GetShareData()->tlsFuncs[i] = (*tlsCallBacks);
		*tlsCallBacks = tempTlsVA;
		tlsCallBacks++;
		i++;
	}
	m_pe.GetShareData()->tlsFuncs[i] = 0;


}