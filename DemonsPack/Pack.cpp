#include "pch.h"
#include "Pack.h"

// ����
void Pack::Encrypt(DWORD dwBase, LPCSTR lpSectionName)
{
	// ��������ݻ������׵�ַ
	BYTE* pTargetText = m_pe.GetSection(dwBase, lpSectionName)->PointerToRawData + (BYTE*)dwBase;

	// ����δ�С
  	DWORD dwTargetTextSize = m_pe.GetSection(dwBase, lpSectionName)->Misc.VirtualSize;

	// ���ܴ����
	for (DWORD i = 0; i < dwTargetTextSize; i++)
	{
 		pTargetText[i] ^= 0x15;
	}

	// �������ο�ʼ��RVA�ʹ�С
	m_pe.GetShareData()->dwTextScnRVA = m_pe.GetSection(dwBase, lpSectionName)->VirtualAddress;
	m_pe.GetShareData()->dwTextScnSize = dwTargetTextSize;
	m_pe.GetShareData()->dwKey = 0x15;
}

// HASH����
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

// ��ȡCPUID
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

// ����CPUID
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

// ��ѹ��
VOID Pack::CompressExe(DWORD dwBase)
{
	//����ͷ�� ��Դ�� TLS��
	DWORD SectionNumber = m_pe.GetFileHeader(dwBase)->NumberOfSections;
	auto* Section = m_pe.GetSectionHeader(dwBase);
	DWORD NewFileSection = 0;
	for (int i = 0; i < SectionNumber; i++)
	{
		//����ԭ�����ļ���С 
		FileInfo[i].dwOldSizeOfRawData = Section->SizeOfRawData;
		//����ԭ�����ε��ļ�ƫ��
		FileInfo[i].dwOldPointerToRawData = Section->PointerToRawData;
		FileInfo[i].dwOldCharcteristics = Section->Characteristics;

		//ѹ�����ε��ļ���С
		unsigned long long nSizeSection = Section->SizeOfRawData;
		//ѹ����Ĵ�С
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
		//ѹ��������ݴ����packed��
		//ѹ�����δ�С �ļ�����
		DWORD NewSize = m_pe.Alignment(outLength, 0x200);
		//�޸������ļ���С
		Section->SizeOfRawData = NewSize;
		m_pe.GetShareData()->oldSize[i].oldSectionSize = FileInfo[i].dwOldSizeOfRawData;
		//�޸�ԭ��λ�õ�����Ϊѹ���������
		//����ԭ������Ϊ0
		memset((void*)(Section->PointerToRawData + dwBase), 0, nSizeSection);
		if (i == 0)
		{
			NewFileSection = Section->PointerToRawData + Section->SizeOfRawData;
			memcpy_s((void*)(Section->PointerToRawData + dwBase), outLength, packed, outLength);
			Section++;
			free(packed);

			continue;
		}
		//�޸��ļ�ƫ��
		Section->PointerToRawData = NewFileSection;
		NewFileSection = Section->PointerToRawData + Section->SizeOfRawData;
		//�޸�Ϊѹ���������
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
	//��ȡ��䵽tls���е���ʱtls������ƫ��
	DWORD tempTlsRVA = (DWORD)GetProcAddress((HMODULE)dwDllBase, "temTls");
	tempTlsRVA = tempTlsRVA - dwDllBase - m_pe.GetSection(dwDllBase, (LPSTR)".text")->VirtualAddress;
	//��ʱtls�ص����������ַ
	DWORD tempTlsVA = m_pe.GetOptionalHeader(dwFIleBase)->ImageBase + m_pe.GetSection(dwFIleBase, (LPSTR)".demons")->VirtualAddress + tempTlsRVA;
	//����tls��
	DWORD tlstableFOA = m_pe.RvaToOffset((PIMAGE_NT_HEADERS)dwFIleBase, tlstableRva);
	PIMAGE_TLS_DIRECTORY32 tlsDir = (PIMAGE_TLS_DIRECTORY32)(dwFIleBase + tlstableFOA);
	//��ȡ�ص���������ָ��
	DWORD tlsCallBackFoa = m_pe.RvaToOffset((PIMAGE_NT_HEADERS)dwFIleBase, (tlsDir->AddressOfCallBacks) - m_pe.GetOptionalHeader(dwFIleBase)->ImageBase);
	DWORD* tlsCallBacks = (DWORD*)(tlsCallBackFoa + dwFIleBase);
	int i = 0;
	//ѭ������tls�ص��������飬�����ַ������ʱ�ص���������
	while (*tlsCallBacks)
	{
		m_pe.GetShareData()->tlsFuncs[i] = (*tlsCallBacks);
		*tlsCallBacks = tempTlsVA;
		tlsCallBacks++;
		i++;
	}
	m_pe.GetShareData()->tlsFuncs[i] = 0;


}