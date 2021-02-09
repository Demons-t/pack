#include "pch.h"
#include "Pe.h"

Pe::Pe()
{
	// ���� dllbase �� �ṹ��
	// ��Ȼ��pack�е��õ�ʱ��ᱻ����
	m_dwDllBase = (DWORD)LoadLibraryExA("Stub.dll", NULL, DONT_RESOLVE_DLL_REFERENCES);
	m_shareData = (PSHAREDATA)GetProcAddress((HMODULE)m_dwDllBase, "ShareData");
}

// ��PE�ļ�
bool Pe::OpenPeFile(LPCSTR lpPath)
{
	// �ļ����ڵ��������ֻ���ķ�ʽ���ļ�
	HANDLE hFileHandle = GetPeFile(lpPath);

	// ��ȡ�ļ��Ĵ�С����ʹ�øô�С����ռ����ڱ���
	m_dwFileSize = GetFileSize(hFileHandle, NULL); 
	m_dwFileBase = (DWORD)malloc(m_dwFileSize * sizeof(BYTE));

	// ���ļ�����������һ���Զ�ȡ����������
	DWORD dwReadBytes = 0;
	ReadFile(hFileHandle, (LPVOID)m_dwFileBase, m_dwFileSize, &dwReadBytes, NULL);

	// �жϵ�ǰ�Ƿ���PE�ļ�
	PIMAGE_DOS_HEADER pDosHeader = GetDosHeader(m_dwFileBase);
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		return false;
	}

	PIMAGE_NT_HEADERS pNtHeaders = GetNtHeaders(m_dwFileBase);
	if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE)
	{
		return false;
	}

	// �رվ��
	CloseHandle(hFileHandle);
}

// ��dll�ļ�
void Pe::OpenDllFile(LPCSTR lpPath, LPCSTR lpSectionName)
{
	// ��Ŀ��ģ����ص���ǰ�Ľ����У����ǲ�����DllMain
	m_dwDllBase = (DWORD)LoadLibraryExA(lpPath, NULL, DONT_RESOLVE_DLL_REFERENCES);

	// ��ģ���л�ȡ�� m_dwStart ������ƫ�ƣ��������Ϊ�µ� OEP
	DWORD offset = (DWORD)GetProcAddress((HMODULE)m_dwDllBase, "Start");
	m_dwStart = (DWORD)GetProcAddress((HMODULE)m_dwDllBase, "Start") - 
		m_dwDllBase - GetSection(m_dwDllBase, lpSectionName)->VirtualAddress;

	m_shareData->HostTLS =
		GetOptionalHeader(m_dwFileBase)->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
	GetOptionalHeader(m_dwFileBase)->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress = 0;
	GetOptionalHeader(m_dwFileBase)->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size = 0;
	// ��ȡ��DLLģ���еĽṹ�����
	m_shareData = (SHAREDATA*)GetProcAddress((HMODULE)m_dwDllBase, "ShareData");
}

// ��ȡ�ļ����ݺʹ�С
char* Pe::GetFileData(LPCSTR lpPath, int* nFileSize)
{
	// ���ļ�
	HANDLE hFIle = GetPeFile(lpPath);
	if (hFIle == INVALID_HANDLE_VALUE)
		return NULL;

	// ��ȡ�ļ���С
	DWORD dwSize = GetFileSize(hFIle, NULL);
	if (nFileSize)
		*nFileSize = dwSize;

	// ����ѿռ�
	char* pFileBuff = new char[dwSize] {0};

	// ��ȡ�ļ����ݵ��ѿռ�
	DWORD dwRead = 0;
	ReadFile(hFIle, pFileBuff, dwSize, &dwRead, NULL);
	CloseHandle(hFIle);

	return pFileBuff;
}

// �����ļ�
HANDLE Pe::GetPeFile(LPCSTR lpPath)
{
	return CreateFileA((LPCSTR)lpPath, GENERIC_READ, FILE_SHARE_READ,
		NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
}

// ��ȡdosͷ
PIMAGE_DOS_HEADER Pe::GetDosHeader(DWORD dwModuleBase)
{
	return (PIMAGE_DOS_HEADER)dwModuleBase;
}

// ��ȡNTͷ
PIMAGE_NT_HEADERS Pe::GetNtHeaders(DWORD dwModuleBase)
{
	return (PIMAGE_NT_HEADERS)(GetDosHeader(dwModuleBase)->e_lfanew + dwModuleBase);
}

// ��ȡ�ļ�ͷ
PIMAGE_FILE_HEADER Pe::GetFileHeader(DWORD dwModuleBase)
{
	return &GetNtHeaders(dwModuleBase)->FileHeader;
}

// ��ȡoptional
PIMAGE_OPTIONAL_HEADER Pe::GetOptionalHeader(DWORD dwModuleBase)
{
	return &GetNtHeaders(dwModuleBase)->OptionalHeader;
}

// ��ȡ DataDirectory
PIMAGE_DATA_DIRECTORY Pe::GetDataDirectory(int nIndex, DWORD dwModuleBase)
{
	return &GetOptionalHeader(dwModuleBase)->DataDirectory[nIndex];
}

// ��ȡ SectionHeader
PIMAGE_SECTION_HEADER Pe::GetSectionHeader(DWORD dwModuleBase)
{
	PIMAGE_NT_HEADERS pNt = GetNtHeaders(dwModuleBase);
	return IMAGE_FIRST_SECTION(pNt);
}

// ��ȡ Section
PIMAGE_SECTION_HEADER Pe::GetSection(DWORD dwBase, LPCSTR lpSectionName)
{
	// ��ȡĿ��ģ������������������α�
	auto auSection = GetSectionHeader(dwBase);

	// ʹ���ļ�ͷ�е����������������α�
	WORD wCount = GetFileHeader(dwBase)->NumberOfSections;
	if (!strcmp(lpSectionName, ".text"))
	{
		for (WORD i = 0; i < wCount; i++)
		{
			//�Ա�ÿһ�����ε������Ƿ��ָ�������������
			if (!memcmp(auSection[i].Name, lpSectionName, 8))
			{
				return &auSection[i];
			}
		}
	}
	else
	{
		for (WORD i = 0; i < wCount; i++)
		{
			//�Ա�ÿһ�����ε������Ƿ��ָ�������������
			if (!memcmp(auSection[i].Name, lpSectionName, strlen(lpSectionName)))
			{
				return &auSection[i];
			}
		}
	}

	return NULL;
}

// ��ȡ FileBase
DWORD Pe::GetFileBase()
{
	return m_dwFileBase;
}

// ��ȡ DllBase
DWORD Pe::GetDllBase()
{
	return m_dwDllBase;
}

// ��ȡ�ṹ��
PSHAREDATA Pe::GetShareData()
{
	return m_shareData;
}

// Rva ת Offset
DWORD Pe::RvaToOffset(PIMAGE_NT_HEADERS32 pNtHead, DWORD dwRva)
{
	WORD wCount = pNtHead->FileHeader.NumberOfSections;
	PIMAGE_SECTION_HEADER pSection = GetSectionHeader(m_dwFileBase);

	if (dwRva < pNtHead->OptionalHeader.SizeOfHeaders)
	{
		return dwRva;
	}

	for (int i = 0; i < wCount; i++)
	{
		if (dwRva >= pSection->VirtualAddress &&
			dwRva < pSection->VirtualAddress + pSection->SizeOfRawData)
		{
			return dwRva - pSection->VirtualAddress + pSection->PointerToRawData;
		}
		pSection++;
	}
	return 0;
}

// ��������Ĵ�С
DWORD Pe::Alignment(DWORD dwAddress, DWORD dwAlgn)
{
	return dwAddress % dwAlgn == 0 ? dwAddress : (dwAddress / dwAlgn + 1) * dwAlgn;
}

// ��Dll�е�ָ�����ο��������ӿǳ�����
void Pe::CopySection(LPCSTR lpDestName, LPCSTR lpSrcName)
{
	// �� Dll ���ҵ� ��Ҫ��������������Ӧ�Ľṹ��
	auto auSrcSection = GetSection(m_dwDllBase, lpSrcName);

	// ��ȡ�����ӿǳ�������һ�����Σ���������µ����ε�ַ
	auto auLastSection = &GetSectionHeader(m_dwFileBase)
		[GetFileHeader(m_dwFileBase)->NumberOfSections - 1];
	auto auNewSection = auLastSection + 1;

	// ��Ŀ�����ε����ݸ�������
	memcpy(auNewSection, auSrcSection, sizeof(IMAGE_SECTION_HEADER));

	// �޸Ŀ��������ݣ����������ļ����ڴ��ַ(�ϸ����εĻ�ַ+����(��С))������
	memcpy(auNewSection->Name, lpDestName, 7);
	auNewSection->PointerToRawData = auLastSection->PointerToRawData + 
		Alignment(auLastSection->SizeOfRawData, GetOptionalHeader(m_dwFileBase)->FileAlignment);
	auNewSection->VirtualAddress = auLastSection->VirtualAddress + 
		Alignment(auLastSection->Misc.VirtualSize, GetOptionalHeader(m_dwFileBase)->SectionAlignment);

	// ��������+1
	GetFileHeader(m_dwFileBase)->NumberOfSections++;

	// Ϊ�����������
	// �������Ҫռ�õ��µĴ�С(�µ��ļ���С)��������FOA + ������RSIZE
	m_dwFileSize = auNewSection->PointerToRawData + auNewSection->SizeOfRawData;
	m_dwFileBase = (DWORD)realloc((LPVOID)m_dwFileBase, m_dwFileSize);

	// �����������κ�� SizeOfImage = ������RVA + ������VSIZE
	GetOptionalHeader(m_dwFileBase)->SizeOfImage = auNewSection->VirtualAddress + auNewSection->Misc.VirtualSize;
}

// �� DLL �е�ָ�����ε����ݿ��������ӿǳ�����
void Pe::CopySectionData(LPCSTR lpDestName, LPCSTR lpSrcName)
{
	// ��ȡ�µ������ڱ��ӿǳ����е���ʼλ��
	LPVOID lpDestData = (LPVOID)(m_dwFileBase + GetSection(m_dwFileBase, lpDestName)->PointerToRawData);

	// ��ȡ����Ҫ������������DLL�е���ʼλ��
	LPVOID lpSrcData = (LPVOID)(m_dwDllBase + GetSection(m_dwDllBase, lpSrcName)->VirtualAddress);

	// ��������ַ���뵽����������                       
	memcpy(lpDestData, lpSrcData, GetSection(m_dwDllBase, lpSrcName)->SizeOfRawData);
}

// ΪĿ��PE�ļ����һ��ָ����С��ָ������
void Pe::AddSection(LPCSTR lpSectionName, UINT uSectionSize)
{
	// 1. �Ȼ�ȡ�����α������һ�����ε�λ��
	auto auLastSection = &GetSectionHeader(m_dwFileBase)[GetFileHeader(m_dwFileBase)->NumberOfSections - 1];

	// 2. ������µı���ӵ����α�Ľṹ��
	auto auNewSection = auLastSection + 1;

	// 3. ����µĶ�ṹ���е���������ֶ�
	// 3.1 �������ε����ƣ������Ϊ8���ַ�������һ�����ַ�
	memcpy(auNewSection->Name, lpSectionName, 7);

	// 3.2 �µ������б����˴������ݣ�����Ϊ�ɶ���д��ִ��
	auNewSection->Characteristics = 0xF00000E0;

	// 3.3 �����������������ڴ��е���ʼλ�ã���һ������RVA + ����VSIZE
	//		�������������ļ��е���ʼλ�ã���һ������FOA + ����RSIZE
	auNewSection->VirtualAddress = auLastSection->VirtualAddress
		+ Alignment(auLastSection->Misc.VirtualSize, GetOptionalHeader(m_dwFileBase)->SectionAlignment);
	auNewSection->PointerToRawData = auLastSection->PointerToRawData
		+ Alignment(auLastSection->SizeOfRawData, GetOptionalHeader(m_dwFileBase)->FileAlignment);

	// 3.4 ���������εĴ�С�������ļ���С����������ڴ��С������ڵ����ļ���С
	auNewSection->SizeOfRawData = auNewSection->Misc.VirtualSize = uSectionSize;

	// 4. ��������������Σ���������������Ҫ+1
	GetFileHeader(m_dwFileBase)->NumberOfSections++;

	// 5. ������������Σ���ҪΪ�����������
	// 5.1 �������Ҫռ�õ��ĵô�С(�µ��ļ���С)��������FOA+������RSIZE
	m_dwFileSize = auNewSection->PointerToRawData + auNewSection->SizeOfRawData;
	m_dwFileBase = (DWORD)realloc((LPVOID)m_dwFileBase, m_dwFileSize);

	// 6. �����������κ�� SizeOfImage = ������RVA + ������VSIZE
	GetOptionalHeader(m_dwFileBase)->SizeOfImage = auNewSection->VirtualAddress + auNewSection->Misc.VirtualSize;
}

// ���� OEP
void Pe::SetOep(LPCSTR lpSectionName)
{
	// ����ԭʼ��OEP��ShareData
	m_shareData->nOldOep = GetOptionalHeader(m_dwFileBase)->AddressOfEntryPoint;
	m_shareData->RelocRva = GetOptionalHeader(m_dwFileBase)->DataDirectory[5].VirtualAddress;

	// �����µ�OEP
	GetOptionalHeader(m_dwFileBase)->AddressOfEntryPoint = 
		GetSection(m_dwFileBase, lpSectionName)->VirtualAddress + m_dwStart;
}

// �޸��ض�λ
void Pe::FixReloc(LPCSTR lpDestName, LPCSTR lpSrcName)
{
	DWORD dwOldImageBase = GetOptionalHeader(m_dwDllBase)->ImageBase;
	DWORD dwNewImageBase = GetOptionalHeader(m_dwFileBase)->ImageBase;
	DWORD dwOldSectionBase = GetSection(m_dwDllBase, lpSrcName)->VirtualAddress;
	DWORD dwNewSectionBase = GetSection(m_dwFileBase, lpDestName)->VirtualAddress;

	// �ҵ�DLLģ����ض�λ��
	auto auRelocs = (PIMAGE_BASE_RELOCATION)(m_dwDllBase +
		GetOptionalHeader(m_dwDllBase)->DataDirectory[5].VirtualAddress);

	// �����ض�λ��
	while (auRelocs->SizeOfBlock)
	{
		DWORD dwOldProtect = 0;
		VirtualProtect((LPVOID)
			(m_dwDllBase + auRelocs->VirtualAddress), 0x1000, PAGE_READWRITE, &dwOldProtect);

		// �ҵ�ÿһ���ض�λ���е��ض�λ������
		TypeOffset* type = (TypeOffset*)(auRelocs + 1);

		// ��������е��ض�λ�����
		int nCount = (auRelocs->SizeOfBlock - 8) / 2;
		for (int i = 0; i < nCount; i++)
		{
			// �ж����� Type Ϊ 3 ��������޸�
			if (type[i].wType == 3)
			{
				// �����ÿһ����Ҫ�ض�λ���������ڵĵ�ַ
				DWORD* dwType = (DWORD*)
					(GetOptionalHeader(m_dwDllBase)->ImageBase + auRelocs->VirtualAddress + type[i].wOffset);

				*dwType = *dwType - dwOldImageBase - dwOldSectionBase + dwNewSectionBase + dwNewImageBase;
			}
		}
		VirtualProtect((LPVOID)
			(m_dwDllBase + auRelocs->VirtualAddress), 0x1000, dwOldProtect, &dwOldProtect);

		// �л�����һ���ض�λ��
		auRelocs = (PIMAGE_BASE_RELOCATION)(auRelocs->SizeOfBlock + (DWORD)auRelocs);
	}
	// �ر�Դ����������ַ
	//GetOptionalHeader(m_dwFileBase)->DllCharacteristics &= ~IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
}

// �޸��ض�λ
void Pe::AddRelocSection()
{
	//��ȡ���ӿǳ������һ������
	PIMAGE_SECTION_HEADER lastSection = &IMAGE_FIRST_SECTION(GetNtHeaders(m_dwFileBase))[GetFileHeader(m_dwFileBase)->NumberOfSections - 1];
	PIMAGE_SECTION_HEADER newRelocSection = lastSection + 1;
	//��ȡdll���ض�λ����ͷ
	PIMAGE_SECTION_HEADER dllRelocSeciton = GetSection((DWORD)m_dwDllBase, (LPSTR)".reloc");
	//��dll���ض�λ����ͷ���Ƶ����ӿǳ�����
	memcpy_s(newRelocSection, sizeof(IMAGE_SECTION_HEADER), dllRelocSeciton, sizeof(IMAGE_SECTION_HEADER));
	//�޸�������
	memcpy_s(newRelocSection->Name, 8, ".augen", 8);
	//�޸������ļ�ƫ��
	newRelocSection->PointerToRawData = lastSection->PointerToRawData + 
		Alignment(lastSection->SizeOfRawData, GetOptionalHeader(m_dwFileBase)->FileAlignment);
	//�޸�����RVA
	newRelocSection->VirtualAddress = lastSection->VirtualAddress + 
		Alignment(lastSection->Misc.VirtualSize, GetOptionalHeader(m_dwFileBase)->SectionAlignment);

	//�����ض�λ��text���ڵ��ض�λ��size

	//���Ǵ�����ض�λ���ַд�뵽����Ŀ¼����
	GetOptionalHeader(m_dwFileBase)->DataDirectory[5].VirtualAddress = newRelocSection->VirtualAddress;
	GetOptionalHeader(m_dwFileBase)->DataDirectory[5].Size = newRelocSection->Misc.VirtualSize;

	//��������������Ŀ
	GetFileHeader(m_dwFileBase)->NumberOfSections++;
	//��������ӳ���С
	GetOptionalHeader(m_dwFileBase)->SizeOfImage = newRelocSection->VirtualAddress +
		Alignment(newRelocSection->Misc.VirtualSize, GetOptionalHeader(m_dwFileBase)->SectionAlignment);;
	m_dwFileSize = newRelocSection->PointerToRawData + 
		Alignment(newRelocSection->SizeOfRawData, GetOptionalHeader(m_dwFileBase)->FileAlignment);
	m_dwFileBase = (DWORD)realloc((LPVOID)m_dwFileBase, m_dwFileSize);
	//��������,��ȡԴ���ݣ�dll�е����ݣ�
	LPVOID psrcData = (LPVOID)(m_dwDllBase + dllRelocSeciton->VirtualAddress);
	//Ŀ�껺������ַ
	LPVOID pdestData = (LPVOID)(m_dwFileBase + GetSection(m_dwFileBase, (LPSTR)".augen")->PointerToRawData);
	memcpy_s(pdestData, GetSection(m_dwFileBase, (LPSTR)".augen")->SizeOfRawData, psrcData, dllRelocSeciton->SizeOfRawData);

	//�޸��ض�λ�е�ƫ��
	PIMAGE_BASE_RELOCATION packReloc = (PIMAGE_BASE_RELOCATION)pdestData;
	DWORD packRva = GetSection(m_dwFileBase, (LPSTR)".demons")->VirtualAddress;
	while (packReloc->SizeOfBlock)
	{
		packReloc->VirtualAddress = packReloc->VirtualAddress + packRva - 0x1000;
		packReloc = (PIMAGE_BASE_RELOCATION)((DWORD)packReloc + packReloc->SizeOfBlock);
	}
}

// �����ļ�
void Pe::SavePeFile(LPCSTR lpPath)
{
	// �����ļ�
	HANDLE hFileHandle = CreateFileA(lpPath, GENERIC_WRITE, NULL,
		NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

	// ��PE����������һ����д���µ��ļ�
	DWORD dwWriteBytes = 0;
	WriteFile(hFileHandle, (LPVOID)m_dwFileBase, m_dwFileSize, &dwWriteBytes, NULL);

	// �ж��Ƿ���PE�ļ�
	PIMAGE_DOS_HEADER pDosHeader = GetDosHeader(m_dwFileBase);
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		return;
	}

	PIMAGE_NT_HEADERS pNtHeaders = GetNtHeaders(m_dwFileBase);
	if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE)
	{
		return;
	}

	// �رվ��
	CloseHandle(hFileHandle);
}
