#include "pch.h"
#include "Pe.h"

Pe::Pe()
{
	// 保存 dllbase 和 结构体
	// 不然在pack中调用的时候会被销毁
	m_dwDllBase = (DWORD)LoadLibraryExA("Stub.dll", NULL, DONT_RESOLVE_DLL_REFERENCES);
	m_shareData = (PSHAREDATA)GetProcAddress((HMODULE)m_dwDllBase, "ShareData");
}

// 打开PE文件
bool Pe::OpenPeFile(LPCSTR lpPath)
{
	// 文件存在的情况下以只读的方式打开文件
	HANDLE hFileHandle = GetPeFile(lpPath);

	// 获取文件的大小，并使用该大小申请空间用于保存
	m_dwFileSize = GetFileSize(hFileHandle, NULL); 
	m_dwFileBase = (DWORD)malloc(m_dwFileSize * sizeof(BYTE));

	// 将文件的所有内容一次性读取到缓冲区内
	DWORD dwReadBytes = 0;
	ReadFile(hFileHandle, (LPVOID)m_dwFileBase, m_dwFileSize, &dwReadBytes, NULL);

	// 判断当前是否是PE文件
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

	// 关闭句柄
	CloseHandle(hFileHandle);
}

// 打开dll文件
void Pe::OpenDllFile(LPCSTR lpPath, LPCSTR lpSectionName)
{
	// 将目标模块加载到当前的进程中，但是不调用DllMain
	m_dwDllBase = (DWORD)LoadLibraryExA(lpPath, NULL, DONT_RESOLVE_DLL_REFERENCES);

	// 从模块中获取到 m_dwStart 函数的偏移，计算后作为新的 OEP
	DWORD offset = (DWORD)GetProcAddress((HMODULE)m_dwDllBase, "Start");
	m_dwStart = (DWORD)GetProcAddress((HMODULE)m_dwDllBase, "Start") - 
		m_dwDllBase - GetSection(m_dwDllBase, lpSectionName)->VirtualAddress;

	m_shareData->HostTLS =
		GetOptionalHeader(m_dwFileBase)->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
	GetOptionalHeader(m_dwFileBase)->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress = 0;
	GetOptionalHeader(m_dwFileBase)->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size = 0;
	// 获取到DLL模块中的结构体变量
	m_shareData = (SHAREDATA*)GetProcAddress((HMODULE)m_dwDllBase, "ShareData");
}

// 获取文件内容和大小
char* Pe::GetFileData(LPCSTR lpPath, int* nFileSize)
{
	// 打开文件
	HANDLE hFIle = GetPeFile(lpPath);
	if (hFIle == INVALID_HANDLE_VALUE)
		return NULL;

	// 获取文件大小
	DWORD dwSize = GetFileSize(hFIle, NULL);
	if (nFileSize)
		*nFileSize = dwSize;

	// 申请堆空间
	char* pFileBuff = new char[dwSize] {0};

	// 读取文件内容到堆空间
	DWORD dwRead = 0;
	ReadFile(hFIle, pFileBuff, dwSize, &dwRead, NULL);
	CloseHandle(hFIle);

	return pFileBuff;
}

// 创建文件
HANDLE Pe::GetPeFile(LPCSTR lpPath)
{
	return CreateFileA((LPCSTR)lpPath, GENERIC_READ, FILE_SHARE_READ,
		NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
}

// 获取dos头
PIMAGE_DOS_HEADER Pe::GetDosHeader(DWORD dwModuleBase)
{
	return (PIMAGE_DOS_HEADER)dwModuleBase;
}

// 获取NT头
PIMAGE_NT_HEADERS Pe::GetNtHeaders(DWORD dwModuleBase)
{
	return (PIMAGE_NT_HEADERS)(GetDosHeader(dwModuleBase)->e_lfanew + dwModuleBase);
}

// 获取文件头
PIMAGE_FILE_HEADER Pe::GetFileHeader(DWORD dwModuleBase)
{
	return &GetNtHeaders(dwModuleBase)->FileHeader;
}

// 获取optional
PIMAGE_OPTIONAL_HEADER Pe::GetOptionalHeader(DWORD dwModuleBase)
{
	return &GetNtHeaders(dwModuleBase)->OptionalHeader;
}

// 获取 DataDirectory
PIMAGE_DATA_DIRECTORY Pe::GetDataDirectory(int nIndex, DWORD dwModuleBase)
{
	return &GetOptionalHeader(dwModuleBase)->DataDirectory[nIndex];
}

// 获取 SectionHeader
PIMAGE_SECTION_HEADER Pe::GetSectionHeader(DWORD dwModuleBase)
{
	PIMAGE_NT_HEADERS pNt = GetNtHeaders(dwModuleBase);
	return IMAGE_FIRST_SECTION(pNt);
}

// 获取 Section
PIMAGE_SECTION_HEADER Pe::GetSection(DWORD dwBase, LPCSTR lpSectionName)
{
	// 获取目标模块的区段数量遍历区段表
	auto auSection = GetSectionHeader(dwBase);

	// 使用文件头中的区段数量遍历区段表
	WORD wCount = GetFileHeader(dwBase)->NumberOfSections;
	if (!strcmp(lpSectionName, ".text"))
	{
		for (WORD i = 0; i < wCount; i++)
		{
			//对比每一个区段的名称是否和指定的名称相符合
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
			//对比每一个区段的名称是否和指定的名称相符合
			if (!memcmp(auSection[i].Name, lpSectionName, strlen(lpSectionName)))
			{
				return &auSection[i];
			}
		}
	}

	return NULL;
}

// 获取 FileBase
DWORD Pe::GetFileBase()
{
	return m_dwFileBase;
}

// 获取 DllBase
DWORD Pe::GetDllBase()
{
	return m_dwDllBase;
}

// 获取结构体
PSHAREDATA Pe::GetShareData()
{
	return m_shareData;
}

// Rva 转 Offset
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

// 计算对齐后的大小
DWORD Pe::Alignment(DWORD dwAddress, DWORD dwAlgn)
{
	return dwAddress % dwAlgn == 0 ? dwAddress : (dwAddress / dwAlgn + 1) * dwAlgn;
}

// 将Dll中的指定区段拷贝到被加壳程序中
void Pe::CopySection(LPCSTR lpDestName, LPCSTR lpSrcName)
{
	// 从 Dll 中找到 需要拷贝的区段所对应的结构体
	auto auSrcSection = GetSection(m_dwDllBase, lpSrcName);

	// 获取到被加壳程序的最后一个区段，并计算出新的区段地址
	auto auLastSection = &GetSectionHeader(m_dwFileBase)
		[GetFileHeader(m_dwFileBase)->NumberOfSections - 1];
	auto auNewSection = auLastSection + 1;

	// 将目标区段的内容复制下来
	memcpy(auNewSection, auSrcSection, sizeof(IMAGE_SECTION_HEADER));

	// 修改拷贝的数据，更新它的文件和内存基址(上个区段的基址+对齐(大小))和名称
	memcpy(auNewSection->Name, lpDestName, 7);
	auNewSection->PointerToRawData = auLastSection->PointerToRawData + 
		Alignment(auLastSection->SizeOfRawData, GetOptionalHeader(m_dwFileBase)->FileAlignment);
	auNewSection->VirtualAddress = auLastSection->VirtualAddress + 
		Alignment(auLastSection->Misc.VirtualSize, GetOptionalHeader(m_dwFileBase)->SectionAlignment);

	// 区段数量+1
	GetFileHeader(m_dwFileBase)->NumberOfSections++;

	// 为区段添加内容
	// 计算出需要占用的新的大小(新的文件大小)：新区段FOA + 新区段RSIZE
	m_dwFileSize = auNewSection->PointerToRawData + auNewSection->SizeOfRawData;
	m_dwFileBase = (DWORD)realloc((LPVOID)m_dwFileBase, m_dwFileSize);

	// 计算出添加区段后的 SizeOfImage = 新区段RVA + 新区段VSIZE
	GetOptionalHeader(m_dwFileBase)->SizeOfImage = auNewSection->VirtualAddress + auNewSection->Misc.VirtualSize;
}

// 将 DLL 中的指定区段的内容拷贝到被加壳程序中
void Pe::CopySectionData(LPCSTR lpDestName, LPCSTR lpSrcName)
{
	// 获取新的区段在被加壳程序中的起始位置
	LPVOID lpDestData = (LPVOID)(m_dwFileBase + GetSection(m_dwFileBase, lpDestName)->PointerToRawData);

	// 获取到需要拷贝的区段在DLL中的起始位置
	LPVOID lpSrcData = (LPVOID)(m_dwDllBase + GetSection(m_dwDllBase, lpSrcName)->VirtualAddress);

	// 将两个地址填入到拷贝操作做                       
	memcpy(lpDestData, lpSrcData, GetSection(m_dwDllBase, lpSrcName)->SizeOfRawData);
}

// 为目标PE文件添加一个指定大小的指定区段
void Pe::AddSection(LPCSTR lpSectionName, UINT uSectionSize)
{
	// 1. 先获取到区段表中最后一个区段的位置
	auto auLastSection = &GetSectionHeader(m_dwFileBase)[GetFileHeader(m_dwFileBase)->NumberOfSections - 1];

	// 2. 计算出新的被添加的区段表的结构体
	auto auNewSection = auLastSection + 1;

	// 3. 填充新的额结构体中的有意义的字段
	// 3.1 设置区段的名称，名称最长为8个字符，保留一个空字符
	memcpy(auNewSection->Name, lpSectionName, 7);

	// 3.2 新的区段中保存了代码数据，设置为可读可写可执行
	auNewSection->Characteristics = 0xF00000E0;

	// 3.3 设置新区段在虚拟内存中的起始位置：上一个区段RVA + 对齐VSIZE
	//		设置新区段在文件中的起始位置：上一个区段FOA + 对齐RSIZE
	auNewSection->VirtualAddress = auLastSection->VirtualAddress
		+ Alignment(auLastSection->Misc.VirtualSize, GetOptionalHeader(m_dwFileBase)->SectionAlignment);
	auNewSection->PointerToRawData = auLastSection->PointerToRawData
		+ Alignment(auLastSection->SizeOfRawData, GetOptionalHeader(m_dwFileBase)->FileAlignment);

	// 3.4 设置新区段的大小，其中文件大小必须堆区，内存大小必须大于等于文件大小
	auNewSection->SizeOfRawData = auNewSection->Misc.VirtualSize = uSectionSize;

	// 4. 由于新添加了区段，所以区段数量需要+1
	GetFileHeader(m_dwFileBase)->NumberOfSections++;

	// 5. 由于添加了区段，需要为区段添加内容
	// 5.1 计算出需要占用的心得大小(新的文件大小)：新区段FOA+新区段RSIZE
	m_dwFileSize = auNewSection->PointerToRawData + auNewSection->SizeOfRawData;
	m_dwFileBase = (DWORD)realloc((LPVOID)m_dwFileBase, m_dwFileSize);

	// 6. 计算出添加区段后的 SizeOfImage = 新区段RVA + 新区段VSIZE
	GetOptionalHeader(m_dwFileBase)->SizeOfImage = auNewSection->VirtualAddress + auNewSection->Misc.VirtualSize;
}

// 设置 OEP
void Pe::SetOep(LPCSTR lpSectionName)
{
	// 保存原始的OEP到ShareData
	m_shareData->nOldOep = GetOptionalHeader(m_dwFileBase)->AddressOfEntryPoint;
	m_shareData->RelocRva = GetOptionalHeader(m_dwFileBase)->DataDirectory[5].VirtualAddress;

	// 设置新的OEP
	GetOptionalHeader(m_dwFileBase)->AddressOfEntryPoint = 
		GetSection(m_dwFileBase, lpSectionName)->VirtualAddress + m_dwStart;
}

// 修复重定位
void Pe::FixReloc(LPCSTR lpDestName, LPCSTR lpSrcName)
{
	DWORD dwOldImageBase = GetOptionalHeader(m_dwDllBase)->ImageBase;
	DWORD dwNewImageBase = GetOptionalHeader(m_dwFileBase)->ImageBase;
	DWORD dwOldSectionBase = GetSection(m_dwDllBase, lpSrcName)->VirtualAddress;
	DWORD dwNewSectionBase = GetSection(m_dwFileBase, lpDestName)->VirtualAddress;

	// 找到DLL模块的重定位表
	auto auRelocs = (PIMAGE_BASE_RELOCATION)(m_dwDllBase +
		GetOptionalHeader(m_dwDllBase)->DataDirectory[5].VirtualAddress);

	// 遍历重定位表
	while (auRelocs->SizeOfBlock)
	{
		DWORD dwOldProtect = 0;
		VirtualProtect((LPVOID)
			(m_dwDllBase + auRelocs->VirtualAddress), 0x1000, PAGE_READWRITE, &dwOldProtect);

		// 找到每一个重定位块中的重定位项数组
		TypeOffset* type = (TypeOffset*)(auRelocs + 1);

		// 计算出所有的重定位项个数
		int nCount = (auRelocs->SizeOfBlock - 8) / 2;
		for (int i = 0; i < nCount; i++)
		{
			// 判断所有 Type 为 3 的项进行修复
			if (type[i].wType == 3)
			{
				// 计算出每一个需要重定位的数据所在的地址
				DWORD* dwType = (DWORD*)
					(GetOptionalHeader(m_dwDllBase)->ImageBase + auRelocs->VirtualAddress + type[i].wOffset);

				*dwType = *dwType - dwOldImageBase - dwOldSectionBase + dwNewSectionBase + dwNewImageBase;
			}
		}
		VirtualProtect((LPVOID)
			(m_dwDllBase + auRelocs->VirtualAddress), 0x1000, dwOldProtect, &dwOldProtect);

		// 切换到下一个重定位块
		auRelocs = (PIMAGE_BASE_RELOCATION)(auRelocs->SizeOfBlock + (DWORD)auRelocs);
	}
	// 关闭源程序的随机基址
	//GetOptionalHeader(m_dwFileBase)->DllCharacteristics &= ~IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
}

// 修复重定位
void Pe::AddRelocSection()
{
	//获取被加壳程序最后一个区段
	PIMAGE_SECTION_HEADER lastSection = &IMAGE_FIRST_SECTION(GetNtHeaders(m_dwFileBase))[GetFileHeader(m_dwFileBase)->NumberOfSections - 1];
	PIMAGE_SECTION_HEADER newRelocSection = lastSection + 1;
	//获取dll的重定位区段头
	PIMAGE_SECTION_HEADER dllRelocSeciton = GetSection((DWORD)m_dwDllBase, (LPSTR)".reloc");
	//将dll的重定位区段头复制到被加壳程序中
	memcpy_s(newRelocSection, sizeof(IMAGE_SECTION_HEADER), dllRelocSeciton, sizeof(IMAGE_SECTION_HEADER));
	//修改区段名
	memcpy_s(newRelocSection->Name, 8, ".augen", 8);
	//修改区段文件偏移
	newRelocSection->PointerToRawData = lastSection->PointerToRawData + 
		Alignment(lastSection->SizeOfRawData, GetOptionalHeader(m_dwFileBase)->FileAlignment);
	//修改区段RVA
	newRelocSection->VirtualAddress = lastSection->VirtualAddress + 
		Alignment(lastSection->Misc.VirtualSize, GetOptionalHeader(m_dwFileBase)->SectionAlignment);

	//遍历重定位表，text段内的重定位项size

	//将壳代码的重定位表地址写入到数据目录表中
	GetOptionalHeader(m_dwFileBase)->DataDirectory[5].VirtualAddress = newRelocSection->VirtualAddress;
	GetOptionalHeader(m_dwFileBase)->DataDirectory[5].Size = newRelocSection->Misc.VirtualSize;

	//重新设置区段数目
	GetFileHeader(m_dwFileBase)->NumberOfSections++;
	//重新设置映像大小
	GetOptionalHeader(m_dwFileBase)->SizeOfImage = newRelocSection->VirtualAddress +
		Alignment(newRelocSection->Misc.VirtualSize, GetOptionalHeader(m_dwFileBase)->SectionAlignment);;
	m_dwFileSize = newRelocSection->PointerToRawData + 
		Alignment(newRelocSection->SizeOfRawData, GetOptionalHeader(m_dwFileBase)->FileAlignment);
	m_dwFileBase = (DWORD)realloc((LPVOID)m_dwFileBase, m_dwFileSize);
	//复制数据,获取源数据（dll中的数据）
	LPVOID psrcData = (LPVOID)(m_dwDllBase + dllRelocSeciton->VirtualAddress);
	//目标缓冲区地址
	LPVOID pdestData = (LPVOID)(m_dwFileBase + GetSection(m_dwFileBase, (LPSTR)".augen")->PointerToRawData);
	memcpy_s(pdestData, GetSection(m_dwFileBase, (LPSTR)".augen")->SizeOfRawData, psrcData, dllRelocSeciton->SizeOfRawData);

	//修改重定位中的偏移
	PIMAGE_BASE_RELOCATION packReloc = (PIMAGE_BASE_RELOCATION)pdestData;
	DWORD packRva = GetSection(m_dwFileBase, (LPSTR)".demons")->VirtualAddress;
	while (packReloc->SizeOfBlock)
	{
		packReloc->VirtualAddress = packReloc->VirtualAddress + packRva - 0x1000;
		packReloc = (PIMAGE_BASE_RELOCATION)((DWORD)packReloc + packReloc->SizeOfBlock);
	}
}

// 保存文件
void Pe::SavePeFile(LPCSTR lpPath)
{
	// 创建文件
	HANDLE hFileHandle = CreateFileA(lpPath, GENERIC_WRITE, NULL,
		NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

	// 将PE的所有内容一次性写入新的文件
	DWORD dwWriteBytes = 0;
	WriteFile(hFileHandle, (LPVOID)m_dwFileBase, m_dwFileSize, &dwWriteBytes, NULL);

	// 判断是否是PE文件
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

	// 关闭句柄
	CloseHandle(hFileHandle);
}
