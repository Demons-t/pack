#include "stub.h"

#pragma comment(linker, "/merge:.data=.text")
#pragma comment(linker, "/merge:.rdata=.text")
#pragma comment(linker, "/section:.text,RWE")

API		g_api;
void*	g_disp;

extern "C" __declspec(dllexport) SHAREDATA ShareData = { 0 };

// 解密
void Decrypt()
{
	unsigned char* pText = (unsigned char*)ShareData.dwTextScnRVA + g_api.dwImageBase;

	// 修改代码段的属性
	DWORD dwOld = 0;
	g_api.VirtualProtect(pText, ShareData.dwTextScnSize, PAGE_READWRITE, &dwOld);

	// 解密代码段
	for (DWORD i = 0; i < ShareData.dwTextScnSize; i++)
	{
		pText[i] ^= ShareData.dwKey;
	}

	g_api.VirtualProtect(pText, ShareData.dwTextScnSize, dwOld, &dwOld);
}

// strcmp
DWORD MyStrcmp(char* pDst, char const* pSrc)
{
	DWORD dwRet = 0;
	while (!(dwRet = *pSrc - *pDst) && *pDst)
	{
		++pSrc;
		++pDst;
	}
	if (dwRet < 0)
	{
		dwRet = -1;
	}
	else if (dwRet > 0)
	{
		dwRet = 1;
	}
	return dwRet;
}

// memcpy
char* MyMemcpy(char* pDst, char* pSrc, DWORD dwSize)
{
	char* pOrigin = pDst;
	for (int i = 0; i < dwSize; i++)
	{
		((char*)pDst)[i] = ((char*)pSrc)[i];
	}
	return pOrigin;
}

// strlen
DWORD MyStrlen(const char* pDst)
{
	DWORD dwRet = 0;
	while (pDst[dwRet]!=0)
	{
		dwRet++;
	}
	return dwRet;
}

// memset
void MyMemset(char* pDst, DWORD dwLength)
{
	for (int i = 0; i < dwLength; i++)
	{
		((char*)pDst)[i] = 0;
	}
}

// findstr
INT MyFindStr(CHAR* nText, CHAR nText2)
{
	int i = 0;
	while (nText[i])
	{
		if (nText[i] == nText2)
			return i;
		i++;
	}
	return -1;
}

// GetStrLeft
VOID MyGetStrLeft(CHAR* nDest, CHAR* nSrc, CHAR nSeg)
{
	int i = 0;
	while (nSrc[i]!=nSeg)
	{
		nDest[i] = nSrc[i];
		i++;
	}
}

// GetStrRight
VOID MyGetStrRight(CHAR* nDest, CHAR* nSrc, CHAR nSeg)
{
	int i = 0;
	while (nSrc[i]!=nSeg)
	{
		i++;
	}
	i++;
	int j = 0;
	while (nSrc[i])
	{
		nDest[j] = nSrc[i];
		i++;
		j++;
	}
}

// strcpy
char* MyStrcpy(char* dst, const char* src)//考虑内存重叠的情况,需要倒过来拷贝
{
	if (dst == NULL || src == NULL)
		return NULL;

	if (dst == src)
		return dst;

	char* ret = dst;
	int nLen = MyStrlen(src);
	dst = dst + nLen;
	src = src + nLen;
	int nLoop = nLen + 1;
	while (nLoop--)
	{
		*dst = *src;
		src--;
		dst--;
	}

	return ret;
}

// floor
float my_floor(float a)
{
	int r = a;
	if (a < 0) --r;
	return (float)r;
}

// equal
int equal(double elem1, double elem2)
{
	if ((elem1 - elem2 < 0.0000001) && (elem1 - elem2 > -0.0000001))
		return 1;	//相等
	else
		return 0;	//不相等
}

double power_unsigned_exp(double base, unsigned int exponent)
{
	double result = 0.0;

	if (0 == exponent)
		return 1.0;
	if (1 == exponent)
		return base;

	result = power_unsigned_exp(base, exponent / 2);
	if (exponent & 1 == 1)
		result *= base;

	return result;
}

// power
double power(double base, int exponent)
{
	unsigned int abs_exponent = exponent;
	double result = 0.0;
	bool invalid_input = 0;

	if (equal(base, 0.0) && exponent < 0)
	{
		invalid_input = 1;
		return 0.0;
	}

	if (exponent < 0)
		abs_exponent = (unsigned int)(-exponent);

	result = power_unsigned_exp(base, abs_exponent >> 1);
	result *= result;

	if (result < 0)
		result = 1.0 / result;

	return result;
}

// itoa
char* my_itoa(int num, char* buffer, int base) 
{
	int curr = 0;

	if (num == 0) {
		// Base case
		buffer[curr++] = '0';
		buffer[curr] = '\0';
		return buffer;
	}

	int num_digits = 0;

	if (num < 0) {
		if (base == 10) {
			num_digits++;
			buffer[curr] = '-';
			curr++;
			num *= -1;
		}
		else
			return NULL;
	}

	num_digits += (int)my_floor(num / base) + 1;

	while (curr < num_digits) {
		int base_val = (int)power(base, num_digits - 1 - curr);

		int num_val = num / base_val;

		char value = num_val + '0';
		buffer[curr] = value;

		curr++;
		num -= base_val * num_val;
	}
	buffer[curr] = '\0';
	return buffer;
}

// sprintf
int mysprintf(char* szBuff, const char* fmt, ...)
{
	va_list ap = NULL;
	const char* pFmt = fmt;
	char* pBuff = szBuff;

	va_start(ap, fmt);

	while (*pFmt != NULL)
	{
		if (*pFmt != '%')
		{
			*pBuff++ = *pFmt++;
		}
		else
		{
			int swNum = 0;
			char numBuff[64] = { 0 };
			char* szStr = NULL;

			pFmt++;

			switch (*pFmt++)
			{
			case 'd':
				swNum = va_arg(ap, int);
				my_itoa(swNum, numBuff, 10);
				MyStrcpy(pBuff, numBuff);
				pBuff += MyStrlen(numBuff);
				break;
			case 's':
				szStr = va_arg(ap, char*);
				MyStrcpy(pBuff, szStr);
				pBuff += MyStrlen(szStr);
				break;
			default:
				break;
			}
		}
	}
	va_end(ap);

	return 0;
}

// 获取Dos头
PIMAGE_DOS_HEADER GetDosHeader(char* pFileData)
{
	return (PIMAGE_DOS_HEADER)pFileData;
}

PDOSSTUB GetDosStubHeader(char* pFileData)
{
	return (PDOSSTUB)(pFileData + sizeof(IMAGE_DOS_HEADER));
}

// 获取Nt头
PIMAGE_NT_HEADERS GetNtHeaders(char* pFileData)
{
	return (PIMAGE_NT_HEADERS)(GetDosHeader(pFileData)->e_lfanew + (SIZE_T)pFileData);
}

// 获取文件头
PIMAGE_FILE_HEADER GetFileHeader(char* pFileData)
{
	return &GetNtHeaders(pFileData)->FileHeader;
}

// 获取 OptioHeader
PIMAGE_OPTIONAL_HEADER GetOptionHeader(char* pFileData)
{
	return &GetNtHeaders(pFileData)->OptionalHeader;
}

// 获取Section
PIMAGE_SECTION_HEADER GetSection(DWORD dwBase, LPCSTR lpSectionName)
{
	// 获取目标模块的区段数量遍历区段表
	auto auSection = IMAGE_FIRST_SECTION(GetNtHeaders((char*)dwBase));

	// 使用文件头中的区段数量遍历区段表
	WORD wCount = GetFileHeader((char*)dwBase)->NumberOfSections;

	for (WORD i = 0; i < wCount; i++)
	{
		//对比每一个区段的名称是否和指定的名称相符合
		if (!MyStrcmp((char*)auSection[i].Name, (char*)lpSectionName))
		{
			return &auSection[i];
		}
	}

	return NULL;
}

// 获取Kernel32地址
DWORD GetKernel32ModuleHandle()
{
	DWORD dwKernel32 = 0;
	__asm
	{
		push esi;
		mov esi, fs: [0x30] ;   //得到PEB地址
		mov esi, [esi + 0xc]; //指向PEB_LDR_DATA结构的首地址
		mov esi, [esi + 0x1c];//一个双向链表的地址
		mov esi, [esi];       //得到第2个条目kernelBase的链表
		mov esi, [esi];       //得到第3个条目kernel32的链表(win10系统)
		mov esi, [esi + 0x8]; //kernel32.dll地址
		mov dwKernel32, esi;
		pop esi;
	}
	return dwKernel32;
}

// 实现自己的 GetProcAddress
DWORD GetProcAddressFunAddr()
{
	DWORD dwKernel32 = 0;
	__asm
	{
		push esi;
		mov esi, fs: [0x30] ;   //得到PEB地址
		mov esi, [esi + 0xc]; //指向PEB_LDR_DATA结构的首地址
		mov esi, [esi + 0x1c];//一个双向链表的地址
		mov esi, [esi];       //得到第2个条目kernelBase的链表
		mov esi, [esi];       //得到第3个条目kernel32的链表(win10系统)
		mov esi, [esi + 0x8]; //kernel32.dll地址
		
		pushad
		mov ebp, esp
		sub esp, 0xc
		mov edx, esi
		mov esi, [edx + 0x3c]		//NT头的RVA
		lea esi, [esi + edx]		//NT头的VA
		mov esi, [esi + 0x78]		//Export的Rva
		lea edi, [esi + edx]		//Export的Va

		mov esi, [edi + 0x1c]		//Eat的Rva
		lea esi, [esi + edx]		//Eat的Va
		mov[ebp - 0x4], esi			//保存Eat

		mov esi, [edi + 0x20]		//Ent的Rva
		lea esi, [esi + edx]		//Ent的Va
		mov[ebp - 0x8], esi			//保存Ent

		mov esi, [edi + 0x24]		//Eot的Rva
		lea esi, [esi + edx]		//Eot的Va
		mov[ebp - 0xc], esi			//保存Eot

		xor ecx, ecx
		jmp _First
	_Zero:
		inc ecx
	_First:
		mov esi, [ebp - 0x8]				//Ent的Va
		mov esi, [esi + ecx * 4]			//FunName的Rva

		lea esi, [esi + edx]				//FunName的Va
		cmp dword ptr[esi], 050746547h		// 47657450 726F6341 64647265 7373;
		jne _Zero;							// 上面的16进制是GetProcAddress的ASCII
		cmp dword ptr[esi + 4], 041636f72h
		jne _Zero;
		cmp dword ptr[esi + 8], 065726464h
		jne _Zero;
		cmp word  ptr[esi + 0ch], 07373h
		jne _Zero;

		xor ebx, ebx
		mov esi, [ebp - 0xc]			//Eot的Va
		mov bx, [esi + ecx * 2]			//得到序号

		mov esi, [ebp - 0x4]			//Eat的Va
		mov esi, [esi + ebx * 4]		//FunAddr的Rva
		lea eax, [esi + edx]			//FunAddr
		mov g_api.GetProcAddress, eax
		add esp, 0xc
		popad
		pop esi
	}
}

// 哈希加密
DWORD HashPassWord(char* pSrc)
{
	DWORD dwRet = 0;
	while (pSrc)
	{
		dwRet = ((dwRet << 25) | (dwRet >> 7));
		dwRet = dwRet + *pSrc;
		pSrc++;
	}
	return dwRet;
}

// 获取被加壳程序主机的CPUID
void cpuId()
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
	mysprintf(buf, "%08X%08X%08X%08X", s1, s2, s3, s4);
	/*int cpuInfo[4] = { 0 };
	__cpuid(cpuInfo, 1);
	char buf[MAX_PATH] = { 0 };
	mysprintf(buf, "%08X%08X%08X%08X", cpuInfo[0], cpuInfo[1], cpuInfo[2], cpuInfo[3]);*/
	DWORD dwSize = MyStrlen(buf);
	for (DWORD i = 0; i < dwSize; i++)
	{
		if (buf[i] != ShareData.pOldCpuId[i])
			g_api.ExitProcess(0);
	}
}

// 解密CPUID
void DecryptCpuId()
{
	for (DWORD i = 0; i < ShareData.dwCpuSize; i++)
	{
		ShareData.pCpuId[i] ^= ShareData.dwCpuKey;
		if (ShareData.pCpuId[i] != ShareData.pOldCpuId[i])
			g_api.ExitProcess(0);
	}
}

// 设置属性为可写
void SetFileHeaderProtect(bool bWrite)
{
	// 获取当前程序的加载基址
	DWORD dwImage = (DWORD)g_api.dwImageBase;
	DWORD dwOldProtect = 0;
	if (bWrite)
		g_api.VirtualProtect((LPVOID)dwImage, 0x400, PAGE_EXECUTE_READWRITE, &dwOldProtect);
	else
		g_api.VirtualProtect((LPVOID)dwImage, 0x400, dwOldProtect, &dwOldProtect);
}

// 初始化API
void InitApi()
{
	HMODULE hKernel32 = (HMODULE)GetKernel32ModuleHandle();

	GetProcAddressFunAddr();
	g_api.LoadLibraryExA = (fnLoadLibraryExA)g_api.GetProcAddress((HMODULE)hKernel32, "LoadLibraryExA");
	g_api.LoadLibraryA = (fnLoadLibraryA)g_api.GetProcAddress((HMODULE)hKernel32, "LoadLibraryA");
	g_api.GetModuleHandleA = (fnGetModuleHandleA)g_api.GetProcAddress((HMODULE)hKernel32, "GetModuleHandleA");
	g_api.MyRtlMoveMemory = (fnRtlMoveMemory)g_api.GetProcAddress((HMODULE)hKernel32, "RtlMoveMemory");
	g_api.MyRtlZeroMemory = (fnRtlZeroMemory)g_api.GetProcAddress((HMODULE)hKernel32, "RtlZeroMemory");
	g_api.VirtualProtect = (fnVirtualProtect)g_api.GetProcAddress((HMODULE)hKernel32, "VirtualProtect");
	g_api.VirtualAlloc = (fnVirtualAlloc)g_api.GetProcAddress((HMODULE)hKernel32, "VirtualAlloc");
	g_api.VirtualFree = (fnVirtualFree)g_api.GetProcAddress((HMODULE)hKernel32, "VirtualFree");

	HMODULE hUser32 = g_api.LoadLibraryExA("user32.dll", NULL, 0);

	g_api.DefWindowProcW = (fnDefWindowProcW)g_api.GetProcAddress(hUser32, "DefWindowProcW");
	g_api.RegisterClassExW = (fnRegisterClassExW)g_api.GetProcAddress(hUser32, "RegisterClassExW");
	g_api.CreateWindowExW = (fnCreateWindowExW)g_api.GetProcAddress(hUser32, "CreateWindowExW");
	g_api.ShowWindow = (fnShowWindow)g_api.GetProcAddress(hUser32, "ShowWindow");
	g_api.UpdateWindow = (fnUpdateWindow)g_api.GetProcAddress(hUser32, "UpdateWindow");
	g_api.GetMessageW = (fnGetMessageW)g_api.GetProcAddress(hUser32, "GetMessageW");
	g_api.TranslateMessage = (fnTranslateMessage)g_api.GetProcAddress(hUser32, "TranslateMessage");
	g_api.DispatchMessageW = (fnDispatchMessageW)g_api.GetProcAddress(hUser32, "DispatchMessageW");
	g_api.ExitProcess = (fnExitProcess)g_api.GetProcAddress(hKernel32, "ExitProcess");
	g_api.PostQuitMessage = (fnPostQuitMessage)g_api.GetProcAddress(hUser32, "PostQuitMessage");
	g_api.DestroyWindow = (fnDestroyWindow)g_api.GetProcAddress(hUser32, "DestroyWindow");
	g_api.GetDlgItemTextA = (fnGetDlgItemTextA)g_api.GetProcAddress(hUser32, "GetDlgItemTextA");
	g_api.MessageBoxW = (fnMessageBoxW)g_api.GetProcAddress(hUser32, "MessageBoxW");
	g_api.SetUnhandledExceptionFilter = (fnSetUnhandledExceptionFilter)g_api.GetProcAddress(hKernel32, "SetUnhandledExceptionFilter");
	g_api.GetWindowTextW = (fnGetWindowTextW)g_api.GetProcAddress(hUser32, "GetWindowTextW");
	g_api.GetWindowTextA = (fnGetWindowTextA)g_api.GetProcAddress(hUser32, "GetWindowTextA");
	g_api.SendMessageW = (fnSendMessageW)g_api.GetProcAddress(hUser32, "SendMessageW");
	g_api.FindWindowW = (fnFindWindowW)g_api.GetProcAddress(hUser32, "FindWindowW");
	g_api.dwImageBase = (DWORD)g_api.GetModuleHandleA(NULL);
}

// 加密
DWORD Decry(DWORD dwFun)
{
	// 申请内存空间
	DWORD dwNewMem = (DWORD)g_api.VirtualAlloc(NULL, 0x20, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	// 加密函数地址
	DWORD dwEncry = 0;
	__asm
	{
		push eax
		mov eax, dwFun
		xor eax, 0x15151515
		mov dwEncry, eax
		pop eax
	}

	BYTE OpCode[] = {
					0xE8, 0x01, 0x00, 0x00,
					0x00, 0xE9, 0x58, 0xEB,
					0x01, 0xE8, 0xB8, 0x85,
					0xEE, 0xCB, 0x60, 0xEB,
					0x01, 0x15, 0x35, 0x15,
					0x15, 0x15, 0x15, 0xEB,
					0x01, 0xFF, 0x50, 0xEB,
					0x02, 0xFF, 0x15, 0xC3 };
	OpCode[11] = dwEncry;		// 0x85
	OpCode[12] = dwEncry >> 0x08;	// 0xEE
	OpCode[13] = dwEncry >> 0x10;	// 0xCB
	OpCode[14] = dwEncry >> 0x18;	// 0x60

	// 将数据拷贝到申请的内存
	g_api.MyRtlMoveMemory((LPVOID)dwNewMem, OpCode, 0x20);

	// 返回新的函数地址
	return dwNewMem;
}

// 恢复数据目录表
void RecoverDataDir()
{
	// 获取当前程序的加载基址
	char* dwBase = (char*)g_api.dwImageBase;
	// 获取数据目录表的个数
	DWORD dwNumOfDataDir = ShareData.dwNumOfDataDir;

	DWORD dwOldAddr = 0;
	PIMAGE_DATA_DIRECTORY pDataDir = (GetOptionHeader(dwBase)->DataDirectory);
	// 遍历数据目录表
	for (DWORD i = 0; i < dwNumOfDataDir; i++)
	{
		if (i == 2)
		{
			pDataDir++;
			continue;
		}
		// 修改属性为可读可写
		g_api.VirtualProtect(pDataDir, 0x8, PAGE_EXECUTE_READWRITE, &dwOldAddr);

		// 还原数据目录表项
		pDataDir->VirtualAddress = ShareData.dwDataDir[i][0];
		pDataDir->Size = ShareData.dwDataDir[i][1];

		// 将属性修改回原来的
		g_api.VirtualProtect(pDataDir, 0x8, dwOldAddr, &dwOldAddr);
		pDataDir++;
	}
}

// 修复 IAT
void FixIat()
{
	// 设置文件属性为可写
	SetFileHeaderProtect(true);
	// 获取当前程序的加载基址
	DWORD dwImageBase = (DWORD)g_api.dwImageBase;

	PIMAGE_THUNK_DATA pInt = NULL;
	PIMAGE_THUNK_DATA pIat = NULL;
	SIZE_T sizeImpAddress = 0;
	HMODULE hImpModule = 0;
	DWORD dwOldProtect = 0;
	PIMAGE_IMPORT_BY_NAME pImpName = 0;

	if (!GetOptionHeader((char*)dwImageBase)->DataDirectory[1].VirtualAddress)
		return;

	// 导入表 = 导入表偏移 + 加载基址
	PIMAGE_IMPORT_DESCRIPTOR pImp = (PIMAGE_IMPORT_DESCRIPTOR)
		(GetOptionHeader((char*)dwImageBase)->DataDirectory[1].VirtualAddress + dwImageBase);

	while (pImp->Name)
	{
		// IAT = 偏移 + 加载基址
		pIat = (PIMAGE_THUNK_DATA)(pImp->FirstThunk + dwImageBase);
		if (pImp->OriginalFirstThunk == 0)	// 如果不存在INT则使用IAT
			pInt = pIat;
		else
			pInt = (PIMAGE_THUNK_DATA)(pImp->OriginalFirstThunk + dwImageBase);

		// 加载DLL
		hImpModule = (HMODULE)g_api.LoadLibraryA((char*)(pImp->Name + dwImageBase));
		// 导入函数地址
		while (pInt->u1.Function)
		{
			// 判断导入的方式，序号还是名称
			if (!IMAGE_SNAP_BY_ORDINAL(pInt->u1.Ordinal))
			{
				pImpName = (PIMAGE_IMPORT_BY_NAME)(pInt->u1.Function + dwImageBase);
				sizeImpAddress = (SIZE_T)g_api.GetProcAddress(hImpModule, (char*)pImpName->Name);
			}
			else
			{
				sizeImpAddress = (SIZE_T)g_api.GetProcAddress(hImpModule, (char*)(pInt->u1.Function & 0xFFFF));
			}

			g_api.VirtualProtect(&pIat->u1.Function, sizeof(pIat->u1.Function), PAGE_READWRITE, &dwOldProtect);
			pIat->u1.Function = sizeImpAddress;
			g_api.VirtualProtect(&pIat->u1.Function, sizeof(pIat->u1.Function), dwOldProtect, &dwOldProtect);
			++pInt;
			++pIat;
		}
		++pImp;
	}
	SetFileHeaderProtect(false);
}

// 加密 IAT
void DecryIat()
{
	// 设置文件属性为可写
	SetFileHeaderProtect(true);
	// 获取当前程序的加载基址
	DWORD dwImageBase = (DWORD)g_api.dwImageBase;

	PIMAGE_THUNK_DATA pInt = NULL;
	PIMAGE_THUNK_DATA pIat = NULL;
	SIZE_T sizeImpAddress = 0;
	HMODULE hImpModule = 0;
	DWORD dwOldProtect = 0;
	PIMAGE_IMPORT_BY_NAME pImpName = 0;

	if (!GetOptionHeader((char*)dwImageBase)->DataDirectory[1].VirtualAddress)
		return;

	// 导入表 = 导入表偏移 + 加载基址
	PIMAGE_IMPORT_DESCRIPTOR pImp = (PIMAGE_IMPORT_DESCRIPTOR)
		(GetOptionHeader((char*)dwImageBase)->DataDirectory[1].VirtualAddress + dwImageBase);

	while (pImp->Name)
	{
		// IAT = 偏移 + 加载基址
		pIat = (PIMAGE_THUNK_DATA)(pImp->FirstThunk + dwImageBase);
		if (pImp->OriginalFirstThunk == 0)	// 如果不存在INT则使用IAT
			pInt = pIat;
		else
			pInt = (PIMAGE_THUNK_DATA)(pImp->OriginalFirstThunk + dwImageBase);

		// 加载DLL
		hImpModule = (HMODULE)g_api.LoadLibraryA((char*)(pImp->Name + dwImageBase));
		// 导入函数地址
		while (pInt->u1.Function)
		{
			// 判断导入的方式，序号还是名称
			if (!IMAGE_SNAP_BY_ORDINAL(pInt->u1.Ordinal))
			{
				pImpName = (PIMAGE_IMPORT_BY_NAME)(pInt->u1.Function + dwImageBase);
				sizeImpAddress = (SIZE_T)g_api.GetProcAddress(hImpModule, (char*)pImpName->Name);
			}
			else
			{
				sizeImpAddress = (SIZE_T)g_api.GetProcAddress(hImpModule, (char*)(pInt->u1.Function & 0xFFFF));
			}

			g_api.VirtualProtect(&pIat->u1.Function, sizeof(pIat->u1.Function), PAGE_READWRITE, &dwOldProtect);
			pIat->u1.Function = Decry(sizeImpAddress);
			g_api.VirtualProtect(&pIat->u1.Function, sizeof(pIat->u1.Function), dwOldProtect, &dwOldProtect);
			++pInt;
			++pIat;
		}
		++pImp;
	}
	SetFileHeaderProtect(false);
}

// 哈希值与函数名比较
bool HashCmpString(char* strFunName, int nHash)
{
	unsigned int nDigest = 0;
	while (*strFunName)
	{
		nDigest = ((nDigest << 25) | (nDigest >> 7));
		nDigest = nDigest + *strFunName;
		strFunName++;
	}
	return nHash == nDigest ? true : false;
}

// 通过哈希值获取API函数地址
int GetFunAddrByHash(int nHashDigest, HMODULE hModule)
{
	// 获取Dos头，NT头
	PIMAGE_DOS_HEADER pDos;
	PIMAGE_NT_HEADERS pNt;
	pDos = (PIMAGE_DOS_HEADER)hModule;
	pNt = (PIMAGE_NT_HEADERS)((DWORD)hModule + pDos->e_lfanew);

	// 获取导出表项
	PIMAGE_DATA_DIRECTORY pDataDir;
	PIMAGE_EXPORT_DIRECTORY pExport;
	pDataDir = pNt->OptionalHeader.DataDirectory + IMAGE_DIRECTORY_ENTRY_EXPORT;
	pExport = (PIMAGE_EXPORT_DIRECTORY)((DWORD)hModule + pDataDir->VirtualAddress);

	// 获取导出表详细信息
	PDWORD pAddrOfFun = (PDWORD)(pExport->AddressOfFunctions + (DWORD)hModule);
	PDWORD pAddrOfName = (PDWORD)(pExport->AddressOfNames + (DWORD)hModule);
	PWORD pAddrOfOrdinals = (PWORD)(pExport->AddressOfNameOrdinals + (DWORD)hModule);

	// 处理以函数名查找函数地址的请求，循环获取ENT中的函数名，并与传入值对比，如果能匹配，则在EAT中
	// 以指定序号为索引，并取出其地址值
	DWORD dwFunAddr;
	for (DWORD i = 0; i < pExport->NumberOfNames; i++)
	{
		PCHAR lpFunName = (PCHAR)(pAddrOfName[i] + (DWORD)hModule);
		if (HashCmpString(lpFunName, nHashDigest))
		{
			dwFunAddr = pAddrOfFun[pAddrOfOrdinals[i]] + (DWORD)hModule;
			break;
		}
		if (i == pExport->NumberOfNames - 1)
			return 0;
	}
	return dwFunAddr;
}

//修复重定位
void FixRelocation(DWORD relocRva)
{
	DWORD imageBase = g_api.dwImageBase;

	if (relocRva == 0)
		return;
	PIMAGE_BASE_RELOCATION prelocAdd = (PIMAGE_BASE_RELOCATION)(imageBase + relocRva);
	PIMAGE_SECTION_HEADER packreSection = GetSection(imageBase, ".augen");
	DWORD oldPageProtect = 0;
	//修改此页访问属性为可读可写

	while (prelocAdd->SizeOfBlock)
	{
		//获取到第一个重定位项
		PTYPEOFFSET relocBlock = (PTYPEOFFSET)(prelocAdd + 1);
		//获取重定位项个数
		DWORD count = (prelocAdd->SizeOfBlock - 8) / 2;

		g_api.VirtualProtect((LPVOID)(imageBase + prelocAdd->VirtualAddress), 0x2000, PAGE_READWRITE, &oldPageProtect);
		for (DWORD i = 0; i < count; i++)
		{
			//判断此重定位项是否有效
			if (relocBlock[i].wType == 3)
			{
				//获取此重定位项地址,从加载这个dll的加载基址处找到对应项的偏移
				PDWORD item = (PDWORD)(imageBase + prelocAdd->VirtualAddress + relocBlock[i].wOffset);
				//修复此项
				*item = *item - 0x400000 + (DWORD)imageBase;
			}
		}
		g_api.VirtualProtect((LPVOID)(imageBase + prelocAdd->VirtualAddress), 0x2000, oldPageProtect, &oldPageProtect);
		//切换到下一个重定位块
		prelocAdd = (PIMAGE_BASE_RELOCATION)(prelocAdd->SizeOfBlock + (DWORD)prelocAdd);
	}
}

//解压缩
void DecompressCode()
{
	// 获取 Dos 头和 Nt 头
	DWORD FileBase = 0;
	_asm
	{
		mov eax, fs: [0x30]				// 获取 peb
		mov eax, dword ptr[eax + 0x08]	// ImageBase
		mov FileBase, eax
	}
	auto DosHeader = (PIMAGE_DOS_HEADER)(FileBase);
	auto NtHeader = (PIMAGE_NT_HEADERS)(FileBase + DosHeader->e_lfanew);
	auto* Section = IMAGE_FIRST_SECTION(NtHeader);
	int nCount = NtHeader->FileHeader.NumberOfSections;
	for (int i = 0; i < nCount - 2; i++)
	{
		if (Section->Characteristics == 0)
			continue;
		//区段的VA
		char* SectionVa = (char*)(FileBase + Section->VirtualAddress);
		//获取解压后的大小
		DWORD packSize = aPsafe_get_orig_size(SectionVa);
		if (packSize != ShareData.oldSize[i].oldSectionSize)
		{
			g_api.ExitProcess(0);
		}
		//申请内存
		char* pBuff = (char*)g_api.VirtualAlloc(NULL, packSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		//解压
		aPsafe_depack(SectionVa, Section->SizeOfRawData, pBuff, packSize);
		DWORD dwOld;
		g_api.VirtualProtect(SectionVa, packSize, PAGE_READWRITE, &dwOld);
		//修改为压缩后的数据
		MyMemcpy(SectionVa, pBuff, packSize);
		//pRtlMoveMemory(SectionVa, pBuff, packSize);
		//把属性修改回去
		g_api.VirtualProtect(SectionVa, packSize, dwOld, &dwOld);
		g_api.VirtualFree(pBuff, packSize, MEM_DECOMMIT);
		Section++;
	}
}

// tls
void DisposeTLS()
{
	if (ShareData.tlsFuncs[0] == 0)
		return;
	DWORD tlstableRva = GetOptionHeader((char*)g_api.dwImageBase)->DataDirectory[9].VirtualAddress;
	PIMAGE_TLS_DIRECTORY32 ptlsDir = (PIMAGE_TLS_DIRECTORY32)((char*)g_api.dwImageBase + tlstableRva);
	DWORD* tlsCallBacks = (DWORD*)ptlsDir->AddressOfCallBacks;
	int i = 0;
	DWORD reversed;
	while (*tlsCallBacks)
	{
		PIMAGE_TLS_CALLBACK tempFunc = (PIMAGE_TLS_CALLBACK)(ShareData.tlsFuncs[i] - ShareData.nOldOep + (char*)g_api.dwImageBase);
		tempFunc((PVOID)g_api.dwImageBase, DLL_PROCESS_ATTACH, &reversed);
		DWORD OldProtect = 0;
		g_api.VirtualProtect((LPVOID)tlsCallBacks, 4, PAGE_READWRITE, &OldProtect);
		*tlsCallBacks = (DWORD)tempFunc;
		g_api.VirtualProtect((LPVOID)tlsCallBacks, 4, OldProtect, &OldProtect);
		tlsCallBacks++;
		i++;
	}
}

// tls
void CallTls()
{
	// 获取当前程序的加载基址
	DWORD dwBase = (DWORD)g_api.dwImageBase;
	// 获取TLS表
	DWORD dwTls = GetOptionHeader((char*)dwBase)->DataDirectory[9].VirtualAddress;
	if (dwTls != 0)
	{
		PIMAGE_TLS_DIRECTORY pTls = (PIMAGE_TLS_DIRECTORY)(dwTls + dwBase);
		if (pTls->AddressOfCallBacks == 0)
			return;
		DWORD dwTlsCall = *(DWORD*)pTls->AddressOfCallBacks;
		__asm
		{
			cmp dwTlsCall, 0
			je ENDCALL
			push 0
			push 1
			push dwBase
			call dwTlsCall
			ENDCALL :
		}
	}
}

// 简单的tls实现
// 调用TLS表
//void CallTls()
//{
//	DWORD nTlsHeadRva = ShareData.HostTLS.VirtualAddress;
//	if (nTlsHeadRva == 0)return;
//
//	PIMAGE_TLS_DIRECTORY pTlsTab = (PIMAGE_TLS_DIRECTORY)(nTlsHeadRva + g_api.dwImageBase);
//
//	if (pTlsTab->AddressOfCallBacks == 0)return;
//
//	PIMAGE_TLS_CALLBACK* pTLSFun = (PIMAGE_TLS_CALLBACK*)pTlsTab->AddressOfCallBacks;
//	//模拟调用
//	while (*pTLSFun) {
//		(*pTLSFun)((PVOID)g_api.dwImageBase, DLL_PROCESS_ATTACH, NULL);
//		(*pTLSFun)((PVOID)g_api.dwImageBase, DLL_THREAD_ATTACH, NULL);
//
//		pTLSFun++;
//	}
//}

// WndProc回调函数
LRESULT	CALLBACK MyWndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
	switch (msg)
	{ 
	case WM_CREATE:
	{
		g_api.info[0].hWnd = g_api.CreateWindowExW(NULL,
			TEXT("edit"),TEXT("Demons"), WS_CHILD | WS_VISIBLE | WS_BORDER,
			60, 40, 180, 20, hWnd, (HMENU)0x1001, NULL, NULL);

		g_api.info[1].hWnd = g_api.CreateWindowExW(NULL, TEXT("button"),
			TEXT("确认"), WS_CHILD | WS_VISIBLE, 100, 80, 80, 30, hWnd,
			(HMENU)0x1002, NULL, NULL);
		g_api.dwIsTrue = false;
		break;
	}
	case WM_COMMAND:
	{
		WORD wHigh = HIWORD(wParam);
		WORD wLow = LOWORD(wParam);
		switch (wLow)
		{
		case 0x1002:
		{
			char szBuf[MAX_PATH] = { 0 };
			MyMemset(szBuf, MAX_PATH);
			g_api.GetWindowTextA(g_api.info[0].hWnd, szBuf, MAX_PATH);
			if (MyStrlen(szBuf) == 0)
				break;

			if (MyStrcmp(szBuf, "Demons") == 0)
			{
				g_api.dwIsTrue = true;
				g_api.SendMessageW(hWnd, WM_CLOSE, NULL, NULL);
			}
			else
			{
				g_api.ExitProcess(0);
			}
			break;
		}
		default:
			break;
		}
	}
	break;
	case WM_CLOSE:
	{
		if (g_api.dwIsTrue)
			g_api.PostQuitMessage(0);
		else
			g_api.ExitProcess(1);
	}
	default:
		break;
	}
	return g_api.DefWindowProcW(hWnd, msg, wParam, lParam);
}

// 弹框
void AlertPasswordBox()
{
	// 注册窗口类
	WNDCLASSEX wnd;
	wnd.cbSize = sizeof(WNDCLASSEX);
	wnd.hInstance = (HINSTANCE)g_api.dwImageBase;
	wnd.cbWndExtra = wnd.cbClsExtra = NULL;
	wnd.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
	wnd.hIcon = NULL;
	wnd.hIconSm = NULL;
	wnd.hCursor = NULL;
	wnd.style = CS_VREDRAW | CS_HREDRAW;
	wnd.lpszMenuName = NULL;
	wnd.lpfnWndProc = MyWndProc;
	wnd.lpszClassName = TEXT("Demons");
	g_api.RegisterClassExW(&wnd);

	// 创建窗口
	g_api.hParent = g_api.CreateWindowExW(0, TEXT("Demons"), TEXT("请输入密码"),
		WS_CAPTION | WS_BORDER | WS_OVERLAPPEDWINDOW,
		300, 200, 400, 180,
		NULL, NULL, (HINSTANCE)g_api.dwImageBase, NULL);

	// 更新窗口
	g_api.ShowWindow(g_api.hParent, SW_SHOW);
	g_api.UpdateWindow(g_api.hParent);

	// 消息处理
	MSG msg = { 0 };
	while (g_api.GetMessageW(&msg,NULL,NULL,NULL) != 0)
	{
		g_api.TranslateMessage(&msg);
		g_api.DispatchMessageW(&msg);
	}
}

// 当程序被调试的时候，BeingDebugged字段保存的是1
bool CheckBeingDebugged()
{
	bool bDebugged = false;
	__asm
	{
		mov eax, dword ptr fs : [0x30]
		mov al, byte ptr ds : [eax + 0x02]
		mov bDebugged, al
	}
	return bDebugged;
}

// 如果当前的进程被调试，保存的就是0x70
bool CheckNtGlobalFlag()
{
	int nNtGlobalFlag = 0;
	__asm
	{
		mov eax, dword ptr fs : [0x30]
		mov eax, dword ptr[eax + 0x68]		// 通过 PEB 偏移为 0x68的地方找到NtGlobalFlag
		mov nNtGlobalFlag, eax
	}
	return nNtGlobalFlag == 0x70 ? true : false;
}
         
// _HEAP 结构不是一个公开的结构体，不同版本的NT内核可能对
// 这个结构体有不同的实现，兼容性不强
bool CheckProcessHeap()
{
	int nFlags = 0;
	int nProcFlags = 0;
	__asm
	{
		mov eax, dword ptr fs : [0x30]
		mov eax, dword ptr[eax + 0x18]		// 找到 ProcessHeap
		mov ecx, dword ptr[eax + 0x40]		// 偏移为0x40 和 0x44
		mov nFlags, ecx
		mov ecx, dword ptr[eax + 0x44]
		mov nProcFlags, ecx
	}
	return nFlags != 2 || nProcFlags != 0;
}

// 反调试
void AntiDebug()
{
	if (CheckBeingDebugged())
	{
		g_api.ExitProcess(0);
	}
	else if (CheckNtGlobalFlag())
	{
		g_api.ExitProcess(0);
	}
	else if (CheckProcessHeap())
	{
		g_api.ExitProcess(0);
	}
}

extern "C" __declspec(dllexport) __declspec(naked) 
void Start()
{
	__FLOWER_DEMONS4(g_disp, InitApi, 0x3323, __FLOWER_DEMONS3(0x983a, __FLOWER_DEMONS2));
	InitApi();				// 初始化API
	AntiDebug();			// 反调试
	DecryptCpuId();			// 解密CPUID
	//cpuId();				// 获取拿到被加壳程序的CPUID
	//DecompressCode();		// 解压缩
	AlertPasswordBox();		// 密码弹框
	Decrypt();				// 解密
	RecoverDataDir();		// 恢复数据目录表
	FixRelocation(ShareData.RelocRva);	// 修复重定位
	//DisposeTLS();			// tls
	FixIat();				// 修复IAT
	DecryIat();				// 加密IAT
	// CallTls();				// tls
	__asm
	{
		mov eax, fs: [0x30]
		mov eax, [eax + 0x08]
		add eax, ShareData.nOldOep
		jmp eax
	}
}