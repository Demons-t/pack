#pragma once

//区段信息
struct mSize
{
	DWORD oldSectionSize;
};

// 在加壳器和壳代码之间传递数据
typedef struct _SHAREDATA
{
	// 保存原始程序的OEP
	int nOldOep;
	DWORD dwSrcOep;			// 入口点

	DWORD dwTextScnRVA;		// 代码段RVA
	DWORD dwTextScnSize;	// 代码段大小
	DWORD dwKey;			// 解密密钥

	DWORD dwStartRVA;		// 起始虚拟地址
	DWORD dwEndRVA;			// 结束虚拟地址

	DWORD dwDataDir[20][2];	// 数据目录表的RVA和size
	DWORD dwNumOfDataDir;	// 数据目录表的个数

	char pCpuId[50];
	char pOldCpuId[50];		// 保存自己的CPUID
	DWORD dwCpuSize;		// 保存大小
	DWORD dwCpuKey;			// 保存CPU 的 key
	DWORD RelocRva;
	//区段原始大小
	mSize oldSize[10];

	DWORD tlsFuncs[MAX_PATH];	// tls
	IMAGE_DATA_DIRECTORY HostTLS;
}SHAREDATA, *PSHAREDATA;

struct TypeOffset
{
	WORD wOffset : 12;
	WORD wType : 4;
};

class Pe
{
public:
	Pe();																			// 构造
	bool					OpenPeFile(LPCSTR lpPath);								// 打开PE文件

	void					OpenDllFile(LPCSTR lpPath, LPCSTR lpSectionName);		// 打开 DLL 文件

	char*					GetFileData(LPCSTR lpPath, int* nFileSize);				// 获取文件内容和大小

	HANDLE					GetPeFile(LPCSTR lpPath);								// 创建文件

	PIMAGE_DOS_HEADER		GetDosHeader(DWORD dwModuleBase);						// 获取DOS头

	PIMAGE_NT_HEADERS		GetNtHeaders(DWORD dwModuleBase);						// 获取NT头

	PIMAGE_FILE_HEADER		GetFileHeader(DWORD dwModuleBase);						// 获取文件头

	PIMAGE_OPTIONAL_HEADER	GetOptionalHeader(DWORD dwModuleBase);					// 获取扩展头

	PIMAGE_DATA_DIRECTORY	GetDataDirectory(int nIndex, DWORD dwModuleBase);		// 获取数据目录表

	PIMAGE_SECTION_HEADER	GetSectionHeader(DWORD dwModuleBase);					// 获取区段头表

	PIMAGE_SECTION_HEADER	GetSection(DWORD dwBase, LPCSTR lpSectionName);			// 从指定模块中找到对应名称的区段

	DWORD					GetFileBase();											// 获取文件基址

	DWORD					GetDllBase();											// 获取dll基址

	PSHAREDATA				GetShareData();											// 获取结构体

	DWORD					RvaToOffset(PIMAGE_NT_HEADERS32 pNtHead, DWORD dwRva);	// Rva 转 Offset

	DWORD					Alignment(DWORD dwAddress, DWORD dwAlgn);				// 计算对齐后的大小

	void					CopySection(LPCSTR lpDestName, LPCSTR lpSrcName);		// 将Dll中的指定区段拷贝到被加壳程序中

	void					CopySectionData(LPCSTR lpDestName, LPCSTR lpSrcName);	// 将 DLL 中的指定区段的内容拷贝到被加壳程序中

	void					AddSection(LPCSTR lpSectionName, UINT uSectionSize);	// 为目标PE文件添加一个指定大小的指定区段

	void					SetOep(LPCSTR lpSectionName);							// 设置新的OEP，修改的是被加壳程序

	void					FixReloc(LPCSTR lpDestName, LPCSTR lpSrcName);			// 修复重定位

	void					AddRelocSection();										// 修复重定位

	void					SavePeFile(LPCSTR lpPath);								// 将修改后的文件保存到指定的路径中

private:
	// 保存文件的基本属性
	DWORD	m_dwFileSize ;
	DWORD	m_dwFileBase ;

	// 保存dll加载基址的变量
	DWORD	m_dwDllBase = 0;
	DWORD	m_dwStart = 0;

	PSHAREDATA  m_shareData;
};

