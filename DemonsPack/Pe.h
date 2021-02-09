#pragma once

//������Ϣ
struct mSize
{
	DWORD oldSectionSize;
};

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

struct TypeOffset
{
	WORD wOffset : 12;
	WORD wType : 4;
};

class Pe
{
public:
	Pe();																			// ����
	bool					OpenPeFile(LPCSTR lpPath);								// ��PE�ļ�

	void					OpenDllFile(LPCSTR lpPath, LPCSTR lpSectionName);		// �� DLL �ļ�

	char*					GetFileData(LPCSTR lpPath, int* nFileSize);				// ��ȡ�ļ����ݺʹ�С

	HANDLE					GetPeFile(LPCSTR lpPath);								// �����ļ�

	PIMAGE_DOS_HEADER		GetDosHeader(DWORD dwModuleBase);						// ��ȡDOSͷ

	PIMAGE_NT_HEADERS		GetNtHeaders(DWORD dwModuleBase);						// ��ȡNTͷ

	PIMAGE_FILE_HEADER		GetFileHeader(DWORD dwModuleBase);						// ��ȡ�ļ�ͷ

	PIMAGE_OPTIONAL_HEADER	GetOptionalHeader(DWORD dwModuleBase);					// ��ȡ��չͷ

	PIMAGE_DATA_DIRECTORY	GetDataDirectory(int nIndex, DWORD dwModuleBase);		// ��ȡ����Ŀ¼��

	PIMAGE_SECTION_HEADER	GetSectionHeader(DWORD dwModuleBase);					// ��ȡ����ͷ��

	PIMAGE_SECTION_HEADER	GetSection(DWORD dwBase, LPCSTR lpSectionName);			// ��ָ��ģ�����ҵ���Ӧ���Ƶ�����

	DWORD					GetFileBase();											// ��ȡ�ļ���ַ

	DWORD					GetDllBase();											// ��ȡdll��ַ

	PSHAREDATA				GetShareData();											// ��ȡ�ṹ��

	DWORD					RvaToOffset(PIMAGE_NT_HEADERS32 pNtHead, DWORD dwRva);	// Rva ת Offset

	DWORD					Alignment(DWORD dwAddress, DWORD dwAlgn);				// ��������Ĵ�С

	void					CopySection(LPCSTR lpDestName, LPCSTR lpSrcName);		// ��Dll�е�ָ�����ο��������ӿǳ�����

	void					CopySectionData(LPCSTR lpDestName, LPCSTR lpSrcName);	// �� DLL �е�ָ�����ε����ݿ��������ӿǳ�����

	void					AddSection(LPCSTR lpSectionName, UINT uSectionSize);	// ΪĿ��PE�ļ����һ��ָ����С��ָ������

	void					SetOep(LPCSTR lpSectionName);							// �����µ�OEP���޸ĵ��Ǳ��ӿǳ���

	void					FixReloc(LPCSTR lpDestName, LPCSTR lpSrcName);			// �޸��ض�λ

	void					AddRelocSection();										// �޸��ض�λ

	void					SavePeFile(LPCSTR lpPath);								// ���޸ĺ���ļ����浽ָ����·����

private:
	// �����ļ��Ļ�������
	DWORD	m_dwFileSize ;
	DWORD	m_dwFileBase ;

	// ����dll���ػ�ַ�ı���
	DWORD	m_dwDllBase = 0;
	DWORD	m_dwStart = 0;

	PSHAREDATA  m_shareData;
};

