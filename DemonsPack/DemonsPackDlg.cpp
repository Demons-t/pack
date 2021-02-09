
// DemonsPackDlg.cpp: 实现文件
//

#include "pch.h"
#include "framework.h"
#include "DemonsPack.h"
#include "DemonsPackDlg.h"
#include "afxdialogex.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// 用于应用程序“关于”菜单项的 CAboutDlg 对话框

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

// 实现
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(IDD_ABOUTBOX)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// CDemonsPackDlg 对话框



CDemonsPackDlg::CDemonsPackDlg(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_DEMONSPACK_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CDemonsPackDlg::CreateMenu()
{
	m_mMenu.LoadMenu(IDR_MENU1);
	SetMenu(&m_mMenu);
}

void CDemonsPackDlg::OutputFile()
{

}

void CDemonsPackDlg::WCharToMByte(LPCWSTR lpcwStr, LPSTR lpsStr, DWORD dwSize)
{
	DWORD dwMinSize;
	dwMinSize = WideCharToMultiByte(CP_OEMCP, NULL, lpcwStr, -1, NULL, 0, NULL, FALSE);
	if (dwSize < dwMinSize)
	{
		return;
	}
	WideCharToMultiByte(CP_OEMCP, NULL, lpcwStr, -1, lpsStr, dwSize, NULL, FALSE);
}

void CDemonsPackDlg::ObtainFilePath(HDROP hDropInfo)
{
	char* pBuff = (char*)malloc(MAX_PATH);
	DragQueryFile(hDropInfo, 0, m_tcFileFullPath, MAX_PATH);
	m_editInput.SetWindowTextW(m_tcFileFullPath);
	WCharToMByte(m_tcFileFullPath, pBuff, MAX_PATH);
	m_pe.OpenPeFile(pBuff);
	DragFinish(hDropInfo);
	free(pBuff);
}

void CDemonsPackDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_INPUTFILE, m_editInput);
	DDX_Control(pDX, IDC_OUTPUTFILE, m_editOutput);
}

BEGIN_MESSAGE_MAP(CDemonsPackDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_STARTPACK, &CDemonsPackDlg::StartPack)
	ON_WM_DROPFILES()
	ON_COMMAND(ID_SET, &CDemonsPackDlg::OnOptions)
	ON_BN_CLICKED(IDC_STARTPACK2, &CDemonsPackDlg::GetCPUID)
END_MESSAGE_MAP()


// CDemonsPackDlg 消息处理程序

BOOL CDemonsPackDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 将“关于...”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != nullptr)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// 设置此对话框的图标。  当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	// TODO: 在此添加额外的初始化代码
	//m_objTab = new CTabCtrl;
	CreateMenu();

	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

void CDemonsPackDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。  对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CDemonsPackDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR CDemonsPackDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}

BOOL CDemonsPackDlg::PreTranslateMessage(MSG* pMsg)
{
	// TODO: 在此添加专用代码和/或调用基类
	if (pMsg->message == WM_KEYDOWN && pMsg->wParam == VK_ESCAPE)
	{
		return TRUE;
	}

	return CDialogEx::PreTranslateMessage(pMsg);
}


void CDemonsPackDlg::OnOK()
{
	// TODO: 在此添加专用代码和/或调用基类

	// CDialogEx::OnOK();
}


// 开始加壳
void CDemonsPackDlg::StartPack()
{
	// TODO: 在此添加控件通知处理程序代码
	char* szPass;
	CString strOut;
	m_editOutput.GetWindowTextW(strOut);
	USES_CONVERSION;
	szPass = T2A(strOut);
	DWORD dwSize = strlen(szPass);
	for (DWORD i = 0; i < dwSize; i++)
	{
		m_pe.GetShareData()->pOldCpuId[i] = szPass[i];
	}
	if (m_boolInput == TRUE)
	{
		m_pe.OpenDllFile("Stub.dll", ".text");			// 打开dll文件
		m_pack.EncryptCpuId(szPass);					// 加密cpuid
		m_pack.Encrypt(m_pe.GetFileBase(), ".text");	// 加密代码段
		//m_pack.CompressExe(m_pe.GetFileBase());		// 压缩源文件
		m_pe.CopySection(".demons", ".text");			// 将Dll中的指定区段拷贝到被加壳程序中
		m_pe.SetOep(".demons");							// 设置OEP
		m_pe.FixReloc(".demons", ".text");				// 修复重定位
		//m_pack.DisposeTLS(m_pe.GetFileBase(), m_pe.GetDllBase());	// tls
		m_pe.AddRelocSection();							// 修复重定位
		m_pe.CopySectionData(".demons", ".text");		// 将 DLL 中的指定区段的内容拷贝到被加壳程序中
		m_pe.SavePeFile("demons_pack.exe");				// 保存文件
	}
	else
	{
		MessageBox(_T("请添加文件"), NULL, NULL);
	}
}

void CDemonsPackDlg::OnDropFiles(HDROP hDropInfo)
{
	// TODO: 在此添加消息处理程序代码和/或调用默认值
	ObtainFilePath(hDropInfo);
	m_boolInput = true;

	CDialogEx::OnDropFiles(hDropInfo);
}

void CDemonsPackDlg::OnOptions()
{
	// TODO: 在此添加命令处理程序代码
	m_opt = new Options;
	m_opt->DoModal();
	delete m_opt;
}


void CDemonsPackDlg::GetCPUID()
{
	// TODO: 在此添加控件通知处理程序代码
	// 获取CPUID
	int cpuInfo[4] = { 0 };
	CString strCpu;
	__cpuid(cpuInfo, 1);
	strCpu.Format(_T("%08X%08X%08X%08X"), cpuInfo[0], cpuInfo[1], cpuInfo[2], cpuInfo[3]);
	m_editOutput.SetWindowTextW(strCpu);
}
