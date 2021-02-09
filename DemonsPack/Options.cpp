// Options.cpp: 实现文件
//

#include "pch.h"
#include "DemonsPack.h"
#include "Options.h"
#include "afxdialogex.h"


// Options 对话框

IMPLEMENT_DYNAMIC(Options, CDialogEx)

Options::Options(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_SET, pParent)
{

}

Options::~Options()
{
}

void Options::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_CHECK1, m_checkIat);
	DDX_Control(pDX, IDC_CHECK2, m_checkData);
	DDX_Control(pDX, IDC_CHECK3, m_checkAnti);
}


BEGIN_MESSAGE_MAP(Options, CDialogEx)
END_MESSAGE_MAP()


// Options 消息处理程序


BOOL Options::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// TODO:  在此添加额外的初始化
	((CButton*)GetDlgItem(IDC_CHECK1))->SetCheck(BST_CHECKED);
	((CButton*)GetDlgItem(IDC_CHECK2))->SetCheck(BST_CHECKED);
	((CButton*)GetDlgItem(IDC_CHECK3))->SetCheck(BST_CHECKED);

	return TRUE;  // return TRUE unless you set the focus to a control
				  // 异常: OCX 属性页应返回 FALSE
}


void Options::OnOK()
{
	// TODO: 在此添加专用代码和/或调用基类

	//CDialogEx::OnOK();
}


BOOL Options::PreTranslateMessage(MSG* pMsg)
{
	// TODO: 在此添加专用代码和/或调用基类
	if (pMsg->message == WM_KEYDOWN && pMsg->wParam == VK_ESCAPE)
	{
		return TRUE;
	}

	return CDialogEx::PreTranslateMessage(pMsg);
}
