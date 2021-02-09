
// DemonsPackDlg.h: 头文件
//

#pragma once
#include "Pe.h"
#include "Options.h"
#include "Pack.h"
#include <afxpriv.h>

// CDemonsPackDlg 对话框
class CDemonsPackDlg : public CDialogEx
{
// 构造
public:
	CDemonsPackDlg(CWnd* pParent = nullptr);	// 标准构造函数
	void CreateMenu();							// 创建菜单
	void OutputFile();							// 输入文件
	void WCharToMByte(LPCWSTR lpcwStr, LPSTR lpsStr, DWORD dwSize);	// 转换
	void ObtainFilePath(HDROP hDropInfo);	//获得文件路径

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_DEMONSPACK_DIALOG };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持


// 实现
protected:
	HICON m_hIcon;

	// 生成的消息映射函数
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()

private:
	CMenu		m_mMenu;
	CEdit		m_editInput;
	CEdit		m_editOutput;
	TCHAR		m_tcFileFullPath[MAX_PATH] = { 0 };
	bool		m_boolInput = false;
	bool		m_boolOutput = false;
	Pe			m_pe;
	Pack		m_pack;
	Options*	m_opt = NULL;

public:
	virtual BOOL PreTranslateMessage(MSG* pMsg);
	virtual void OnOK();
	afx_msg void StartPack();							// 开始加壳
	afx_msg void OnDropFiles(HDROP hDropInfo);			// 打开文件
	afx_msg void OnOptions();							// 打开选项
	afx_msg void GetCPUID();							// 获取CPUID
};
