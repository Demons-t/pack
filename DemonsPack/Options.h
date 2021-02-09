#pragma once


// Options 对话框

class Options : public CDialogEx
{
	DECLARE_DYNAMIC(Options)

public:
	Options(CWnd* pParent = nullptr);   // 标准构造函数
	virtual ~Options();

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_SET };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

	DECLARE_MESSAGE_MAP()

private:
	CButton m_checkIat;
	CButton m_checkData;
	CButton m_checkAnti;
public:
	virtual BOOL OnInitDialog();
	virtual void OnOK();
	virtual BOOL PreTranslateMessage(MSG* pMsg);
};
