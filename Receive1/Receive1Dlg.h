// Receive1Dlg.h : header file
//
#if !defined(AFX_RECEIVE1DLG_H__6C6BC412_6E7B_4B03_A4D5_6C7EC39639CE__INCLUDED_)
#define AFX_RECEIVE1DLG_H__6C6BC412_6E7B_4B03_A4D5_6C7EC39639CE__INCLUDED_
//////////////////////////////



#include "MultiColorPlotCtrl.h"

// 产生随机数
#define GetRandom( min, max ) ((rand() % (int)(((max)+1) - (min))) + (min))

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#define WM_MY_MESSAGE WM_USER + 100
#define WM_MY_MESSAGE1 WM_USER + 101

#define  PI 3.1415926535897932384626433832795028841971

void ThreadFunc();//线程函数，处理抓包
//void ThreadFunc1();
/////////////////////////////////////////////////////////////////////////////
// CReceive1Dlg dialog

class CReceive1Dlg : public CDialog
{
// Construction
public:
	void Calculate();

//////////////////////////////////////////////////////
//////////////////////////////////////////////////////
	void ShowList();
	void ShowWave();
	void GetMacAddress();
	CReceive1Dlg(CWnd* pParent = NULL);	// standard constructor
	CListCtrl	m_list;
	friend void ThreadFunc1(CReceive1Dlg *DlgThis);
// 	struct data2receive
// 	{
// // 		float am_Aa;
// // 		float am_Ab;
// // 		float am_Ac;
// 		float currentA;
// 		float currentB;
// 		float currentC;
// 		
// 		float VoltageA;
// 		float VoltageB;
// 		float VoltageC;
// 	}data_to_receive;

// Dialog Data
	//{{AFX_DATA(CReceive1Dlg)
	enum { IDD = IDD_RECEIVE1_DIALOG };
	CEdit	m_youxiaozhi;
	CEdit	m_smpcount;
	CComboBox	m_harmList;
	CEdit	m_freqDrift;
	CComboBox	m_freqdriftList;
	CEdit	m_unbalance;
	CComboBox	m_unbalanceList;
	CEdit	m_flick_longflick;
	CEdit	m_flick_shortflick;
	CEdit	m_flick_fluctuate;
	CComboBox	m_flickList;
	CEdit	m_skew_skew;
	CEdit	m_skew_youxiaozhi;
	CComboBox	m_skewList;
	CButton	m_harm_analy;
	CEdit	m_harm_total;
	CEdit	m_harm_hru;
	CEdit	m_harm_h;
	CButton	m_listoff;
	CSliderCtrl	m_slider_v;
	CSliderCtrl	m_slider_a;
	CMultiColorPlotCtrl	m_voltage_c;
	CMultiColorPlotCtrl	m_voltage_b;
	CMultiColorPlotCtrl	m_voltage_a;
	CMultiColorPlotCtrl	m_voltage_abc;
	CProgressCtrl	m_progress;
	CEdit	m_fliter_src;
	CButton	m_radio_Aabc;
	CMultiColorPlotCtrl	m_current_abc;
	CMultiColorPlotCtrl	m_current_c;
	CMultiColorPlotCtrl	m_current_b;
	CEdit	m_soumac;
	CMultiColorPlotCtrl	m_current_a;
	CButton	m_radio1;
	CComboBox	m_adapter;
	//}}AFX_DATA

	// ClassWizard generated virtual function overrides
	//{{AFX_VIRTUAL(CReceive1Dlg)
	public:
	virtual BOOL DestroyWindow();
	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV support
	//}}AFX_VIRTUAL

// Implementation
protected:
	HICON m_hIcon;
	HANDLE hThread;//线程的句柄
	DWORD ThreadID;//线程的ID
	// Generated message map functions
	//{{AFX_MSG(CReceive1Dlg)
	afx_msg  void OnMyMessage(WPARAM, LPARAM); //用户添加自定义消息说明
	afx_msg  void OnMyMessage1(WPARAM, LPARAM); //用户添加自定义消息说明
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	afx_msg void OnDropdownAdapterList();
	afx_msg void OnSelchangeAdapterList();
	afx_msg void OnStart();
	afx_msg void OnRadio1();
	afx_msg void OnRadio2();
	afx_msg void OnRadio3();
	afx_msg void OnRadio4();
	afx_msg void OnRadio5();
	afx_msg void OnRadio6();
	afx_msg void OnStop();
	afx_msg void OnButtonClear();
	afx_msg void OnTimer(UINT nIDEvent);
	afx_msg void OnRadio_Aabc();
	afx_msg void OnRadio_Aa();
	afx_msg void OnRadio_Ab();
	afx_msg void OnRadio_Ac();
	afx_msg void OnChangeEDITflitersrc();
	afx_msg void OnRadio_Ashut();
	afx_msg void OnRadio_Vabc();
	afx_msg void OnRadio_Va();
	afx_msg void OnRadio_Vb();
	afx_msg void OnRadio_Vc();
	afx_msg void OnRadio_Vshut();
	afx_msg void OnRADIOliston();
	afx_msg void OnRADIOlistseq();
	afx_msg void OnDropdownCOMBOharm();
	afx_msg void OnDropdownCOMBOskew();
	afx_msg void OnDropdownCOMBOflick();
	afx_msg void OnDropdownCOMBOfreqDriftList();
	afx_msg void OnDropdownCOMBOunbalance();
	afx_msg void OnSelchangeCOMBOflick();
	afx_msg void OnSelchangeCOMBOfreqDriftList();
	afx_msg void OnSelchangeCOMBOharm();
	afx_msg void OnSelchangeCOMBOskew();
	afx_msg void OnSelchangeCOMBOunbalance();
	afx_msg void OnBUTTONharmana();
	afx_msg void OnButtonSkew();
	afx_msg void OnButton_flick();
	afx_msg void OnButton_Unbalance();
	afx_msg void OnButton_freqdrift();
	afx_msg void OnButton_about();
	afx_msg void OnButton_Save();
	afx_msg void OnOutofmemorySliderA(NMHDR* pNMHDR, LRESULT* pResult);
	afx_msg void OnOutofmemorySliderV(NMHDR* pNMHDR, LRESULT* pResult);
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()
};

//{{AFX_INSERT_LOCATION}}
// Microsoft Visual C++ will insert additional declarations immediately before the previous line.

#endif // !defined(AFX_RECEIVE1DLG_H__6C6BC412_6E7B_4B03_A4D5_6C7EC39639CE__INCLUDED_)
