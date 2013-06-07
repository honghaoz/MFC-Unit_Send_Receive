// Send1Dlg.h : header file
//

#if !defined(AFX_SEND1DLG_H__6DEE1272_6098_4EF8_95BB_A02371A5D065__INCLUDED_)
#define AFX_SEND1DLG_H__6DEE1272_6098_4EF8_95BB_A02371A5D065__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000



#include "MultiColorPlotCtrl.h"
// 产生随机数
#define GetRandom( min, max ) ((rand() % (int)(((max)+1) - (min))) + (min))

/////////////////////////////////////////////////////////////////////////////
// CSend1Dlg dialog

class CSend1Dlg : public CDialog
{
// Construction
public:
	void add_amp();
	void add_harm();
	void ShowWave();
	void SetSin(float A,float B,float C,int PhaseA,float D,float E,float F,int PhaseD);
// 	void packet_ini();
	void ShowDesMacAddress();
	void GetMacAddress();
	CSend1Dlg(CWnd* pParent = NULL);	// standard constructor
	friend DWORD WINAPI ThreadFunc_Timer(LPVOID lpParam);
	friend DWORD WINAPI ThreadFunc_Send(LPVOID lpParam);
	friend UINT ThreadFunc(LPVOID lpParam); 

// Dialog Data
	//{{AFX_DATA(CSend1Dlg)
	enum { IDD = IDD_SEND1_DIALOG };
	CEdit	m_right;
	CEdit	m_left;
	CSliderCtrl	m_slider_f;
	CEdit	m_freqdrift_i;
	CEdit	m_harm_i;
	CEdit	m_add_i;
	CEdit	m_smprate;
	CEdit	m_smpcount;
	CComboBox	m_harmList;
	CComboBox	m_freqList;
	CComboBox	m_addList;
	CEdit	m_freq;
	CEdit	m_harm_amp;
	CEdit	m_harm_n;
	CEdit	m_add_freq;
	CEdit	m_add_amp;
	CEdit	m_fault_period;
	CButton	m_fault_k3;
	CButton	m_fc;
	CButton	m_fb;
	CButton	m_fa;
	CEdit	m_am_Vn;
	CEdit	m_am_An;
	CEdit	m_phaseC_drift;
	CEdit	m_phaseB_drift;
	CEdit	m_phaseA_drift;
	CSliderCtrl	m_slider_v;
	CSliderCtrl	m_slider_a;
	CButton	m_radio_Vabc;
	CMultiColorPlotCtrl	m_voltage_c;
	CMultiColorPlotCtrl	m_voltage_b;
	CMultiColorPlotCtrl	m_voltage_abc;
	CMultiColorPlotCtrl	m_voltage_a;
	CProgressCtrl	m_progress;
	CButton	m_check_src;
	CEdit	m_am_Vc;
	CEdit	m_am_Vb;
	CEdit	m_am_Va;
	CMultiColorPlotCtrl	m_current_abc;
	CButton	m_radio_Aabc;
	CMultiColorPlotCtrl	m_current_c;
	CMultiColorPlotCtrl	m_current_b;
	CEdit	m_am_Ac;
	CEdit	m_am_Ab;
	CEdit	m_am_Aa;
	CMultiColorPlotCtrl	m_current_a;
	CEdit	m_soumac;
	CEdit	m_desmac;
	CComboBox	m_adapter;
	//}}AFX_DATA

	// ClassWizard generated virtual function overrides
	//{{AFX_VIRTUAL(CSend1Dlg)
	public:
	virtual BOOL DestroyWindow();
	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV support
	//}}AFX_VIRTUAL

// Implementation
protected:
	HICON m_hIcon;
	HANDLE hThread_send;//线程的句柄
	DWORD ThreadID_send;//线程的ID
	HANDLE hThread_timer;//线程的句柄
	DWORD ThreadID_timer;//线程的ID
	CWinThread* pThread;

	// Generated message map functions
	//{{AFX_MSG(CSend1Dlg)
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	afx_msg void OnSend();
	afx_msg void OnDropdownAdapterList();
	afx_msg void OnSelchangeAdapterList();
	afx_msg void OnStop();
	afx_msg void OnChangeEdit13();
	afx_msg void OnTimer(UINT nIDEvent);
	afx_msg void OnChangeEdit1_am_Aa();
	afx_msg void OnChangeEdit2_am_Ab();
	afx_msg void OnChangeEdit3_am_Ac();
	afx_msg void OnRadio_Aabc();
	afx_msg void OnRadio_Aa();
	afx_msg void OnRadio_Ab();
	afx_msg void OnRadio_Ac();
	afx_msg void OnCheck1_ChangeSrcMac();
	afx_msg void OnChangeEDITsoumac();
	afx_msg void OnRadio_Ashut();
	afx_msg void OnChangeEdit4_am_Va();
	afx_msg void OnChangeEdit5_am_Vb();
	afx_msg void OnChangeEdit6_am_Vc();
	afx_msg void OnRadio_Vabc();
	afx_msg void OnRadio_Va();
	afx_msg void OnRadio_Vb();
	afx_msg void OnRadio_Vc();
	afx_msg void OnRadio_Vshut();
	afx_msg void OnCustomdrawSliderA(NMHDR* pNMHDR, LRESULT* pResult);
	afx_msg void OnCustomdrawSliderV(NMHDR* pNMHDR, LRESULT* pResult);
	afx_msg void OnChangeEdit9_driftA();
	afx_msg void OnChangeEdit10_driftB();
	afx_msg void OnChangeEdit11_driftC();
	afx_msg void OnRADIOk3();
	afx_msg void OnRADIOk1();
	afx_msg void OnRADIOk2();
	afx_msg void OnRADIOk11();
	afx_msg void OnRADIOd1();
	afx_msg void OnRADIOd2();
	afx_msg void OnCHECKfa();
	afx_msg void OnCHECKfb();
	afx_msg void OnCHECKfc();
	afx_msg void OnBUTTONfaulton();
	afx_msg void OnBUTTONfaultoff();
	afx_msg void OnButton_add_plus();
	afx_msg void OnButton_add_minus();
	afx_msg void OnButton_harm_plus();
	afx_msg void OnButton_harm_minus();
	afx_msg void OnDropdownCOMBOadd();
	afx_msg void OnDropdownCOMBOfreq();
	afx_msg void OnDropdownCOMBOharm();
	afx_msg void OnSelchangeCOMBOadd();
	afx_msg void OnSelchangeCOMBOfreq();
	afx_msg void OnSelchangeCOMBOharm();
	afx_msg void OnChangeEDITsmprate();
	afx_msg void OnButton_freqdrift();
	afx_msg void OnButton_about();
	afx_msg void OnButton_Save();
	afx_msg void OnCustomdrawSLIDERfault(NMHDR* pNMHDR, LRESULT* pResult);
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()
};

//{{AFX_INSERT_LOCATION}}
// Microsoft Visual C++ will insert additional declarations immediately before the previous line.

#endif // !defined(AFX_SEND1DLG_H__6DEE1272_6098_4EF8_95BB_A02371A5D065__INCLUDED_)
