// Send1.h : main header file for the SEND1 application
//

#if !defined(AFX_SEND1_H__061A3F5E_0F49_47D2_B866_DF95F9BA5275__INCLUDED_)
#define AFX_SEND1_H__061A3F5E_0F49_47D2_B866_DF95F9BA5275__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#ifndef __AFXWIN_H__
	#error include 'stdafx.h' before including this file for PCH
#endif

#include "resource.h"		// main symbols

/////////////////////////////////////////////////////////////////////////////
// CSend1App:
// See Send1.cpp for the implementation of this class
//

class CSend1App : public CWinApp
{
public:
	CSend1App();

// Overrides
	// ClassWizard generated virtual function overrides
	//{{AFX_VIRTUAL(CSend1App)
	public:
	virtual BOOL InitInstance();
	//}}AFX_VIRTUAL

// Implementation

	//{{AFX_MSG(CSend1App)
		// NOTE - the ClassWizard will add and remove member functions here.
		//    DO NOT EDIT what you see in these blocks of generated code !
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()
};


/////////////////////////////////////////////////////////////////////////////

//{{AFX_INSERT_LOCATION}}
// Microsoft Visual C++ will insert additional declarations immediately before the previous line.

#endif // !defined(AFX_SEND1_H__061A3F5E_0F49_47D2_B866_DF95F9BA5275__INCLUDED_)
