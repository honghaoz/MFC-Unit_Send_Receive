// Receive1.h : main header file for the RECEIVE1 application
//

#if !defined(AFX_RECEIVE1_H__02AEB669_D77A_4476_B888_2B9356F66FF4__INCLUDED_)
#define AFX_RECEIVE1_H__02AEB669_D77A_4476_B888_2B9356F66FF4__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#ifndef __AFXWIN_H__
	#error include 'stdafx.h' before including this file for PCH
#endif

#include "resource.h"		// main symbols

/////////////////////////////////////////////////////////////////////////////
// CReceive1App:
// See Receive1.cpp for the implementation of this class
//

class CReceive1App : public CWinApp
{
public:
	CReceive1App();

// Overrides
	// ClassWizard generated virtual function overrides
	//{{AFX_VIRTUAL(CReceive1App)
	public:
	virtual BOOL InitInstance();
	//}}AFX_VIRTUAL

// Implementation

	//{{AFX_MSG(CReceive1App)
		// NOTE - the ClassWizard will add and remove member functions here.
		//    DO NOT EDIT what you see in these blocks of generated code !
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()
};


/////////////////////////////////////////////////////////////////////////////

//{{AFX_INSERT_LOCATION}}
// Microsoft Visual C++ will insert additional declarations immediately before the previous line.

#endif // !defined(AFX_RECEIVE1_H__02AEB669_D77A_4476_B888_2B9356F66FF4__INCLUDED_)
