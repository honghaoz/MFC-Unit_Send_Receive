////////////////////////////////////////////////////////////////////////
//�ļ���  :MULTICOLORPLOT.H
//�ؼ�˵��:ʵʱ������ʾ���ܿؼ�,�ṩLINE��BAR����������ʾ����
//����:    �ݸ�
//�������:2007-01-17
//��Ȩ    :��������ʹ�ô���
///////////////////////////////////////////////////////////////////////
#if !defined(AFX_MULTICOLORPLOTCTRL_H__C85858A7_972C_4A59_812D_6D77BAD88697__INCLUDED_)
#define AFX_MULTICOLORPLOTCTRL_H__C85858A7_972C_4A59_812D_6D77BAD88697__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000
// MultiColorPlotCtrl.h : header file
//
//---------------------------------user define head files
#include "afxwin.h"
#include <math.h>
#include "MemDC.h"

#define BAR 0
#define LINE 1

#define GRID_TIMER 1
//����ˢ������
#define GRID_UPDATE_SPEED 50  

typedef struct tagData_Point
{
	float fx ;
	float fy ;
} DATA_POINT ;

/////////////////////////////////////////////////////////////////////////////
// CMultiColorPlotCtrl window

class CMultiColorPlotCtrl : public CStatic
{
// Construction
public:
	CMultiColorPlotCtrl();
private: // ��������
	
	CBitmap *m_pBitmapOldBackground ;
	CBitmap m_pBitmapBackground ;
	CDC m_dcBackground;
	
	int nPlotType ; // ��������  BAR �� LINE // BAR 
	// ����X�����ϵļ��
	int nGridResolutionX ; // 10
	// ����Y�����ϵļ��
	int nGridResolutionY ; // 10
	// ����������ٶȺͷ�����ֵΪ�������ҹ����ʹ��ϵ��£�����֮��0������
	int nGridScrollSpeedX ; // -1
	int nGridScrollSpeedY ; // 0
	// ���ݵ�ֱ��ʴ�С������һ�����ݵ�ռ�ݵ���������
	int nPlotGranulatrity ; // 2
	// �����߿��
	int nGridLineWidth ; // 1
	// ����ɫ
	COLORREF m_clrDarkBack ; // RGB(0,0,75)
	// ǰ��ɫ
	COLORREF m_clrDarkLine ; // RGB(32,64,32)
	// �ؼ�����
	CRect m_rectCtrl;
	// �ؼ��ĳߴ�
	CSize m_Size ;
	// �ؼ������ɿɼ������ݵ���
	int nPlotData ; // 0
	// ʵ������
	float * pfData ; // 0
	// ���ݷ�Χ
	float fLow , fHigh ; // 0,0
	// ���ݱ���
	float fScaleY ; // 1.0
	// ���ݵ㴦����ɫ
	COLORREF m_clrCyanData ; // RGB ( 0,255,255 )
	// ����
	CPen m_GridPen ;
	// ���ݵ�λͼ��ˢ
	CBrush m_clrBrush ;
	// ����ʼλ��
	int nGridStarPosX , nGridStarPosY ; // 0,0
	// ������ʾ��Χ
	bool bLock ; // true---����
	// �ؼ�����ʾ������
	CFont m_SmallFont ;
	// Y��̶ȵ���ɫ
	COLORREF m_clrAxisScaleY ; // RGB ( 0,255,255 )
	// �Ƿ���ʾY��̶�����
	int nShowFormatDataText ; // 0---����ʾ
	// �ؼ�����
	TCHAR szTitls [MAX_PATH * sizeof ( TCHAR ) + 1] ; // NULL
	// ���ߵ�λ
	TCHAR szUints [32 * sizeof ( TCHAR ) + 1] ; // NULL
	
	// LINE����
	// ������ɫ
	COLORREF m_clrLinePen ; // RGB(0,255,0)
	// ���߿��
	int nLineWidth ; 
	
	// BAR��ɫ
	COLORREF m_clrUp ;
	COLORREF m_clrDown ;
	
	DATA_POINT * g_DataPoint ;
	
private:
	// �ؼ�����
	CRITICAL_SECTION g_cs ;

// Attributes
public:

// Operations
public:

// Overrides
	// ClassWizard generated virtual function overrides
	//{{AFX_VIRTUAL(CMultiColorPlotCtrl)
	protected:
	virtual void PreSubclassWindow();
	//}}AFX_VIRTUAL

// Implementation
public:
	void SetLineColorWidth ( COLORREF clrLine = RGB ( 0 , 255 , 0 ) , int nWidth = 1 );
	void SetBarColor ( COLORREF clrUp , COLORREF clrDown , bool bfRfastness = false , bool bfGfastness = false , bool bfBfastness = false );
	void ShowTitle ( int nShow = 1 );
	void SetUnit ( LPCTSTR pctUint = NULL );
	void SetTitle ( LPCTSTR pctTitle = NULL );
	void SetAxisScaleClrY ( COLORREF clr = RGB ( 0 , 255 , 255 ) );
	void SetLinePen ( int nWidth , COLORREF clr );
	void SetRang ( float fL , float fH );
	void SetGridLineClr ( COLORREF clr );
	BOOL SetPlotGranulatrity ( int nPlotGrltiy );
	void SetPlotType ( int nType );

	virtual ~CMultiColorPlotCtrl();

	// Generated message map functions
protected:
	//{{AFX_MSG(CMultiColorPlotCtrl)
	afx_msg void OnPaint();
	//}}AFX_MSG

	DECLARE_MESSAGE_MAP()
public:
	afx_msg BOOL OnEraseBkgnd(CDC* pDC);
	void ReconstructControl(void);
protected:
	void InitColorPlot(CDC *pDC);
private:
	void DrawBackGroundGrid(CDC * pDC);
protected:
	void DrawValue(CDC * pDC);
	void DrawAxisScaleYValue(CDC * pDC);
public:
	afx_msg void OnTimer(UINT nIDEvent);
	// ����������
	void SetGridResolutionX(int nGridReluX);
	// ����������
	void SetGridResolutionY(int nGridReluY);
	// ������������ٶ�,��ֵΪ�������ҹ���,0����
	void SetGridScrollSpeedX(int nSpeedX);
	// ��ֵΪ���ϵ��¹���,0����
	void SetGridScrollSpeedY(int nSpeedY);
	// �����߿��
	void SetGridLineWidth(int nWidth);
	// ����ɫ
	void SetGridBackClr(COLORREF clr);
	// // ����������ʾ��Χ
	void LockRang(bool bfLock = true);
	// ����������ʾ��Χ
	void LockRang(float fMin, float fMax);
	// ��������
	void SetData(float fData);
	// ������ɫ
	void SetLineColor(COLORREF clrLine = RGB ( 0 , 255 , 0 ));
	void SetLineWidth(int nWidth = 1);
	const COLORREF GetLineColor(void);
	const int GetLineWidth(void); 
};

/////////////////////////////////////////////////////////////////////////////

//{{AFX_INSERT_LOCATION}}
// Microsoft Visual C++ will insert additional declarations immediately before the previous line.

#endif // !defined(AFX_MULTICOLORPLOTCTRL_H__C85858A7_972C_4A59_812D_6D77BAD88697__INCLUDED_)
