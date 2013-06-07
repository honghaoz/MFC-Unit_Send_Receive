////////////////////////////////////////////////////////////////////////
//�ļ���  :MULTICOLORPLOT.CPP
//�ؼ�˵��:ʵʱ������ʾ���ܿؼ�,�ṩLINE��BAR����������ʾ����
//����:    �ݸ�
//�������:2007-01-17
//��Ȩ    :��������ʹ�ô���
///////////////////////////////////////////////////////////////////////

// MultiColorPlotCtrl.cpp : implementation file
//

#include "stdafx.h"
#include "Receive1.h"
#include "MultiColorPlotCtrl.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/////////////////////////////////////////////////////////////////////////////
// CMultiColorPlotCtrl

CMultiColorPlotCtrl::CMultiColorPlotCtrl()
	: nPlotType(BAR) 
	, nGridResolutionX(10)
	, nGridResolutionY(10)
	, nGridScrollSpeedX(0)
	, nGridScrollSpeedY(0)
	, nPlotGranulatrity(2)
	, nGridLineWidth(1)
	, m_clrDarkBack(RGB(0,0,75))
	, m_clrDarkLine(RGB(32,64,32))
	, nPlotData(0)
	, pfData(NULL)
	, fLow(0.0)
	, fHigh(100.0)
	, fScaleY(1.0)
	, m_clrCyanData(RGB(0,255,255))
	, nGridStarPosX(0)
	, nGridStarPosY(0)
	, bLock(true)
	, m_clrAxisScaleY(RGB(0,255,255))
	, nShowFormatDataText(0)
	, m_clrLinePen(RGB(0,255,0))
	, nLineWidth(1)
{
	// �ؼ�����
	// ��ʼ���ؼ������ C_S �ṹ
	InitializeCriticalSection ( & g_cs ) ;
	
	// ��ʼ������
	_stprintf ( szTitls , _TEXT ( "%s" ) , _TEXT ( "" ) ) ; 
	// ��ʼ����λ
	_stprintf ( szUints , _TEXT ( "%s" ) , _TEXT ( "" ) ) ;
	

}

CMultiColorPlotCtrl::~CMultiColorPlotCtrl()
{
	if ( pfData )
	{
		delete [] pfData ;
	}
	
	// �ͷŹؼ�����
	DeleteCriticalSection ( & g_cs ) ;

}


BEGIN_MESSAGE_MAP(CMultiColorPlotCtrl, CStatic)
	//{{AFX_MSG_MAP(CMultiColorPlotCtrl)
	ON_WM_PAINT()
	//}}AFX_MSG_MAP
	ON_WM_ERASEBKGND()
	ON_WM_TIMER()
END_MESSAGE_MAP()

/////////////////////////////////////////////////////////////////////////////
// CMultiColorPlotCtrl message handlers
void CMultiColorPlotCtrl::OnPaint() 
{
	CPaintDC dc(this); // device context for painting
	
	// TODO: Add your message handler code here
	// ��ÿؼ�����
	GetClientRect (&m_rectCtrl);
	// �����ڴ� DC
	CMemDC *pMemDC = new CMemDC(&dc, &m_rectCtrl);
	
	CPoint orgBrushOrigin = pMemDC->GetBrushOrg () ;
	
	if(m_dcBackground.GetSafeHdc() == NULL || m_pBitmapBackground.m_hObject == NULL)
	{
		m_dcBackground.CreateCompatibleDC(&dc);
		m_pBitmapBackground.CreateCompatibleBitmap(&dc, m_rectCtrl.Width(),m_rectCtrl.Height()) ;
		m_pBitmapOldBackground = m_dcBackground.SelectObject(&m_pBitmapBackground) ;
		InitColorPlot(&m_dcBackground);
	}
	
	pMemDC->BitBlt(0, 0, m_rectCtrl.Width(), m_rectCtrl.Height(), 
		&m_dcBackground, 0, 0, SRCCOPY) ; 
	
	//�����߱���������
	DrawBackGroundGrid(pMemDC); 
	//����������
	DrawValue(pMemDC);
	//������Y�̶�
	DrawAxisScaleYValue(pMemDC);		
	
	pMemDC->SetBrushOrg ( orgBrushOrigin.x , orgBrushOrigin.y ) ;  
	delete pMemDC ;
	// Do not call CStatic::OnPaint() for painting messages
}
// ���û��ߵ�����
void CMultiColorPlotCtrl::SetPlotType(int nType)
{
	nPlotType = nType ;	 
}

// ���ݵ������С������һ�����ݵ�ռ�ݵ���������
BOOL CMultiColorPlotCtrl::SetPlotGranulatrity(int nPlotGrltiy)
{
	nPlotGranulatrity = nPlotGrltiy ;
	nPlotData = m_Size.cx / nPlotGranulatrity ;
	pfData = new float [nPlotData] ;
	if ( pfData )
	{
		// ��ʼ������Ϊ 0 
		ZeroMemory ( pfData , sizeof ( pfData ) * nPlotData ) ;			
		return TRUE ;
	}		
	return FALSE ;
}

// ǰ��ɫ
void CMultiColorPlotCtrl::SetGridLineClr(COLORREF clr)
{
	m_clrDarkLine = clr ;
	m_GridPen.CreatePen ( PS_SOLID , nGridLineWidth , m_clrDarkLine ) ;		
	m_clrDarkLine = clr ; 
}

// ���ݷ�Χ
void CMultiColorPlotCtrl::SetRang(float fL, float fH)
{
	fLow = fL ;
	fHigh = fH ;
}

// ��������
void CMultiColorPlotCtrl::SetLinePen(int nWidth, COLORREF clr)
{
	nGridLineWidth = nWidth ;
	m_clrDarkLine = clr ;
	m_GridPen.CreatePen ( PS_SOLID , nGridLineWidth , m_clrDarkLine ) ;
}

// Y��̶���ɫ
void CMultiColorPlotCtrl::SetAxisScaleClrY(COLORREF clr)
{
	m_clrAxisScaleY = clr ; 
}

// ����
void CMultiColorPlotCtrl::SetTitle(LPCTSTR pctTitle)
{
	_stprintf ( szTitls , _TEXT ( "%s" ) , pctTitle ) ;
}

// ���ݵ�λ����SetUnit( _TEXT ( "(k/sec)" ) ) ;
void CMultiColorPlotCtrl::SetUnit(LPCTSTR pctUint)
{
	_stprintf ( szUints , _TEXT ( "%s" ) , pctUint ) ;
}

// �Ƿ���ʾ���ݱ��⡢��ɫ����λ
/*
nShow = 0 ; ����ʾ�κ��ı�
nShow = 1 ; ������ʾ����
nShow = 2 ; ������ʾ����������ܼ�
nShow = 3 ; ��ʾ�������Сֵ
nShow = 4 ; ��ʾ���⡢��Сֵ����ֵ
*/
void CMultiColorPlotCtrl::ShowTitle(int nShow)
{
	nShowFormatDataText = nShow ;
}

// BAR ��ɫ
// clrUp -------- ������ɫ
// clrDown -------- �ײ���ɫ
// bfRfastness  -------- ��ɫ�����Ƿ�̶�����  false ---- ����
// bfGfastness  -------- ��ɫ�����Ƿ�̶�����  false ---- ����
// bfBfastness  -------- ��ɫ�����Ƿ�̶�����  false ---- ����
void CMultiColorPlotCtrl::SetBarColor(COLORREF clrUp, COLORREF clrDown, bool bfRfastness, bool bfGfastness, bool bfBfastness)
{

}

// ������ɫ
void CMultiColorPlotCtrl::SetLineColorWidth(COLORREF clrLine, int nWidth)
{
	nLineWidth = nWidth ;
	m_clrLinePen = clrLine ;
}
void CMultiColorPlotCtrl::PreSubclassWindow() 
{
	// TODO: Add your specialized code here and/or call the base class
	// ��Ӧͨ����Ϣ
	ModifyStyle( 0 , SS_NOTIFY ) ;
	
	GetClientRect ( & m_rectCtrl ) ;
	
	// �õ��ÿؼ��Ŀ�͸�
	m_Size.cx = m_rectCtrl.right - m_rectCtrl.left ;
	m_Size.cy = m_rectCtrl.bottom - m_rectCtrl.top ;
	
	// ����ؼ������ɿɼ������ݵ���
	nPlotData = m_Size.cx / nPlotGranulatrity ;
	
	// ���ÿؼ�����ʾ�����ֵ�����ʹ�С
	m_SmallFont.CreateFont( -11 , 0 , 0 , 0 , FW_THIN , false , false , false , DEFAULT_CHARSET ,
		OUT_DEFAULT_PRECIS , CLIP_DEFAULT_PRECIS , DEFAULT_QUALITY , VARIABLE_PITCH , _TEXT( "Times New Roman" ) ) ;
	
	// ��ʵ�����ݷ����ڴ�
	pfData = new float [ nPlotData ] ;
	if ( pfData )
	{
		// ��ʼ������Ϊ 0 
		ZeroMemory ( pfData , sizeof ( pfData ) * nPlotData ) ;
		
		m_GridPen.CreatePen ( PS_SOLID , nGridLineWidth , m_clrDarkLine ) ;
		
		CRgn m_Rgn ;
		m_Rgn.CreateRoundRectRgn ( 0 , 0 , m_Size.cx , m_Size.cy , 10 , 10 ) ;
		
		SetWindowRgn ( ( HRGN ) m_Rgn , true ) ; 
		
		SetTimer ( GRID_TIMER , GRID_UPDATE_SPEED , NULL ) ;
	}
	
	CStatic::PreSubclassWindow();
}
BOOL CMultiColorPlotCtrl::OnEraseBkgnd(CDC* pDC)
{
	// TODO: �ڴ������Ϣ�����������/�����Ĭ��ֵ
	return TRUE;
}

void CMultiColorPlotCtrl::ReconstructControl(void)
{
}

void CMultiColorPlotCtrl::InitColorPlot(CDC *pDC)
{
	// ���ݲ�ͬ�����߷ֱ����
	if ( nPlotType == BAR ) 
	{
		double factor = 255.0 / ( float ) m_Size.cy ;

		BYTE r , g , b ;

		for ( int x = 0 ; x < m_Size.cy ; x ++ )
		{
			g = ( BYTE ) ( 255 - factor * x ) ;
			r = ( BYTE ) ( factor * x ) ;
			b = ( BYTE ) 64 ;

			pDC->SetPixelV ( 0 , x , RGB ( r , g , b ) ) ;
			pDC->SetPixelV ( 1 , x , RGB ( r , g , b ) ) ;
		}
	}
	else if ( nPlotType == LINE )
	{
	}
	else
	{
	} 

	pDC->SelectObject ( m_pBitmapOldBackground ) ;

	// ����λͼ��ˢ
	m_clrBrush.CreatePatternBrush ( & m_pBitmapBackground ) ;
}

//��������ͱ���
void CMultiColorPlotCtrl::DrawBackGroundGrid(CDC * pDC)
{
	// ��䱳��ɫ
	pDC->FillSolidRect ( & m_rectCtrl , m_clrDarkBack ) ;

	// ������
	int nGridLinesX = m_Size.cx / nGridResolutionX ;
	int nGridLinesY = m_Size.cy / nGridResolutionY ;

	// ѡ�񻭱�
	CPen * pOldPen = pDC->SelectObject ( & m_GridPen ) ;

	// ������ֱ��
	for ( int x = 0 ; x <= nGridLinesX ; x ++ )
	{
		pDC->MoveTo ( x * nGridResolutionX + nGridStarPosX , 0 );
		pDC->LineTo ( x * nGridResolutionX + nGridStarPosX , m_Size.cy );
	}
	// ���ˮƽ��
	for ( int y = 0 ; y <= nGridLinesY ; y ++ )
	{
		pDC->MoveTo ( 0 , nGridStarPosY + m_Size.cy - y * nGridResolutionY - 2 ) ;
		pDC->LineTo ( m_Size.cx , nGridStarPosY + m_Size.cy - y * nGridResolutionY - 2 ) ;
	}
	// ����������ȷ�ƶ�
	nGridStarPosX += nGridScrollSpeedX ;
	nGridStarPosY += nGridScrollSpeedY ;

	if ( nGridStarPosX < 0 ) nGridStarPosX = nGridResolutionX ;
	if ( nGridStarPosX > nGridResolutionX ) nGridStarPosX = 0 ;
	if ( nGridStarPosY < 0 ) nGridStarPosY = nGridResolutionY ;
	if ( nGridStarPosY > nGridResolutionY ) nGridStarPosY = 0 ;

	// ��ԭ���񻭱�
	pDC->SelectObject ( pOldPen ) ;
}

void CMultiColorPlotCtrl::DrawValue(CDC * pDC)
{
	float fx , fy ;

	// �ùؼ�����ͬ����SetData
	EnterCriticalSection ( & g_cs ) ;

	if ( nPlotType == BAR )
	{
		RECT rFill ;

		for ( int nData = 0 ; nData < nPlotData ; nData ++ )
		{
			fx = ( float ) ( m_rectCtrl.left + nData * nPlotGranulatrity ) ;
			fy = ( float ) fabs ( ( float ) ( m_rectCtrl.bottom - ( ( ( ( pfData[nData] - fLow ) / ( fHigh - fLow ) ) * m_Size.cy ) ) ) ) ;

			rFill.bottom = ( LONG ) m_rectCtrl.bottom ;
			rFill.top = ( LONG ) fy ;
			rFill.left = ( LONG ) fx ;
			rFill.right = ( LONG ) ( fx + nPlotGranulatrity ) ;

			pDC->SetBrushOrg ( ( int ) fx , m_rectCtrl.bottom ) ;

			// �ó�ʼ����ˢʱ���ɵĽ���λͼ��ˢ������
			pDC->FillRect ( & rFill , & m_clrBrush ) ;
			// �����ݵ㴦����ɫ
			pDC->SetPixelV ( ( int ) fx , ( int ) fy , m_clrCyanData ) ;
		}
	}
	else if ( nPlotType == LINE )
	{
		CPoint * g_DataPoint = new CPoint [nPlotData] ;

		// �������߻���
		CPen m_Pen ;
		m_Pen.CreatePen ( PS_SOLID , nLineWidth , m_clrLinePen ) ;
		CPen * m_pOldPen = pDC->SelectObject ( & m_Pen ) ;

		for ( int nData = 0 ; nData < nPlotData ; nData ++ )
		{
			g_DataPoint[nData].x  =  ( LONG ) ( m_rectCtrl.left + nData * nPlotGranulatrity ) ;
			g_DataPoint[nData].y  =  ( LONG ) fabs ( ( float ) ( m_rectCtrl.bottom - ( ( ( ( pfData[nData] - fLow ) / ( fHigh - fLow ) ) * m_Size.cy ) ) ) ) ;
		}

		pDC->Polyline ( g_DataPoint , nPlotData ) ;

		pDC->SelectObject ( m_pOldPen ) ;

		delete [] g_DataPoint ;
	}
	else
	{
	}
}

void CMultiColorPlotCtrl::DrawAxisScaleYValue(CDC * pDC)
{
	CFont * pOldFont ;
	// ����Y��̶�
	TCHAR szAxisScaleYMax [MAX_PATH * sizeof ( TCHAR ) + 1] ;
	TCHAR szAxisScaleYMin [MAX_PATH * sizeof ( TCHAR ) + 1] ;
	TCHAR szAxisScaleY  [MAX_PATH * sizeof ( TCHAR ) + 1] ;

	ZeroMemory ( & szAxisScaleYMax , sizeof ( szAxisScaleYMax ) ) ;
	ZeroMemory ( & szAxisScaleYMin , sizeof ( szAxisScaleYMin ) ) ;
	ZeroMemory ( & szAxisScaleY , sizeof ( szAxisScaleY ) ) ;

	COLORREF clrText = pDC->GetTextColor () ;
	int nBkMode = pDC->GetBkMode () ;
	pDC->SetTextColor ( m_clrAxisScaleY ) ;
	pDC->SetBkMode ( TRANSPARENT ) ;

	pOldFont = pDC->SelectObject ( & m_SmallFont ) ;

	// ���Ҫ����ʵY��̶�����
	switch ( nShowFormatDataText )
	{
	case 0 : // ����ʾ
		{
		} 
		break ;
	case 1 : // ����ʾ����
		{
			_stprintf ( szAxisScaleYMax , _TEXT ( "%s" ) , szTitls ) ;

			pDC->TextOut ( 0 ,  0 , szAxisScaleYMax ) ;
		} 
		break ;
	case 2 : // ��ʾ�������������
		{
			_stprintf ( szAxisScaleYMax , _TEXT ( "%s %8.1f %s / %8.1f" ) , szTitls , pfData [ nPlotData - 1 ] , szUints , fHigh ) ;

			pDC->TextOut ( 0 ,  0 , szAxisScaleYMax ) ;
		} 
		break ;
	case 3 : // ��ʾ�����Сֵ
		{
			// ��ʽ�����ֵ�ͱ��⼰��λ
			_stprintf ( szAxisScaleYMax , _TEXT ( "%s %8.1f %s / %8.1f" ) , szTitls , pfData [ nPlotData - 1 ] , szUints , fHigh ) ;
			// ��ʽ����Сֵ
			_stprintf ( szAxisScaleYMin , _TEXT ( "%8.1f" ) , fLow ) ;

			pDC->TextOut ( 0 ,  0 , szAxisScaleYMax ) ;
			pDC->TextOut ( 0 , m_Size.cy - 10 , szAxisScaleYMin ) ;
		} 
		break ;
	case 4 : // ��ʾȫ��
		{
			// ��ʽ�����ֵ�ͱ��⼰��λ
			_stprintf ( szAxisScaleYMax , _TEXT ( "%s %8.1f %s / %8.1f" ) , szTitls , pfData [ nPlotData - 1 ] , szUints , fHigh ) ;
			// ��ʽ����Сֵ
			_stprintf ( szAxisScaleYMin , _TEXT ( "%8.1f" ) , fLow ) ;
			// ��ʽ����ֵ
			_stprintf ( szAxisScaleY , _TEXT ( "%8.1f" ) , ( ( fHigh - fLow ) / 2.0 + fLow ) ) ;


			// ����Y��̶�
			pDC->TextOut ( 0 ,  0 , szAxisScaleYMax ) ;
			pDC->TextOut ( -8 , m_Size.cy - 13 , szAxisScaleYMin ) ;
			pDC->TextOut ( -8 , m_Size.cy /  2 -10, szAxisScaleY ) ;
		} break ;

	}


	pDC->SetTextColor ( clrText ) ;
	pDC->SetBkMode ( nBkMode ) ;
	pDC->SelectObject ( pOldFont ) ;

	// �뿪�ؼ�����
	LeaveCriticalSection ( & g_cs ) ;
}

void CMultiColorPlotCtrl::OnTimer(UINT nIDEvent)
{
	// TODO: �ڴ������Ϣ�����������/�����Ĭ��ֵ
	switch ( nIDEvent )
	{
	case GRID_TIMER :
		{
		} 
		break ;
	}
	
	Invalidate ( false ) ;

	CStatic::OnTimer(nIDEvent);
}

// ����������
void CMultiColorPlotCtrl::SetGridResolutionX(int nGridReluX)
{
	nGridResolutionX = nGridReluX ;
}

// ����������
void CMultiColorPlotCtrl::SetGridResolutionY(int nGridReluY)
{
	nGridResolutionY = nGridReluY ;
}

// ������������ٶ�,��ֵΪ�������ҹ���,0����
void CMultiColorPlotCtrl::SetGridScrollSpeedX(int nSpeedX)
{
	nGridScrollSpeedX = nSpeedX ; 
}

// ��ֵΪ���ϵ��¹���,0����
void CMultiColorPlotCtrl::SetGridScrollSpeedY(int nSpeedY)
{
	nGridScrollSpeedY = nSpeedY ;
}

// �����߿��
void CMultiColorPlotCtrl::SetGridLineWidth(int nWidth)
{
	nGridLineWidth = nWidth ;
}

// ����ɫ
void CMultiColorPlotCtrl::SetGridBackClr(COLORREF clr)
{
	m_clrDarkBack = clr ;
}

// // ����������ʾ��Χ
void CMultiColorPlotCtrl::LockRang(bool bfLock)
{
	bLock = bfLock ;
}

// ����������ʾ��Χ
void CMultiColorPlotCtrl::LockRang(float fMin, float fMax)
{
	fLow = fMin ;
	fHigh = fMax ;	
	LockRang ( true ) ;
}

// ��������
void CMultiColorPlotCtrl::SetData(float fData)
{
	// �ùؼ�����ͬ��
	EnterCriticalSection ( & g_cs ) ;
	
	for ( int n = 0 ; n < nPlotData - 1 ; n ++ )
	{
		pfData [ n ] = pfData [ n + 1 ] ;
	}
	
	pfData [ nPlotData - 1 ] = fData ;
	
	if ( bLock ) // ����������Χ
	{
	}
	else
	{
		// ������Сֵ
		if ( fLow > fData )
		{
			fLow = fData ;
		}
		// �������ֵ
		if ( fHigh < fData )
		{
			fHigh = fData ;
		}
	}
	
	// �뿪�ؼ�����
	LeaveCriticalSection ( & g_cs ) ;
}

// ������ɫ
void CMultiColorPlotCtrl::SetLineColor(COLORREF clrLine)
{
	m_clrLinePen = clrLine ;
}

void CMultiColorPlotCtrl::SetLineWidth(int nWidth)
{
	nLineWidth = nWidth ;
}

const COLORREF CMultiColorPlotCtrl::GetLineColor(void)
{
	return m_clrLinePen ;
}

const int CMultiColorPlotCtrl::GetLineWidth(void)
{
	return nLineWidth ;
}
 
