// Send1Dlg.cpp : implementation file
//

#include "stdafx.h"
#include "Send1.h"
#include "Send1Dlg.h"

#include "DataType.h"

#include <stdio.h>
#include <conio.h>
#include "packet32.h"
#include <ntddndis.h>

#include <pcap.h>
#include <remote-ext.h>

// #include <Win32-Extensions.h>
#include <cmath>
#include <fstream>

#include "ThreadPool.h"
#include "Packet.h"
#include "highPerformanceTimer.h"

#pragma comment(lib,"wpcap.lib")
#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"wsock32.lib")
#pragma comment(lib,"packet.lib")
#pragma comment(lib,"iphlpapi.lib")

// #pragma comment(lib,"libpacket.a")
// #pragma comment(lib,"libwpcap.a")
//获得网卡以及打开网卡用到的参数
pcap_if_t *alldevs;//获取所有网卡
pcap_if_t *d;//当前选择的网卡
// unsigned char packet[256];//发送的数据包
Packet packet2send;
unsigned char *packetp=packet2send.packet;//发送队列用
int interface_num;//网卡总数
int i=0;
pcap_t *adhandle;
char errbuf[PCAP_ERRBUF_SIZE];
unsigned int res;


volatile BOOL m_bRun;//代表线程是否正在运行
CString desmac;//输入目的地址时用
CString desmac_temp="";
 	int desmac_len;
CString soumac;//获得本机mac地址时用
CString soumac_temp="";
	int soumac_len;

#define  PI 3.1415926535897932384626433832795028841971
int FFT_N;    //定义福利叶变换的点数
double msec;
int wav_A_flg=4;//电流波形显示标记
int wav_V_flg=4;//电压波形显示标记
bool send_flg=false;//表示是否发送

LARGE_INTEGER litmp; 
LONGLONG QPart1,QPart2,QPart3,QPart4,QPart_ini; 
double dfMinus, dfFreq, dfTim; 

int itemp=0;
CString strtemp="";

CThreadPool Pool(50);//创建一个50大小的线程池

pcap_send_queue *squeue;//发送队列　　　
//分配发送队列
const int MaxPacketLen=150;//数据包长度
struct pcap_pkthdr mpktheader;//数据包的包头
struct pcap_pkthdr *pktheader=&mpktheader;
timeval tv;//时间戳
int dus=100;//发送时间间隔，100微秒

int driftA;
int driftB;
int driftC;

int sliderA=106;
int sliderV=106;
int sliderF=65;

#define normal 0
#define k3 1
#define k1 2
#define k2 3
#define k11 4
#define d1 5
#define d2 6

int fault_flg=k3;
bool fault_switch=false;

#define fa 1
#define fb 2
#define fc 3
#define fab 4
#define fac 5
#define fbc 6
#define fabc 7

int fault_p=fabc;
int fault_pswitch=0;
// float alpha;
// float i0;
float pfi;

//电能质量
#define NN -1
#define Aa 0
#define Ab 1
#define Ac 2
#define Va 3
#define Vb 4
#define Vc 5
//谐波
int harm_n;
double harm_amp;
int harm_cursel;
struct _harm{
	int h;
	double amp;
	int cursel;
}harm[31];
int harm_i;
//调幅
double add_freq;
double add_amp;
int add_cursel;
// int smprate;
struct _add
{
	double amp;
	double freq;
	int cursel;
}add[31];
int add_i;
//频率偏移
double freqdrift;
int freqdrift_cursel;
int freqdrift_i;
double f_Aa,f_Ab,f_Ac,f_Va,f_Vb,f_Vc;
// 
// int smpcount;

double interval;

//故障
int f_left,f_right;


// ChighPerformanceTimer HTimer("Timer",true,1);

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/////////////////////////////////////////////////////////////////////////////
// CAboutDlg dialog used for App About

class CAboutDlg : public CDialog
{
public:
	CAboutDlg();

// Dialog Data
	//{{AFX_DATA(CAboutDlg)
	enum { IDD = IDD_ABOUTBOX };
	//}}AFX_DATA

	// ClassWizard generated virtual function overrides
	//{{AFX_VIRTUAL(CAboutDlg)
	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support
	//}}AFX_VIRTUAL

// Implementation
protected:
	//{{AFX_MSG(CAboutDlg)
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialog(CAboutDlg::IDD)
{
	//{{AFX_DATA_INIT(CAboutDlg)
	//}}AFX_DATA_INIT
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	//{{AFX_DATA_MAP(CAboutDlg)
	//}}AFX_DATA_MAP
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialog)
	//{{AFX_MSG_MAP(CAboutDlg)
		// No message handlers
	//}}AFX_MSG_MAP
END_MESSAGE_MAP()

/////////////////////////////////////////////////////////////////////////////
// CSend1Dlg dialog

CSend1Dlg::CSend1Dlg(CWnd* pParent /*=NULL*/)
	: CDialog(CSend1Dlg::IDD, pParent)
{
	//{{AFX_DATA_INIT(CSend1Dlg)
		// NOTE: the ClassWizard will add member initialization here
	//}}AFX_DATA_INIT
	// Note that LoadIcon does not require a subsequent DestroyIcon in Win32
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CSend1Dlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	//{{AFX_DATA_MAP(CSend1Dlg)
	DDX_Control(pDX, IDC_EDIT_right, m_right);
	DDX_Control(pDX, IDC_EDIT_left, m_left);
	DDX_Control(pDX, IDC_SLIDER_fault, m_slider_f);
	DDX_Control(pDX, IDC_EDIT22, m_freqdrift_i);
	DDX_Control(pDX, IDC_EDIT21, m_harm_i);
	DDX_Control(pDX, IDC_EDIT20, m_add_i);
	DDX_Control(pDX, IDC_EDIT_smprate, m_smprate);
	DDX_Control(pDX, IDC_EDIT_smpcount, m_smpcount);
	DDX_Control(pDX, IDC_COMBO_harm, m_harmList);
	DDX_Control(pDX, IDC_COMBO_freq, m_freqList);
	DDX_Control(pDX, IDC_COMBO_add, m_addList);
	DDX_Control(pDX, IDC_EDIT19, m_freq);
	DDX_Control(pDX, IDC_EDIT18, m_harm_amp);
	DDX_Control(pDX, IDC_EDIT17, m_harm_n);
	DDX_Control(pDX, IDC_EDIT16, m_add_freq);
	DDX_Control(pDX, IDC_EDIT15, m_add_amp);
	DDX_Control(pDX, IDC_EDIT_faultPeriod, m_fault_period);
	DDX_Control(pDX, IDC_RADIO_k3, m_fault_k3);
	DDX_Control(pDX, IDC_CHECK_fc, m_fc);
	DDX_Control(pDX, IDC_CHECK_fb, m_fb);
	DDX_Control(pDX, IDC_CHECK_fa, m_fa);
	DDX_Control(pDX, IDC_EDIT8, m_am_Vn);
	DDX_Control(pDX, IDC_EDIT7, m_am_An);
	DDX_Control(pDX, IDC_EDIT11, m_phaseC_drift);
	DDX_Control(pDX, IDC_EDIT10, m_phaseB_drift);
	DDX_Control(pDX, IDC_EDIT9, m_phaseA_drift);
	DDX_Control(pDX, IDC_SLIDER_V, m_slider_v);
	DDX_Control(pDX, IDC_SLIDER_A, m_slider_a);
	DDX_Control(pDX, IDC_RADIO6, m_radio_Vabc);
	DDX_Control(pDX, IDC_PLOT_VOLTAGE_C, m_voltage_c);
	DDX_Control(pDX, IDC_PLOT_VOLTAGE_B, m_voltage_b);
	DDX_Control(pDX, IDC_PLOT_VOLTAGE_ABC, m_voltage_abc);
	DDX_Control(pDX, IDC_PLOT_VOLTAGE_A, m_voltage_a);
	DDX_Control(pDX, IDC_PROGRESS1, m_progress);
	DDX_Control(pDX, IDC_CHECK1, m_check_src);
	DDX_Control(pDX, IDC_EDIT6, m_am_Vc);
	DDX_Control(pDX, IDC_EDIT5, m_am_Vb);
	DDX_Control(pDX, IDC_EDIT4, m_am_Va);
	DDX_Control(pDX, IDC_PLOT_CURRENT_ABC, m_current_abc);
	DDX_Control(pDX, IDC_RADIO1, m_radio_Aabc);
	DDX_Control(pDX, IDC_PLOT_CURRENT_C, m_current_c);
	DDX_Control(pDX, IDC_PLOT_CURRENT_B, m_current_b);
	DDX_Control(pDX, IDC_EDIT3, m_am_Ac);
	DDX_Control(pDX, IDC_EDIT2, m_am_Ab);
	DDX_Control(pDX, IDC_EDIT1, m_am_Aa);
	DDX_Control(pDX, IDC_PLOT_CURRENT_A, m_current_a);
	DDX_Control(pDX, IDC_EDIT_soumac, m_soumac);
	DDX_Control(pDX, IDC_EDIT_desmac, m_desmac);
	DDX_Control(pDX, IDC_AdapterList, m_adapter);
	//}}AFX_DATA_MAP
}

BEGIN_MESSAGE_MAP(CSend1Dlg, CDialog)
	//{{AFX_MSG_MAP(CSend1Dlg)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDSEND, OnSend)
	ON_CBN_DROPDOWN(IDC_AdapterList, OnDropdownAdapterList)
	ON_CBN_SELCHANGE(IDC_AdapterList, OnSelchangeAdapterList)
	ON_BN_CLICKED(IDC_STOP, OnStop)
	ON_EN_CHANGE(IDC_EDIT_desmac, OnChangeEdit13)
	ON_WM_TIMER()
	ON_EN_CHANGE(IDC_EDIT1, OnChangeEdit1_am_Aa)
	ON_EN_CHANGE(IDC_EDIT2, OnChangeEdit2_am_Ab)
	ON_EN_CHANGE(IDC_EDIT3, OnChangeEdit3_am_Ac)
	ON_BN_CLICKED(IDC_RADIO1, OnRadio_Aabc)
	ON_BN_CLICKED(IDC_RADIO2, OnRadio_Aa)
	ON_BN_CLICKED(IDC_RADIO3, OnRadio_Ab)
	ON_BN_CLICKED(IDC_RADIO4, OnRadio_Ac)
	ON_BN_CLICKED(IDC_CHECK1, OnCheck1_ChangeSrcMac)
	ON_EN_CHANGE(IDC_EDIT_soumac, OnChangeEDITsoumac)
	ON_BN_CLICKED(IDC_RADIO5, OnRadio_Ashut)
	ON_EN_CHANGE(IDC_EDIT4, OnChangeEdit4_am_Va)
	ON_EN_CHANGE(IDC_EDIT5, OnChangeEdit5_am_Vb)
	ON_EN_CHANGE(IDC_EDIT6, OnChangeEdit6_am_Vc)
	ON_BN_CLICKED(IDC_RADIO6, OnRadio_Vabc)
	ON_BN_CLICKED(IDC_RADIO7, OnRadio_Va)
	ON_BN_CLICKED(IDC_RADIO8, OnRadio_Vb)
	ON_BN_CLICKED(IDC_RADIO9, OnRadio_Vc)
	ON_BN_CLICKED(IDC_RADIO10, OnRadio_Vshut)
	ON_NOTIFY(NM_CUSTOMDRAW, IDC_SLIDER_A, OnCustomdrawSliderA)
	ON_NOTIFY(NM_CUSTOMDRAW, IDC_SLIDER_V, OnCustomdrawSliderV)
	ON_EN_CHANGE(IDC_EDIT9, OnChangeEdit9_driftA)
	ON_EN_CHANGE(IDC_EDIT10, OnChangeEdit10_driftB)
	ON_EN_CHANGE(IDC_EDIT11, OnChangeEdit11_driftC)
	ON_BN_CLICKED(IDC_RADIO_k3, OnRADIOk3)
	ON_BN_CLICKED(IDC_RADIO_k1, OnRADIOk1)
	ON_BN_CLICKED(IDC_RADIO_k2, OnRADIOk2)
	ON_BN_CLICKED(IDC_RADIO_k11, OnRADIOk11)
	ON_BN_CLICKED(IDC_RADIO_d1, OnRADIOd1)
	ON_BN_CLICKED(IDC_RADIO_d2, OnRADIOd2)
	ON_BN_CLICKED(IDC_CHECK_fa, OnCHECKfa)
	ON_BN_CLICKED(IDC_CHECK_fb, OnCHECKfb)
	ON_BN_CLICKED(IDC_CHECK_fc, OnCHECKfc)
	ON_BN_CLICKED(IDC_BUTTON_faulton, OnBUTTONfaulton)
	ON_BN_CLICKED(IDC_BUTTON_faultoff, OnBUTTONfaultoff)
	ON_BN_CLICKED(IDC_BUTTON1, OnButton_add_plus)
	ON_BN_CLICKED(IDC_BUTTON2, OnButton_add_minus)
	ON_BN_CLICKED(IDC_BUTTON3, OnButton_harm_plus)
	ON_BN_CLICKED(IDC_BUTTON4, OnButton_harm_minus)
	ON_CBN_DROPDOWN(IDC_COMBO_add, OnDropdownCOMBOadd)
	ON_CBN_DROPDOWN(IDC_COMBO_freq, OnDropdownCOMBOfreq)
	ON_CBN_DROPDOWN(IDC_COMBO_harm, OnDropdownCOMBOharm)
	ON_CBN_SELCHANGE(IDC_COMBO_add, OnSelchangeCOMBOadd)
	ON_CBN_SELCHANGE(IDC_COMBO_freq, OnSelchangeCOMBOfreq)
	ON_CBN_SELCHANGE(IDC_COMBO_harm, OnSelchangeCOMBOharm)
	ON_EN_CHANGE(IDC_EDIT_smprate, OnChangeEDITsmprate)
	ON_BN_CLICKED(IDC_BUTTON5, OnButton_freqdrift)
	ON_BN_CLICKED(IDC_BUTTON7, OnButton_about)
	ON_BN_CLICKED(IDC_BUTTON8, OnButton_Save)
	ON_NOTIFY(NM_CUSTOMDRAW, IDC_SLIDER_fault, OnCustomdrawSLIDERfault)
	//}}AFX_MSG_MAP
END_MESSAGE_MAP()

/////////////////////////////////////////////////////////////////////////////
// CSend1Dlg message handlers

BOOL CSend1Dlg::OnInitDialog()
{
	CDialog::OnInitDialog();

	// Add "About..." menu item to system menu.

	// IDM_ABOUTBOX must be in the system command range.
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
	{
		CString strAboutMenu;
		strAboutMenu.LoadString(IDS_ABOUTBOX);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// Set the icon for this dialog.  The framework does this automatically
	//  when the application's main window is not a dialog
	SetIcon(m_hIcon, TRUE);			// Set big icon
	SetIcon(m_hIcon, FALSE);		// Set small icon
	
	// TODO: Add extra initialization here
//初始化波形显示
//电流
	m_current_a.SetTitle("A相电流:");
	m_current_a.SetUnit(":kA");
//	m_current_a.LockRang(-500.00f,500.00f);
	m_current_a.SetRang(-600,600);
	m_current_a.SetPlotGranulatrity(4);
	m_current_a.SetGridResolutionX(10);
	m_current_a.ShowTitle(4);
	m_current_a.SetPlotType(LINE);
	m_current_a.SetGridScrollSpeedX(0);
	
	m_current_b.SetTitle("B相电流:");
	m_current_b.SetUnit(":kA");
	//	m_current_a.LockRang(-500.00f,500.00f);
	m_current_b.SetRang(-600,600);
	m_current_b.SetPlotGranulatrity(4);
	m_current_b.SetGridResolutionX(10);
	m_current_b.ShowTitle(4);
	m_current_b.SetPlotType(LINE);
	m_current_b.SetGridScrollSpeedX(0);

	m_current_c.SetTitle("C相电流:");
	m_current_c.SetUnit(":kA");
	//	m_current_a.LockRang(-500.00f,500.00f);
	m_current_c.SetRang(-600,600);
	m_current_c.SetPlotGranulatrity(4);
	m_current_c.SetGridResolutionX(10);
	m_current_c.ShowTitle(4);
	m_current_c.SetPlotType(LINE);
	m_current_c.SetGridScrollSpeedX(0);

	m_current_abc.SetTitle("ABC相电流:");
	m_current_abc.SetUnit(":kA");
	//	m_current_a.LockRang(-500.00f,500.00f);
	m_current_abc.SetRang(-600,600);
	m_current_abc.SetPlotGranulatrity(4);
	m_current_abc.SetGridResolutionX(10);
	m_current_abc.ShowTitle(4);
	m_current_abc.SetPlotType(LINE);
	m_current_abc.SetGridScrollSpeedX(0);
	GetDlgItem(IDC_PLOT_CURRENT_ABC)->ShowWindow(SW_HIDE);	
//	m_radio_Aabc.SetCheck(TRUE);
	CheckRadioButton(IDC_RADIO1,IDC_RADIO5,IDC_RADIO5);
// 	OnRadio_Ashut();
//电压
	m_voltage_a.SetTitle("A相电压:");
	m_voltage_a.SetUnit(":kA");
	//	m_current_a.LockRang(-500.00f,500.00f);
	m_voltage_a.SetRang(-600,600);
	m_voltage_a.SetPlotGranulatrity(4);
	m_voltage_a.SetGridResolutionX(10);
	m_voltage_a.ShowTitle(4);
	m_voltage_a.SetPlotType(LINE);
	m_voltage_a.SetGridScrollSpeedX(0);
	
	m_voltage_b.SetTitle("B相电压:");
	m_voltage_b.SetUnit(":kA");
	//	m_current_a.LockRang(-500.00f,500.00f);
	m_voltage_b.SetRang(-600,600);
	m_voltage_b.SetPlotGranulatrity(4);
	m_voltage_b.SetGridResolutionX(10);
	m_voltage_b.ShowTitle(4);
	m_voltage_b.SetPlotType(LINE);
	m_voltage_b.SetGridScrollSpeedX(0);
	
	m_voltage_c.SetTitle("C相电压:");
	m_voltage_c.SetUnit(":kA");
	//	m_current_a.LockRang(-500.00f,500.00f);
	m_voltage_c.SetRang(-600,600);
	m_voltage_c.SetPlotGranulatrity(4);
	m_voltage_c.SetGridResolutionX(10);
	m_voltage_c.ShowTitle(4);
	m_voltage_c.SetPlotType(LINE);
	m_voltage_c.SetGridScrollSpeedX(0);
	
	m_voltage_abc.SetTitle("ABC相电压:");
	m_voltage_abc.SetUnit(":kA");
	//	m_current_a.LockRang(-500.00f,500.00f);
	m_voltage_abc.SetRang(-600,600);
	m_voltage_abc.SetPlotGranulatrity(4);
	m_voltage_abc.SetGridResolutionX(10);
	m_voltage_abc.ShowTitle(4);
	m_voltage_abc.SetPlotType(LINE);
	m_voltage_abc.SetGridScrollSpeedX(0);
	GetDlgItem(IDC_PLOT_VOLTAGE_ABC)->ShowWindow(SW_HIDE);	
//	m_radio_Vabc.SetCheck(TRUE);
// 	GetCheckedRadioButton(IDC_RADIO1,IDC_RADIO6)!=IDC_RADIO6;
	CheckRadioButton(IDC_RADIO6,IDC_RADIO10,IDC_RADIO10);
// 	OnRadio_Vshut();


//初始化电流电压幅值窗口、
	CString am;	
	m_am_Aa.SetWindowText("220");
	m_am_Ab.SetWindowText("220");
	m_am_Ac.SetWindowText("220");

	m_am_Aa.GetWindowText(am);
	packet2send.data_to_send.am_Aa=sqrt(2)*atof(am);

	m_am_Ab.GetWindowText(am);
	packet2send.data_to_send.am_Ab=sqrt(2)*atof(am);

	m_am_Ac.GetWindowText(am);
	packet2send.data_to_send.am_Ac=sqrt(2)*atof(am);
////电压
	m_am_Va.SetWindowText("220");
	m_am_Vb.SetWindowText("220");
	m_am_Vc.SetWindowText("220");
	
	m_am_Va.GetWindowText(am);
	packet2send.data_to_send.am_Va=sqrt(2)*atof(am);
	
	m_am_Vb.GetWindowText(am);
	packet2send.data_to_send.am_Vb=sqrt(2)*atof(am);
	
	m_am_Vc.GetWindowText(am);
	packet2send.data_to_send.am_Vc=sqrt(2)*atof(am);
//设置slider
	m_slider_a.SetRange(1,120);
	m_slider_v.SetRange(1,120);
	m_slider_f.SetRange(0,100);

	m_slider_a.SetPos(sliderA);
	m_slider_v.SetPos(sliderV);
	m_slider_f.SetPos(sliderF);
	m_left.SetWindowText("65%");
	m_right.SetWindowText("35%");
//设置相位偏移
	m_phaseA_drift.SetWindowText("0");
	m_phaseB_drift.SetWindowText("0");
	m_phaseC_drift.SetWindowText("0");

	m_phaseA_drift.GetWindowText(am);
	driftA=atof(am);
	
	m_phaseB_drift.GetWindowText(am);
	driftB=atof(am);
	
	m_phaseC_drift.GetWindowText(am);
	driftC=atof(am);
//设置故障模拟
	m_fault_k3.SetCheck(true);
	m_fa.SetCheck(true);
	m_fb.SetCheck(true);
	m_fc.SetCheck(true);
	GetDlgItem(IDC_CHECK_fa)->EnableWindow(FALSE);
	GetDlgItem(IDC_CHECK_fb)->EnableWindow(FALSE);
	GetDlgItem(IDC_CHECK_fc)->EnableWindow(FALSE);
	fault_flg=k3;
	fault_switch=false;
	m_fault_period.SetWindowText("999999");
	GetDlgItem(IDC_BUTTON_faulton)->EnableWindow(FALSE);
	GetDlgItem(IDC_BUTTON_faultoff)->EnableWindow(FALSE);

//初始化电能质量设置
	m_add_amp.SetWindowText("0");
	m_add_freq.SetWindowText("0");

	m_harm_amp.SetWindowText("0");
	m_harm_n.SetWindowText("2");

	m_add_amp.GetWindowText(am);
//	add_amp=atoi(am);
	m_add_freq.GetWindowText(am);
	add_freq=atof(am);
	m_harm_amp.GetWindowText(am);
	harm_amp=atof(am);	
	m_harm_n.GetWindowText(am);
	harm_n=atoi(am);

	m_freq.SetWindowText("0");
	m_freq.GetWindowText(am);
	freqdrift=atof(am);

	add_cursel=NN;
	harm_cursel=NN;
	freqdrift_cursel=NN;

	add_i=0;
	harm_i=0;
	freqdrift_i=0;
	m_add_i.SetWindowText("0");
	m_harm_i.SetWindowText("0");
	m_freqdrift_i.SetWindowText("0");

	m_smpcount.SetWindowText("0");
	m_smpcount.GetWindowText(am);
	packet2send.smpCount=atoi(am);
	m_smprate.SetWindowText("100");
	m_smprate.GetWindowText(am);
	packet2send.smpRate=atoi(am);

	f_Aa=0;
	f_Ab=0;
	f_Ac=0;
	f_Va=0;
	f_Vb=0;
	f_Vc=0;

////////////
 	//计时器初始化
 	QueryPerformanceFrequency(&litmp); 
 	// 获得计数器的时钟频率 
 	dfFreq = (double)litmp.QuadPart; 

//创建发送和计时器线程
	hThread_send=CreateThread(NULL,
		0,
		(LPTHREAD_START_ROUTINE)ThreadFunc_Send,
		(CSend1Dlg *)this,
		CREATE_SUSPENDED,
		&ThreadID_send);
	SetThreadPriority(hThread_send,HIGH_PRIORITY_CLASS);

	hThread_timer=CreateThread(NULL,
		0,
		(LPTHREAD_START_ROUTINE)ThreadFunc_Timer,
		(CSend1Dlg *)this,
		CREATE_SUSPENDED,
		&ThreadID_timer);
	SetThreadPriority(hThread_timer,REALTIME_PRIORITY_CLASS);

	fault_pswitch=0;
//////////////////////

// 	HTimer.Expires(1,true,1);
// 	pThread=AfxBeginThread(ThreadFunc,
// 		(CSend1Dlg *)this,THREAD_PRIORITY_NORMAL,0,CREATE_SUSPENDED,NULL);
// 	pThread->m_bAutoDelete=false;
	SetTimer(1,1,NULL);
	return TRUE;  // return TRUE  unless you set the focus to a control
}

void CSend1Dlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialog::OnSysCommand(nID, lParam);
	}
}

// If you add a minimize button to your dialog, you will need the code below
//  to draw the icon.  For MFC applications using the document/view model,
//  this is automatically done for you by the framework.

void CSend1Dlg::OnPaint() 
{
	if (IsIconic())
	{
		CPaintDC dc(this); // device context for painting

		SendMessage(WM_ICONERASEBKGND, (WPARAM) dc.GetSafeHdc(), 0);

		// Center icon in client rectangle
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// Draw the icon
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialog::OnPaint();
	}
}

// The system calls this to obtain the cursor to display while the user drags
//  the minimized window.
HCURSOR CSend1Dlg::OnQueryDragIcon()
{
	return (HCURSOR) m_hIcon;
}

void CSend1Dlg::OnSend() 
{
	if(d==NULL){
		MessageBox("请先选择网卡","错误",MB_OK);
	}
	else{
		GetDlgItem(IDC_EDIT_smprate)->EnableWindow(FALSE);
		GetDlgItem(IDC_BUTTON_faulton)->EnableWindow(true);
		send_flg=true;
		if(m_check_src.GetCheck()==false)
		{
			GetMacAddress();
		}
	/* Fill the rest of the packet */
//		packet_ini();
		
		m_bRun=true;
// 		HTimer.Start();
		ResumeThread(hThread_timer);
  //		ResumeThread(hThread_send);
// 		Pool.Run(ThreadFunc_Send,(CSend1Dlg *)this);
//		Pool.Run(ThreadFunc_Timer,(CSend1Dlg *)this);
// 		ResumeThread(pThread->m_hThread);
	}
}
timeval add_stamp(timeval *ptv,unsigned int dus)
{
	ptv->tv_usec=ptv->tv_usec+dus;
	if(ptv->tv_usec>=1000000)
	{
		ptv->tv_sec=ptv->tv_sec+1;
		ptv->tv_usec=ptv->tv_usec-1000000;
	}
	return *ptv;
}
DWORD WINAPI ThreadFunc_Send(LPVOID lpParam)//线程函数，实际是处理抓包的，用另一个线程处理，避免用户界面卡死
{
// 	::MessageBox(NULL,"123","asdad",MB_OK);
 	CSend1Dlg *DlgThis=(CSend1Dlg *)lpParam;
//	++itemp;
// 	strtemp.Format("%d",itemp);
// 	DlgThis->m_am_An.SetWindowText(strtemp);
// 
	DlgThis->SetSin(packet2send.data_to_send.am_Aa,
		packet2send.data_to_send.am_Ab,
		packet2send.data_to_send.am_Ac,
		0,
		packet2send.data_to_send.am_Va,
		packet2send.data_to_send.am_Vb,
		packet2send.data_to_send.am_Vc,
		0);
	DlgThis->add_amp();
	DlgThis->add_harm();
	DlgThis->ShowWave();
	packet2send.RecCurrent_Voltage();
  	packet2send.CreatFrame();

// 	strtemp.Format("%d",packet2send.smpCount);
// 	DlgThis->m_smpcount.SetWindowText(strtemp);
// 
// 	if (send_flg==true)
// 	{
// 		DlgThis->DataSet_32(packet2send.data_to_send.currentA,&packet2send.packet[53]);
// 		DlgThis->DataSet_32(packet2send.data_to_send.currentB,&packet2send.packet[57]);
// 		DlgThis->DataSet_32(packet2send.data_to_send.currentC,&packet2send.packet[61]);
// 		// 			DlgThis->hThread=CreateThread(NULL,
// 		// 				0,
// 		// 				(LPTHREAD_START_ROUTINE)ThreadFunc_Send,
// 		// 				(CSend1Dlg *)this,
// 		// 				0,
// 		// 				&DlgThis->ThreadID);
// 	}

	/* 发送packet */
  	pcap_sendpacket(adhandle, packet2send.packet, packet2send.send_len);

	// 	while (m_bRun)
	// 	{
	// 		if (pcap_sendpacket(adhandle, packet, 100)!= 0)
	// 		{
	// // 			fprintf(stderr,"\nError sending the packet: \n", pcap_geterr(adhandle));
	// 			//         return -1;
	//		}
	// 	}
// 	strtemp.Format("%d",itemp++);
// 	DlgThis->m_am_Va.SetWindowText(strtemp);
// 	DlgThis->hThread_send=CreateThread(NULL,
// 		0,
// 		(LPTHREAD_START_ROUTINE)ThreadFunc_Send,
// 		DlgThis,
// 		CREATE_SUSPENDED,
// 		&DlgThis->ThreadID_send);
// 	SetThreadPriority(DlgThis->hThread_send,HIGH_PRIORITY_CLASS);
// 

// 	tv.tv_sec=0;
// 	tv.tv_usec=0;
// // 	int npacks=10000;
// 	//用数据包填充发送队列　　　
// 	//设置数据包的包头
// 	pktheader->ts=tv;
// 	pktheader->caplen=packet2send.send_len;//发送包的长度
// //	pktheader->len=packet2send.send_len/*MaxPacketLen*/;
// 	squeue=pcap_sendqueue_alloc((unsigned int)((MaxPacketLen+sizeof(struct pcap_pkthdr)) *1000));
// 	if(pcap_sendqueue_queue(squeue,pktheader,packetp) == -1)
// 	{
// //			printf("警告:　数据包缓冲区太小，不是所有的数据包被发送.n");
// 		MessageBox(NULL,"数据包缓冲区太小，不是所有的数据包被发送","警告",MB_OK);
// 	}
// 	add_stamp(&tv,dus);//增加时间戳
// 	pktheader->ts=tv;//更新数据包头的时间戳
// 
// 	if (itemp%10==0)
// 	{
// 		//发送数据包
// 	// 	Sleep(1);
// 		if((/*res=*/pcap_sendqueue_transmit(adhandle,squeue,1))<squeue->len)
// 		{
// 	// 		printf("发送数据包时出现错误：%s.仅%d字节被发送n",pcap_geterr(adhandle),res);
// 			MessageBox(NULL,"发送数据包时出现错误","警告",MB_OK);
// 		}
// 	}
// //	pcap_sendqueue_transmit(adhandle,squeue,1);
// // 	//释放发送队列
// 	pcap_sendqueue_destroy(squeue);
// // 	//关闭输出设备
// // 	pcap_close(fp);
	return 0;
}

void CSend1Dlg::OnDropdownAdapterList() 
{
								/*获取网卡列表，并显示在下拉菜单中：*/
	m_adapter.ResetContent();
	i=0;
	CString adapter="";
	/* 获得网卡列表 */ 
	if (pcap_findalldevs(&alldevs, errbuf) == -1)
// 	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
	{
		MessageBox("获取网卡列表错误","错误",MB_OK);
//		fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
/*		exit(1);*/
	}
	
	/* 打印网卡信息 */
	for(d=alldevs; d; d=d->next)
	{
		adapter="";
// 		//		printf("%d. %s", ++i, d->name);
// 		cout<<"No. : "<<++i<<endl;
// 		cout<<"Name: "<<d->name<<endl;
		++i;
// 		adapter=d->name;
		if (d->description)
			adapter+=d->description;
/*			cout<<"Description: "<<d->description<<endl<<endl;*/
		//			printf(" (%s)\n", d->description);
 		else
			adapter+=d->name;
// 			printf(" (No description available)\n\n");
/*		m_adapter.AddString(adapter);	*/
		m_adapter.InsertString(i-1,adapter);

	}
	/* 未找到网卡 */
	if(i==0)
	{
// 		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		MessageBox("未找到任何网卡","提示",MB_OK);
/*		return -1;*/
	}
}

void CSend1Dlg::OnSelchangeAdapterList() 
{
	// TODO: Add your control notification handler code here
							/*选择某个网卡：*/
	int interface_num=0;
	interface_num=m_adapter.GetCurSel();

	/* 找到要选择的网卡结构 */
	for(d=alldevs, i=0; i< interface_num-1 ;d=d->next, i++);

	/* 打开选择的网卡 */
	if ( (adhandle= pcap_open_live(d->name, // 设备名称
		65536,   // portion of the packet to capture.  
		// 65536 grants that the whole packet will be captured on all the MACs.
		1,       // 混杂模式
		1000,     // 读超时为1秒
		errbuf   // error buffer
		) ) == NULL)
	{ //打开不成功，返回
		MessageBox("打开网卡失败","错误",MB_OK);
// 		fprintf(stderr,"\nUnable to open the adapter. %s is not supported by WinPcap\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
// 		return -1;
	}
 		GetMacAddress();//显示本机mac地址
 		ShowDesMacAddress();//显示packet包中的目的地址
}

void CSend1Dlg::OnStop() 
{
	// TODO: Add your control notification handler code here
	m_bRun=FALSE;
	send_flg=false;
	GetDlgItem(IDC_EDIT_smprate)->EnableWindow(true);
	GetDlgItem(IDC_BUTTON_faulton)->EnableWindow(FALSE);
	GetDlgItem(IDC_BUTTON_faultoff)->EnableWindow(FALSE);
// 	HTimer.Stop();
	//释放发送队列
// 	pcap_sendqueue_destroy(squeue);
	// 	//关闭输出设备
	// 	pcap_close(fp);
// 	pcap_sendqueue_transmit(adhandle,squeue,1);

}

void CSend1Dlg::OnChangeEdit13()//获取目的mac地址
{
	// TODO: If this is a RICHEDIT control, the control will not
	// send this notification unless you override the CDialog::OnInitDialog()
	// function and call CRichEditCtrl().SetEventMask()
	// with the ENM_CHANGE flag ORed into the mask.
	
	// TODO: Add your control notification handler code here
	m_desmac.GetWindowText(desmac);
	desmac_len=desmac.GetLength();
	//12:12:12:12:12:12
	if(desmac_len<=17)
		desmac_temp=desmac;
	else {
		m_desmac.SetWindowText(desmac_temp);
		desmac=desmac_temp;
		m_desmac.SetSel(-1);//是光标放在最后
	}
	if(desmac_len==2 || desmac_len==5 || desmac_len==8 || desmac_len==11 || desmac_len==14){
		desmac+=":";
		m_desmac.SetWindowText(desmac);
		m_desmac.SetSel(-1);//是光标放在最后
	}
	sscanf(desmac,"%x:%x:%x:%x:%x:%x",&packet2send.packet[0],&packet2send.packet[1],&packet2send.packet[2],&packet2send.packet[3],&packet2send.packet[4],&packet2send.packet[5]);
}

void CSend1Dlg::GetMacAddress()
{
	//
	// 打开选定的网卡
	//
	LPADAPTER	lpAdapter = 0;
	PPACKET_OID_DATA  OidData;
	lpAdapter = PacketOpenAdapter(d->name);
	BOOLEAN		Status;

	// 
	// 为MAC地址分配空间
	//
	OidData = (PPACKET_OID_DATA )malloc(6 + sizeof(PACKET_OID_DATA));
	if (OidData == NULL) 
	{
//		printf("error allocating memory!\n");
		MessageBox("error allocating memory!\n","error",MB_OK);
		PacketCloseAdapter(lpAdapter);
//		return -1;
	}
	// 
	// Retrieve the adapter MAC querying the NIC driver
	//
	
	OidData->Oid = OID_802_3_CURRENT_ADDRESS;
	
	OidData->Length = 6;
	ZeroMemory(OidData->Data, 6);
	
	Status = PacketRequest(lpAdapter, FALSE, OidData);
	if(Status)
	{//打印MAC地址
//		printf("The MAC address of the adapter is %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n",
			packet2send.packet[6]=(OidData->Data)[0];
			packet2send.packet[7]=(OidData->Data)[1];
			packet2send.packet[8]=(OidData->Data)[2];
			packet2send.packet[9]=(OidData->Data)[3];
			packet2send.packet[10]=(OidData->Data)[4];
			packet2send.packet[11]=(OidData->Data)[5];
			CString str1;
			soumac="";
			for (int i = 6; i < 12; i++)
			{
				if (i != 11)
				{
					str1.Format("%02x:",packet2send.packet[i]);
					soumac+=str1;
				}
				else{
					str1.Format("%02x",packet2send.packet[i]);
					soumac+=str1;
				}
				
			}
			soumac.MakeUpper();
			m_soumac.SetWindowText(soumac);
	}
	else
	{
		MessageBox("error retrieving the MAC address of the adapter!\n","error",MB_OK);
//		printf("error retrieving the MAC address of the adapter!\n");
	}
	
	free(OidData);
	PacketCloseAdapter(lpAdapter);
}

void CSend1Dlg::ShowDesMacAddress()
{
	desmac="";
	CString str1;
	for (int i = 0; i < 6; i++)
	{
		if (i != 5)
		{
			// 	            printf("%02x-", dlcheader->DesMAC[i]);
			str1.Format("%02x:",packet2send.packet[i]);
			desmac+=str1;
		}
		else{
			// 	            printf("%02x\n", dlcheader->DesMAC[i]);
			str1.Format("%02x",packet2send.packet[i]);
			desmac+=str1;
		}
		
	}
	desmac.MakeUpper();
	m_desmac.SetWindowText(desmac);


}

void CSend1Dlg::OnTimer(UINT nIDEvent) 
{
	// TODO: Add your message handler code here and/or call default
// 	m_current_a.SetData( ( float ) GetRandom(20000,50000)/100 ) ;
	for (int ii=1;ii<=101;ii+=5)
	{
		m_progress.SetPos(ii);
		Sleep(1);
	}
	KillTimer(nIDEvent);
	CDialog::OnTimer(nIDEvent);
}
// 
// void CSend1Dlg::packet_ini()
// {
// //0-5 6-11在别的函数中修改
// //802.1q//优先级标记4字节
// 	//TPID 默认是8100
//  	packet[12]=0x81;//0x81;
//  	packet[13]=0x00;
// 	//TCI
// 	packet[14]=0x80;
// 	// 				User priorit（3位）：用户优先级，用来区分采样值，实时的保护相关的GOOSE报
// 	// 				文和低优先级的总线负载。高优先级帧应设置其优先级为4～7，低优先级帧
// 	// 				则为1～3，优先级1 为未标记的帧，应避免采用优先级0，因为这会引起正
// 	// 				常通信下不可预见的传输时延。 
// 	// 				采样值传输优先级设置建议为最高级7。
// 	// 				CFI（1位）：若值为1，则表明在ISO/IEC 8802-3  标记帧中，Length/Type 域后接着
// 	// 				内嵌的路由信息域(RIF)，否则应置0。
// 	packet[15]=0x00;//虚拟局域网ID
// //以太网类型 Ethertype //2字节
// 	//由IEEE著作权注册机构进行注册，可以区分不同应用。 
// 	// 		
// 	//应用  以太网类型码（16 进制）  
// 	//IEC 61850-8-1 GOOSE   88-B8 
// 	//IEC 61850-9-1 采样值  88-BA 
// 	//IEC 61850-9-2 采样值  88-BA 
// 	packet[16]=0x88;
// 	packet[17]=0xBA;
// //以太网类型PDU //Ether-type PDU//8字节
// 	//APPID
// 	// 	APPID：应用标识，建议在同一系统中采用唯一标识，面向数据源的标识。 
// 	// 	为采样值保留的 APPID 值范围是 0x4000-0x7fff。可以根据报文中的 APPID
// 	// 	来确定唯一的采样值控制块
//  /*可能需要修改*/
// 	packet[18]=0x40;//本处采用4000为APPID
// 	packet[19]=0x00;
//  /*可能需要修改*/
// 	//length
// 	// 	长度Length：从 APPID开始的字节数。 
// 	packet[20]=0x00;
// 	packet[21]=79;//length
// 	// 保留4个字节
// 	//Reserved1
// 	packet[22]=0x00;
// 	packet[23]=0x00;
// 	//Reserved2
// 	packet[24]=0x00;
// 	packet[25]=0x00;
// //APDU 应用协议数据单元 一个 APDU可以由多个 ASDU链接而成。
// 	/* IEC 61850-9-2 采样值报文  APDU部分*/
// 	//Tag+length IEC 61850-9-2
// 	packet[26]=0x60;////APDU 标记（=0x60） 9-2
// ////////////////////////////////////////////////////////////////////////////
//  /*可能需要修改*/
// 	packet[27]=69;//APDU长度
// 	//Asdu num
// 	packet[28]=0x80;//ASDU数目 标记（=0x80）
//  /*可能需要修改*/
// 	packet[29]=0x01;//ASDU数目 长度
//     packet[30]=0x02;//ASDU数目 值（=1）  类型  INT16U 编码为 asn.1 整型编码
//     //Asdus head
// 	packet[31]=0xa2;//ASDU序列 标记（=0xA2）
//  /*可能需要修改*/
// 	packet[32]=64;//length //Sequence of ASDU 长度
// 		
// 	//Asdu1 head
// 	packet[33]=0x30;//ASDU 标记（=0x30）
//  /*可能需要修改*/
// 	packet[34]=30;//length //ASDU 长度 
// //Asdu1 ID
// 	packet[35]=0x80;//采样值控制块 ID  标记（=0x80）
// 	packet[36]=0x01;//采样值控制块 ID  长度 
// 	packet[37]=86;//V  //采样值控制块 ID  值 	类型：VISBLE STRING 编码为 asn.1 VISBLE STRING 编码
// 	//Dataset  这块内容是什么？标记为81
// 	packet[38]=0x81;
// 	packet[39]=0x03;
// 	packet[40]=68;//DSV
// 	packet[41]=83;
// 	packet[42]=86;
//     //sample count
// 	packet[43]=0x82;//采样计数器 标记（=0x82）
// 	packet[44]=0x02;//采样计数器 长度
// 	packet[45]=0x23;//采样计数器 值 		类型  INT16U  编码为 16 Bit Big Endian 
// 	packet[46]=0x56;
// 	//sample rate 这块内容是什么？标记为86
// 	packet[47]=0x86;
// 	packet[48]=0x02;
// 	packet[49]=0x00;
// 	packet[50]=0x30;
// 	
// 	//sampledata
// 	packet[51]=0x87;//采样值序列标记（=0x87）
// 	packet[52]=0x0c;//样值序列 长度 0x0c=12
// 	
// 	//channel_1
// 	packet[53]=0x00;
// 	packet[54]=0x00;
// 	packet[55]=0x13;
// 	packet[56]=0x74;//4980
// 	//channel_2
// 	packet[57]=0x00;
// 	packet[58]=0x00;
// 	packet[59]=0x00;
// 	packet[60]=0x00;
// 	//channel_3
// 	packet[61]=0x00;
// 	packet[62]=0x00;
// 	packet[63]=0x00;
// 	packet[64]=0x00;
// 	
// //Asdu2 head
// 	packet[65]=0x30;
// 	packet[66]=30;//length
// 	//Asdu1 ID
// 	packet[67]=0x80;
// 	packet[68]=0x01;
// 	packet[69]=65;//A
// 	//Dataset
// 	packet[70]=0x81;
// 	packet[71]=0x03;
// 	packet[72]=68;//DSA
// 	packet[73]=83;
// 	packet[74]=65;
//     //samplecount
// 	packet[75]=0x82;
// 	packet[76]=0x02;
// 	packet[77]=0x23;
// 	packet[78]=0x56;
// 	//samplerate
// 	packet[79]=0x86;
// 	packet[80]=0x02;
// 	packet[81]=0x00;
// 	packet[82]=0x30;
// 	
// 	//sampledata
// 	packet[83]=0x87;
// 	packet[84]=0x0c;
// 	
// 	//channel_1
// 	packet[85]=0x00;
// 	packet[86]=0x00;
// 	packet[87]=0x13;
// 	packet[88]=0x7e;//4990
// 	//channel_2
// 	packet[89]=0x00;
// 	packet[90]=0x00;
// 	packet[91]=0x00;
// 	packet[92]=0x00;
// 	//channel_3
// 	packet[93]=0x00;
// 	packet[94]=0x00;
// 	packet[95]=0x00;
// 	packet[96]=0x00;
// }

void CSend1Dlg::SetSin(float A,float B,float C,int PhaseA,float D,float E,float F,int PhaseD)//产生波形
{
	if (packet2send.smpCount==0)
	{
// 		QueryPerformanceCounter(&litmp); 
// 		QPart_ini = litmp.QuadPart; 
		msec=0-interval;
	}

////  	QueryPerformanceCounter(&litmp); 
 	// 获得初始值 
//// 	QPart3 = litmp.QuadPart; 
//  	Sleep(100) ; 
//  	QueryPerformanceCounter(&litmp); 
//  	// 获得终止值 
//  	QPart2 = litmp.QuadPart; 
//  	dfMinus = (double)(QPart2 - QPart1); 
//  	dfTim = dfMinus / dfFreq; 
//  	// 获得对应的时间值 
// 	msec=::GetTickCount();

	msec+=interval;/*(double)(QPart3-QPart_ini)/dfFreq;*/
//  	msec=QPart3/1e11;//设置为秒
// 	msec=QPart3/dfFreq;//设置为秒

	if(fault_switch==true)
	{
		switch (fault_flg)
		{
		case k3:
			packet2send.data_to_send.currentA=
				100/(double)(f_left+2)*A*cos(2*PI*50*msec+(PhaseA+driftA-90)*PI/180)+
				(A*cos((-90*PI)/180)-100/(double)(f_left+2)*A*cos((-90*PI)/180))*exp(-msec/0.02);


			packet2send.data_to_send.currentB=
				100/(double)(f_left+2)*B*cos(2*PI*50*msec+(PhaseA+driftB-90-120)*PI/180)+
				(B*cos((-90-120)*PI/180)-100/(double)(f_left+2)*B*cos((-90-120)*PI/180))*exp(-msec/0.02);

			packet2send.data_to_send.currentC=
				100/(double)(f_left+2)*C*cos(2*PI*50*msec+(PhaseA+driftC-90+120)*PI/180)+
				(C*cos((-90+120)*PI/180)-100/(double)(f_left+2)*C*cos((-90+120)*PI/180))*exp(-msec/0.02);
			
			packet2send.data_to_send.VoltageA=0;
			packet2send.data_to_send.VoltageB=0;
			packet2send.data_to_send.VoltageC=0;

			break;
		case k1:
			switch (fault_p)
			{
			case fa:
// 				packet2send.data_to_send.currentA=sqrt(2)*A*2*PI*50*1e-1*
// 					((sin(pfi)*sin(2*PI*50*msec)-cos(pfi)*cos(2*PI*50*msec))*exp(-msec/100)+cos(2*PI*50*msec+pfi));
// 					+A/(2*PI*50*10)*(cos(pfi)*exp(-msec/100)-cos(2*PI*50*msec+pfi));
				packet2send.data_to_send.VoltageA=0;
				packet2send.data_to_send.VoltageB=sqrt(3)*E*cos(2*PI*(50+f_Vb)*msec+(PhaseD-150+driftB)*PI/180);
				packet2send.data_to_send.VoltageC=sqrt(3)*F*cos(2*PI*(50+f_Vc)*msec+(PhaseD+150+driftC)*PI/180);

				packet2send.data_to_send.currentB=2*PI*50*1e-3 * sqrt(3)*E*cos(2*PI*(50+f_Vb)*msec+(PhaseD-150+90+driftB)*PI/180);
				packet2send.data_to_send.currentC=2*PI*50*1e-3 * sqrt(3)*F*cos(2*PI*(50+f_Vc)*msec+(PhaseD+150-90+driftC)*PI/180);	
				packet2send.data_to_send.currentA=packet2send.data_to_send.currentB+packet2send.data_to_send.currentC;

				break;
			case fb:

				packet2send.data_to_send.VoltageA=sqrt(3)*D*cos(2*PI*(50+f_Va)*msec+(PhaseD+150+driftA)*PI/180);
				packet2send.data_to_send.VoltageB=0;
				packet2send.data_to_send.VoltageC=sqrt(3)*F*cos(2*PI*(50+f_Vc)*msec+(PhaseD-150+driftC)*PI/180);
				
				packet2send.data_to_send.currentA=2*PI*50*1e-3 * sqrt(3)*D*cos(2*PI*(50+f_Va)*msec+(PhaseD+150+90+driftA)*PI/180);
				packet2send.data_to_send.currentC=2*PI*50*1e-3 * sqrt(3)*F*cos(2*PI*(50+f_Vc)*msec+(PhaseD-150+90+driftC)*PI/180);
				packet2send.data_to_send.currentB=packet2send.data_to_send.currentA+packet2send.data_to_send.currentC;

				break;
			case fc:

				packet2send.data_to_send.VoltageA=sqrt(3)*D*cos(2*PI*(50+f_Va)*msec+(PhaseD-150+driftA)*PI/180);
				packet2send.data_to_send.VoltageB=sqrt(3)*E*cos(2*PI*(50+f_Vb)*msec+(PhaseD+150+driftB)*PI/180);
				packet2send.data_to_send.VoltageC=0;

				packet2send.data_to_send.currentA=2*PI*50*1e-3 * sqrt(3)*D*cos(2*PI*(50+f_Va)*msec+(PhaseD-150+90+driftA)*PI/180);
				packet2send.data_to_send.currentB=2*PI*50*1e-3 * sqrt(3)*E*cos(2*PI*(50+f_Vb)*msec+(PhaseD+150+90+driftB)*PI/180);
				packet2send.data_to_send.currentC=packet2send.data_to_send.currentA+packet2send.data_to_send.currentB;

				break;
			}
			break;
		case k2:
			switch (fault_p)
			{
			case fab:
				break;
			case fac:
				break;
			case fbc:
				break;
			}
			break;
		case k11:
			switch (fault_p)
			{
			case fab:
				break;
			case fac:
				break;
			case fbc:
				break;
			}
			break;
		case d1:
			switch (fault_p)
			{
			case fa:
				break;
			case fb:
				break;
			case fc:
				break;
			}
			break;
		case d2:
			switch (fault_p)
			{
			case fab:
				break;
			case fac:
				break;
			case fbc:
				break;
			}
			break;
		}
	}
	else//正常波形在此
	{
		packet2send.data_to_send.currentA=A*cos(2*PI*(50+f_Aa)*msec+(PhaseA+driftA)*PI/180);
		packet2send.data_to_send.currentB=B*cos(2*PI*(50+f_Ab)*msec+(PhaseA-120+driftB)*PI/180);
		packet2send.data_to_send.currentC=C*cos(2*PI*(50+f_Ac)*msec+(PhaseA+120+driftC)*PI/180);
		
		packet2send.data_to_send.VoltageA=D*cos(2*PI*(50+f_Va)*msec+(PhaseD+driftA)*PI/180);
		packet2send.data_to_send.VoltageB=E*cos(2*PI*(50+f_Vb)*msec+(PhaseD-120+driftB)*PI/180);
		packet2send.data_to_send.VoltageC=F*cos(2*PI*(50+f_Vc)*msec+(PhaseD+120+driftC)*PI/180);
	}

}

void CSend1Dlg::OnChangeEdit1_am_Aa() 
{
	// TODO: If this is a RICHEDIT control, the control will not
	// send this notification unless you override the CDialog::OnInitDialog()
	// function and call CRichEditCtrl().SetEventMask()
	// with the ENM_CHANGE flag ORed into the mask.

	// TODO: Add your control notification handler code here
	CString am;
	m_am_Aa.GetWindowText(am);
	packet2send.data_to_send.am_Aa=sqrt(2)*atof(am);
}

void CSend1Dlg::OnChangeEdit2_am_Ab() 
{
	// TODO: If this is a RICHEDIT control, the control will not
	// send this notification unless you override the CDialog::OnInitDialog()
	// function and call CRichEditCtrl().SetEventMask()
	// with the ENM_CHANGE flag ORed into the mask.
	
	// TODO: Add your control notification handler code here
	CString am;
	m_am_Ab.GetWindowText(am);
	packet2send.data_to_send.am_Ab=sqrt(2)*atof(am);

}

void CSend1Dlg::OnChangeEdit3_am_Ac() 
{
	// TODO: If this is a RICHEDIT control, the control will not
	// send this notification unless you override the CDialog::OnInitDialog()
	// function and call CRichEditCtrl().SetEventMask()
	// with the ENM_CHANGE flag ORed into the mask.
	
	// TODO: Add your control notification handler code here
	CString am;
	m_am_Ac.GetWindowText(am);
	packet2send.data_to_send.am_Ac=sqrt(2)*atof(am);	
}

void CSend1Dlg::OnRadio_Aabc() 
{
	// TODO: Add your control notification handler code here
	wav_A_flg=0;
	GetDlgItem(IDC_PLOT_CURRENT_A)->ShowWindow(!SW_HIDE);
//	SetBkMode(GetDlgItem(IDC_PLOT_CURRENT_A),TRANSPARENT);
	GetDlgItem(IDC_PLOT_CURRENT_B)->ShowWindow(!SW_HIDE);
	GetDlgItem(IDC_PLOT_CURRENT_C)->ShowWindow(!SW_HIDE);
	GetDlgItem(IDC_PLOT_CURRENT_ABC)->ShowWindow(SW_HIDE);
}

void CSend1Dlg::OnRadio_Aa() 
{
	// TODO: Add your control notification handler code here
	wav_A_flg=1;
	GetDlgItem(IDC_PLOT_CURRENT_A)->ShowWindow(SW_HIDE);
	GetDlgItem(IDC_PLOT_CURRENT_B)->ShowWindow(SW_HIDE);
	GetDlgItem(IDC_PLOT_CURRENT_C)->ShowWindow(SW_HIDE);
	GetDlgItem(IDC_PLOT_CURRENT_ABC)->ShowWindow(!SW_HIDE);
	m_current_abc.SetTitle("A相电流:");

}

void CSend1Dlg::OnRadio_Ab() 
{
	// TODO: Add your control notification handler code here
	wav_A_flg=2;
	GetDlgItem(IDC_PLOT_CURRENT_A)->ShowWindow(SW_HIDE);
	GetDlgItem(IDC_PLOT_CURRENT_B)->ShowWindow(SW_HIDE);
	GetDlgItem(IDC_PLOT_CURRENT_C)->ShowWindow(SW_HIDE);
	GetDlgItem(IDC_PLOT_CURRENT_ABC)->ShowWindow(!SW_HIDE);
	m_current_abc.SetTitle("B相电流:");
}

void CSend1Dlg::OnRadio_Ac() 
{
	// TODO: Add your control notification handler code here
	wav_A_flg=3;
	GetDlgItem(IDC_PLOT_CURRENT_A)->ShowWindow(SW_HIDE);
	GetDlgItem(IDC_PLOT_CURRENT_B)->ShowWindow(SW_HIDE);
	GetDlgItem(IDC_PLOT_CURRENT_C)->ShowWindow(SW_HIDE);
	GetDlgItem(IDC_PLOT_CURRENT_ABC)->ShowWindow(!SW_HIDE);
	m_current_abc.SetTitle("C相电流:");
}
void CSend1Dlg::OnRadio_Ashut() 
{
	// TODO: Add your control notification handler code here
	wav_A_flg=4;
	GetDlgItem(IDC_PLOT_CURRENT_A)->ShowWindow(SW_HIDE);
	GetDlgItem(IDC_PLOT_CURRENT_B)->ShowWindow(SW_HIDE);
	GetDlgItem(IDC_PLOT_CURRENT_C)->ShowWindow(SW_HIDE);
	GetDlgItem(IDC_PLOT_CURRENT_ABC)->ShowWindow(SW_HIDE);
	//	m_current_abc.SetTitle("C相电流:");
}

DWORD WINAPI ThreadFunc_Timer(LPVOID lpParam){
	CSend1Dlg *DlgThis=(CSend1Dlg *)lpParam;
// 	while(WaitForSingleObject(HTimer.TimerHandle(),HTimer.g_TimerPeriod*2)==WAIT_OBJECT_0){
// 	while(1)
// 	{
// 		Pool.Run(ThreadFunc_Send,DlgThis);
// // 		MessageBox(NULL,"ads","das",MB_OK);
// 	}
	
// 	CString str="";
// 	CString str1="";
// 	msec=0;

	interval=(double)0.02/(packet2send.smpRate);
	double p=interval;
	int last=0;
	int now;
	int delt=packet2send.smpRate/0.02;
	int display=0;
	p-=p/15;
//	p=p/5;
//  p=1e-12;
	while (1)
	{
		QueryPerformanceCounter(&litmp); 
		QPart1 = litmp.QuadPart; 
		QPart4 = litmp.QuadPart;
		while (1)
		{
re:			QueryPerformanceCounter(&litmp);
			QPart2 = litmp.QuadPart;
			if( (double)(QPart2 - QPart1)/dfFreq > p ){//0.1ms 发一个
// 				ResumeThread(DlgThis->hThread_send);
//  			CreateThread(NULL,0,(LPTHREAD_START_ROUTINE)ThreadFunc_Send,DlgThis,0,NULL/*&DlgThis->ThreadID_send*/);
				Pool.Run(ThreadFunc_Send,DlgThis);
				break;
			}
		}
		if ((double)(QPart2 - QPart4)/dfFreq >= 1)
		{
			strtemp.Format("%d",packet2send.smpCount/*display+=delt*/);
			DlgThis->m_smpcount.SetWindowText(strtemp);

			now=packet2send.smpCount;
			if(now-last>delt)
				p+=p/16;
			else 
				p-=p/16;
			last=now;
//			last=packet2send.smpCount;
// 			strtemp.Format("%d",itemp);
// 			DlgThis->m_am_Vn.SetWindowText(strtemp);

			QueryPerformanceCounter(&litmp); 
			QPart4 = litmp.QuadPart; 
//			SuspendThread(DlgThis->hThread_timer);
		}

// 		str1.Format("%f",(double)QPart4/*(QPart2 - QPart3)/dfFreq*/);
// 		str1=str1+"  "+str;
// 		DlgThis->m_am_Vb.SetWindowText(str1);
		while (1)
		{
			QueryPerformanceCounter(&litmp);
			QPart1 = litmp.QuadPart;
			if( (double)(QPart1 - QPart2)/dfFreq > p ){//0.1ms 发一个
// 				ResumeThread(DlgThis->hThread_send);
//  				CreateThread(NULL,0,(LPTHREAD_START_ROUTINE)ThreadFunc_Send,DlgThis,0,NULL/*&DlgThis->ThreadID_send*/);
				Pool.Run(ThreadFunc_Send,DlgThis);
				break;
			}
		}
		if ((double)(QPart1 - QPart4)/dfFreq >= 1)
		{
			strtemp.Format("%d",packet2send.smpCount/*display+=delt*/);
			DlgThis->m_smpcount.SetWindowText(strtemp);
			now=packet2send.smpCount;
			if(now-last>delt)
				p+=p/16;
			else 
				p-=p/16;
			last=now;
// 			strtemp.Format("%d",itemp);
// 			DlgThis->m_am_Vn.SetWindowText(strtemp);

			QueryPerformanceCounter(&litmp); 
			QPart4 = litmp.QuadPart; 
//			SuspendThread(DlgThis->hThread_timer);
		}
		if (m_bRun==FALSE /*|| packet2send.smpCount>62000*/)
		{
// 			strtemp.Format("%d",itemp);
// 			DlgThis->m_am_An.SetWindowText(strtemp);
			strtemp.Format("%d",packet2send.smpCount);
			DlgThis->m_smpcount.SetWindowText(strtemp);
			SuspendThread(DlgThis->hThread_timer);
		}
		else {
			ResumeThread(DlgThis->hThread_timer);
		}
goto re;		

// 		str.Format("%f",(double)(QPart1 - QPart2)/dfFreq);
//  		DlgThis->m_am_Vb.SetWindowText(str1);

return 0;
	}
}
UINT ThreadFunc(LPVOID lpParam)
{
	strtemp.Format("%d",itemp++);
	CSend1Dlg *DlgThis=(CSend1Dlg *)lpParam;
	DlgThis->m_am_Va.SetWindowText(strtemp);
	return 0;
}

//DEL void CSend1Dlg::DataSet_32(float value, unsigned char *des)
//DEL {
//DEL 	float *p_f=&value;
//DEL 	unsigned char *src=(unsigned char *)p_f;
//DEL 	memcpy(des,src+3,8);
//DEL 	memcpy(des+1,src+2,8);
//DEL 	memcpy(des+2,src+1,8);
//DEL 	memcpy(des+3,src,8);
//DEL }

void CSend1Dlg::OnCheck1_ChangeSrcMac() 
{
	// TODO: Add your control notification handler code here
// 	GetDlgItem(IDC_EDIT_soumac)->SetReadOnly(FALSE);
	if (m_check_src.GetCheck()==false)
	{
		m_soumac.SetReadOnly(true);
	}
	else
		m_soumac.SetReadOnly(FALSE);

}

void CSend1Dlg::OnChangeEDITsoumac() 
{
	// TODO: If this is a RICHEDIT control, the control will not
	// send this notification unless you override the CDialog::OnInitDialog()
	// function and call CRichEditCtrl().SetEventMask()
	// with the ENM_CHANGE flag ORed into the mask.
	
	// TODO: Add your control notification handler code here
	m_soumac.GetWindowText(soumac);
	soumac_len=soumac.GetLength();
	//12:12:12:12:12:12
	if(soumac_len<=17)
		soumac_temp=soumac;
	else {
		m_soumac.SetWindowText(soumac_temp);
		soumac=soumac_temp;
		m_soumac.SetSel(-1);//是光标放在最后
	}
	if(soumac_len==2 || soumac_len==5 || soumac_len==8 || soumac_len==11 || soumac_len==14){
		soumac+=":";
		m_soumac.SetWindowText(soumac);
		m_soumac.SetSel(-1);//是光标放在最后
	}
	sscanf(soumac,"%x:%x:%x:%x:%x:%x",&packet2send.packet[6],&packet2send.packet[7],&packet2send.packet[8],&packet2send.packet[9],&packet2send.packet[10],&packet2send.packet[11]);
}

void CSend1Dlg::OnChangeEdit4_am_Va() 
{
	// TODO: If this is a RICHEDIT control, the control will not
	// send this notification unless you override the CDialog::OnInitDialog()
	// function and call CRichEditCtrl().SetEventMask()
	// with the ENM_CHANGE flag ORed into the mask.
	
	// TODO: Add your control notification handler code here
	CString am;
	m_am_Va.GetWindowText(am);
	packet2send.data_to_send.am_Va=sqrt(2)*atof(am);
}

void CSend1Dlg::OnChangeEdit5_am_Vb() 
{
	// TODO: If this is a RICHEDIT control, the control will not
	// send this notification unless you override the CDialog::OnInitDialog()
	// function and call CRichEditCtrl().SetEventMask()
	// with the ENM_CHANGE flag ORed into the mask.
	
	// TODO: Add your control notification handler code here
	CString am;
	m_am_Vb.GetWindowText(am);
	packet2send.data_to_send.am_Vb=sqrt(2)*atof(am);
}

void CSend1Dlg::OnChangeEdit6_am_Vc() 
{
	// TODO: If this is a RICHEDIT control, the control will not
	// send this notification unless you override the CDialog::OnInitDialog()
	// function and call CRichEditCtrl().SetEventMask()
	// with the ENM_CHANGE flag ORed into the mask.
	
	// TODO: Add your control notification handler code here
	CString am;
	m_am_Vc.GetWindowText(am);
	packet2send.data_to_send.am_Vc=sqrt(2)*atof(am);
}

void CSend1Dlg::OnRadio_Vabc() 
{
	// TODO: Add your control notification handler code here
	wav_V_flg=0;
	GetDlgItem(IDC_PLOT_VOLTAGE_A)->ShowWindow(!SW_HIDE);
	//	SetBkMode(GetDlgItem(IDC_PLOT_CURRENT_A),TRANSPARENT);
	GetDlgItem(IDC_PLOT_VOLTAGE_B)->ShowWindow(!SW_HIDE);
	GetDlgItem(IDC_PLOT_VOLTAGE_C)->ShowWindow(!SW_HIDE);
	GetDlgItem(IDC_PLOT_VOLTAGE_ABC)->ShowWindow(SW_HIDE);

}

void CSend1Dlg::OnRadio_Va() 
{
	// TODO: Add your control notification handler code here
	wav_V_flg=1;
	GetDlgItem(IDC_PLOT_VOLTAGE_A)->ShowWindow(SW_HIDE);
	GetDlgItem(IDC_PLOT_VOLTAGE_B)->ShowWindow(SW_HIDE);
	GetDlgItem(IDC_PLOT_VOLTAGE_C)->ShowWindow(SW_HIDE);
	GetDlgItem(IDC_PLOT_VOLTAGE_ABC)->ShowWindow(!SW_HIDE);
	m_voltage_abc.SetTitle("A相电压:");
}

void CSend1Dlg::OnRadio_Vb() 
{
	// TODO: Add your control notification handler code here
	wav_V_flg=2;
	GetDlgItem(IDC_PLOT_VOLTAGE_A)->ShowWindow(SW_HIDE);
	GetDlgItem(IDC_PLOT_VOLTAGE_B)->ShowWindow(SW_HIDE);
	GetDlgItem(IDC_PLOT_VOLTAGE_C)->ShowWindow(SW_HIDE);
	GetDlgItem(IDC_PLOT_VOLTAGE_ABC)->ShowWindow(!SW_HIDE);
	m_voltage_abc.SetTitle("B相电压:");

}

void CSend1Dlg::OnRadio_Vc() 
{
	// TODO: Add your control notification handler code here
	wav_V_flg=3;
	GetDlgItem(IDC_PLOT_VOLTAGE_A)->ShowWindow(SW_HIDE);
	GetDlgItem(IDC_PLOT_VOLTAGE_B)->ShowWindow(SW_HIDE);
	GetDlgItem(IDC_PLOT_VOLTAGE_C)->ShowWindow(SW_HIDE);
	GetDlgItem(IDC_PLOT_VOLTAGE_ABC)->ShowWindow(!SW_HIDE);
	m_voltage_abc.SetTitle("C相电压:");

}

void CSend1Dlg::OnRadio_Vshut() 
{
	// TODO: Add your control notification handler code here
	wav_V_flg=4;
	GetDlgItem(IDC_PLOT_VOLTAGE_A)->ShowWindow(SW_HIDE);
	GetDlgItem(IDC_PLOT_VOLTAGE_B)->ShowWindow(SW_HIDE);
	GetDlgItem(IDC_PLOT_VOLTAGE_C)->ShowWindow(SW_HIDE);
	GetDlgItem(IDC_PLOT_VOLTAGE_ABC)->ShowWindow(SW_HIDE);

}

void CSend1Dlg::ShowWave()
{
	if (wav_A_flg!=4 && packet2send.smpCount%sliderA==0)
	{
		//波形显示
		if(wav_A_flg==0){
			m_current_a.SetData(packet2send.data_to_send.currentA);
			m_current_b.SetData(packet2send.data_to_send.currentB);
			m_current_c.SetData(packet2send.data_to_send.currentC);
		}
		else if (wav_A_flg==1)
		{
			m_current_abc.SetData(packet2send.data_to_send.currentA);
		}
		else if (wav_A_flg==2)
		{
			m_current_abc.SetData(packet2send.data_to_send.currentB);
		}
		else if (wav_A_flg==3)
		{
			m_current_abc.SetData(packet2send.data_to_send.currentC);
		}
	}
	if (wav_V_flg!=4 && packet2send.smpCount%sliderV==0)
	{
		//波形显示
		if(wav_V_flg==0){
			m_voltage_a.SetData(packet2send.data_to_send.VoltageA);
			m_voltage_b.SetData(packet2send.data_to_send.VoltageB);
			m_voltage_c.SetData(packet2send.data_to_send.VoltageC);
		}
		else if (wav_V_flg==1)
		{
			m_voltage_abc.SetData(packet2send.data_to_send.VoltageA);
		}
		else if (wav_V_flg==2)
		{
			m_voltage_abc.SetData(packet2send.data_to_send.VoltageB);
		}
		else if (wav_V_flg==3)
		{
			m_voltage_abc.SetData(packet2send.data_to_send.VoltageC);
		}
	}
}

void CSend1Dlg::OnCustomdrawSliderA(NMHDR* pNMHDR, LRESULT* pResult) 
{
	// TODO: Add your control notification handler code here
	sliderA=m_slider_a.GetPos();
	*pResult = 0;
}

void CSend1Dlg::OnCustomdrawSliderV(NMHDR* pNMHDR, LRESULT* pResult) 
{
	// TODO: Add your control notification handler code here
	sliderV=m_slider_v.GetPos();
	*pResult = 0;
}

BOOL CSend1Dlg::DestroyWindow() 
{
	// TODO: Add your specialized code here and/or call the base class
	pcap_freealldevs(alldevs);
	SuspendThread(hThread_timer);
	Pool.Destroy();
/*	packet2send.~Packet();*/

	return CDialog::DestroyWindow();
}

void CSend1Dlg::OnChangeEdit9_driftA() 
{
	// TODO: If this is a RICHEDIT control, the control will not
	// send this notification unless you override the CDialog::OnInitDialog()
	// function and call CRichEditCtrl().SetEventMask()
	// with the ENM_CHANGE flag ORed into the mask.
	
	// TODO: Add your control notification handler code here
	CString am;
	m_phaseA_drift.GetWindowText(am);
	driftA=atof(am);
}

void CSend1Dlg::OnChangeEdit10_driftB() 
{
	// TODO: If this is a RICHEDIT control, the control will not
	// send this notification unless you override the CDialog::OnInitDialog()
	// function and call CRichEditCtrl().SetEventMask()
	// with the ENM_CHANGE flag ORed into the mask.
	
	// TODO: Add your control notification handler code here
	CString am;
	m_phaseB_drift.GetWindowText(am);
	driftB=atof(am);
}

void CSend1Dlg::OnChangeEdit11_driftC() 
{
	// TODO: If this is a RICHEDIT control, the control will not
	// send this notification unless you override the CDialog::OnInitDialog()
	// function and call CRichEditCtrl().SetEventMask()
	// with the ENM_CHANGE flag ORed into the mask.
	
	// TODO: Add your control notification handler code here
	CString am;
	m_phaseC_drift.GetWindowText(am);
	driftC=atof(am);
}

void CSend1Dlg::OnRADIOk3() 
{
	// TODO: Add your control notification handler code here
	fault_flg=k3;
	fault_p=fabc;
	m_fa.SetCheck(true);
	m_fb.SetCheck(true);
	m_fc.SetCheck(true);
	GetDlgItem(IDC_CHECK_fa)->EnableWindow(FALSE);
	GetDlgItem(IDC_CHECK_fb)->EnableWindow(FALSE);
	GetDlgItem(IDC_CHECK_fc)->EnableWindow(FALSE);

}

void CSend1Dlg::OnRADIOk1() 
{
	// TODO: Add your control notification handler code here
	GetDlgItem(IDC_CHECK_fa)->EnableWindow(true);
	GetDlgItem(IDC_CHECK_fb)->EnableWindow(true);
	GetDlgItem(IDC_CHECK_fc)->EnableWindow(true);
	fault_flg=k1;
	fault_p=fa;
	m_fa.SetCheck(true);
	m_fb.SetCheck(false);
	m_fc.SetCheck(false);
}

void CSend1Dlg::OnRADIOk2() 
{
	// TODO: Add your control notification handler code here
	GetDlgItem(IDC_CHECK_fa)->EnableWindow(true);
	GetDlgItem(IDC_CHECK_fb)->EnableWindow(true);
	GetDlgItem(IDC_CHECK_fc)->EnableWindow(true);
	fault_flg=k2;
	fault_p=fbc;
	m_fa.SetCheck(false);
	m_fb.SetCheck(true);
	m_fc.SetCheck(true);
}

void CSend1Dlg::OnRADIOk11() 
{
	// TODO: Add your control notification handler code here
	GetDlgItem(IDC_CHECK_fa)->EnableWindow(true);
	GetDlgItem(IDC_CHECK_fb)->EnableWindow(true);
	GetDlgItem(IDC_CHECK_fc)->EnableWindow(true);
	fault_flg=k11;
	fault_p=fbc;
	m_fa.SetCheck(false);
	m_fb.SetCheck(true);
	m_fc.SetCheck(true);
}

void CSend1Dlg::OnRADIOd1() 
{
	// TODO: Add your control notification handler code here
	GetDlgItem(IDC_CHECK_fa)->EnableWindow(true);
	GetDlgItem(IDC_CHECK_fb)->EnableWindow(true);
	GetDlgItem(IDC_CHECK_fc)->EnableWindow(true);
	fault_flg=d1;
	fault_p=fa;
	m_fa.SetCheck(true);
	m_fb.SetCheck(false);
	m_fc.SetCheck(false);

}

void CSend1Dlg::OnRADIOd2() 
{
	// TODO: Add your control notification handler code here
	GetDlgItem(IDC_CHECK_fa)->EnableWindow(true);
	GetDlgItem(IDC_CHECK_fb)->EnableWindow(true);
	GetDlgItem(IDC_CHECK_fc)->EnableWindow(true);
	fault_flg=d2;
	fault_p=fbc;
	m_fa.SetCheck(false);
	m_fb.SetCheck(true);
	m_fc.SetCheck(true);
}
void CSend1Dlg::OnCHECKfa() 
{
	// TODO: Add your control notification handler code here
	if (fault_flg==k1 || fault_flg==d1)
	{
		if (m_fa.GetCheck()==false && m_fb.GetCheck()==false && m_fc.GetCheck()==false)
		{
			m_fa.SetCheck(true);
			fault_p=fa;
		}
		if (m_fa.GetCheck()==true && m_fb.GetCheck()==true && m_fc.GetCheck()==false)
		{
			m_fb.SetCheck(false);
			fault_p=fa;
		}
		if (m_fa.GetCheck()==true && m_fb.GetCheck()==false && m_fc.GetCheck()==true)
		{
			m_fc.SetCheck(false);
			fault_p=fa;
		}
	}
	else if (fault_flg==k2 || fault_flg==k11 || fault_flg==d2)
	{
		if (m_fa.GetCheck()==true && m_fb.GetCheck()==true && m_fc.GetCheck()==true)
		{
			switch ((fault_pswitch++)%2)
			{
			case 0:
				m_fb.SetCheck(false);
				fault_p=fac;
				break;
			case 1:
				m_fc.SetCheck(false);
				fault_p=fab;
				break;
			}

		}
		if (m_fa.GetCheck()==false && m_fb.GetCheck()==true && m_fc.GetCheck()==false)
		{
			m_fa.SetCheck(true);
			fault_p=fab;
		}
		if (m_fa.GetCheck()==false && m_fb.GetCheck()==false && m_fc.GetCheck()==true)
		{
			m_fa.SetCheck(true);
			fault_p=fac;
		}
	}
}

void CSend1Dlg::OnCHECKfb() 
{
	// TODO: Add your control notification handler code here
	if (fault_flg==k1 || fault_flg==d1)
	{
		if (m_fa.GetCheck()==false && m_fb.GetCheck()==false && m_fc.GetCheck()==false)
		{
			m_fb.SetCheck(true);
			fault_p=fb;
		}
		if (m_fa.GetCheck()==true && m_fb.GetCheck()==true && m_fc.GetCheck()==false)
		{
			m_fa.SetCheck(false);
			fault_p=fb;
		}
		if (m_fa.GetCheck()==false && m_fb.GetCheck()==true && m_fc.GetCheck()==true)
		{
			m_fc.SetCheck(false);
			fault_p=fb;
		}
	}
	else if (fault_flg==k2 || fault_flg==k11 || fault_flg==d2)
	{
		if (m_fa.GetCheck()==true && m_fb.GetCheck()==true && m_fc.GetCheck()==true)
		{
			switch ((fault_pswitch++)%2)
			{
			case 0:
				m_fa.SetCheck(false);
				fault_p=fbc;
				fault_pswitch++;
				break;
			case 1:
				m_fc.SetCheck(false);
				fault_p=fab;
				fault_pswitch++;
				break;
			}	
		}
		if (m_fa.GetCheck()==true && m_fb.GetCheck()==false && m_fc.GetCheck()==false)
		{
			m_fb.SetCheck(true);
			fault_p=fab;
		}
		if (m_fa.GetCheck()==false && m_fb.GetCheck()==false && m_fc.GetCheck()==true)
		{
			m_fb.SetCheck(true);
			fault_p=fbc;
		}
	}
}

void CSend1Dlg::OnCHECKfc() 
{
	// TODO: Add your control notification handler code here
	if (fault_flg==k1 || fault_flg==d1)
	{
		if (m_fa.GetCheck()==false && m_fb.GetCheck()==false && m_fc.GetCheck()==false)
		{
			m_fc.SetCheck(true);
			fault_p=fc;
		}
		if (m_fa.GetCheck()==true && m_fb.GetCheck()==false && m_fc.GetCheck()==true)
		{
			m_fa.SetCheck(false);
			fault_p=fc;
		}
		if (m_fa.GetCheck()==false && m_fb.GetCheck()==true && m_fc.GetCheck()==true)
		{
			m_fb.SetCheck(false);
			fault_p=fc;
		}
	}
	else if (fault_flg==k2 || fault_flg==k11 || fault_flg==d2)
	{
		if (m_fa.GetCheck()==true && m_fb.GetCheck()==true && m_fc.GetCheck()==true)
		{
			switch ((fault_pswitch++)%2)
			{
			case 0:
				m_fb.SetCheck(false);
				fault_p=fac;
//				fault_pswitch++;
				break;
			case 1:
				m_fa.SetCheck(false);
				fault_p=fbc;
//				fault_pswitch++;
				break;
			}
		}
		if (m_fa.GetCheck()==true && m_fb.GetCheck()==false && m_fc.GetCheck()==false)
		{
			m_fc.SetCheck(true);
			fault_p=fac;
		}
		if (m_fa.GetCheck()==false && m_fb.GetCheck()==true && m_fc.GetCheck()==false)
		{
			m_fc.SetCheck(true);
			fault_p=fbc;
		}
	}

}

void CSend1Dlg::OnBUTTONfaulton() 
{
	// TODO: Add your control notification handler code here
	fault_switch=true;
// 	QueryPerformanceCounter(&litmp); 
// 	QPart_ini = litmp.QuadPart; 
// 	alpha=(2*PI*50*msec+(0+driftA)*PI/180);
// 	i0=packet2send.data_to_send.am_Ab*cos(2*PI*50*msec+(0+driftA)*PI/180);
	pfi=2*PI*(50+f_Aa)*msec+(driftA)*PI/180;
	msec=0-interval;
	GetDlgItem(IDC_BUTTON_faultoff)->EnableWindow(true);
	GetDlgItem(IDC_BUTTON_faulton)->EnableWindow(FALSE);

}

void CSend1Dlg::OnBUTTONfaultoff() 
{
	// TODO: Add your control notification handler code here
	fault_switch=false;
	GetDlgItem(IDC_BUTTON_faulton)->EnableWindow(true);
	GetDlgItem(IDC_BUTTON_faultoff)->EnableWindow(FALSE);

}

void CSend1Dlg::OnDropdownCOMBOadd() 
{
	// TODO: Add your control notification handler code here
	m_addList.ResetContent();
	CString list="";
	int index=0;
	list="A相电流";
	m_addList.InsertString(index++,list);
	list="B相电流";
	m_addList.InsertString(index++,list);
	list="C相电流";
	m_addList.InsertString(index++,list);
	list="A相电压";
	m_addList.InsertString(index++,list);
	list="B相电压";
	m_addList.InsertString(index++,list);
	list="C相电压";
	m_addList.InsertString(index++,list);
}

void CSend1Dlg::OnDropdownCOMBOfreq() 
{
	// TODO: Add your control notification handler code here
	m_freqList.ResetContent();
	CString list="";
	int index=0;
	list="A相电流";
	m_freqList.InsertString(index++,list);
	list="B相电流";
	m_freqList.InsertString(index++,list);
	list="C相电流";
	m_freqList.InsertString(index++,list);
	list="A相电压";
	m_freqList.InsertString(index++,list);
	list="B相电压";
	m_freqList.InsertString(index++,list);
	list="C相电压";
	m_freqList.InsertString(index++,list);
}

void CSend1Dlg::OnDropdownCOMBOharm() 
{
	// TODO: Add your control notification handler code here
	m_harmList.ResetContent();
	CString list="";
	int index=0;
	list="A相电流";
	m_harmList.InsertString(index++,list);
	list="B相电流";
	m_harmList.InsertString(index++,list);
	list="C相电流";
	m_harmList.InsertString(index++,list);
	list="A相电压";
	m_harmList.InsertString(index++,list);
	list="B相电压";
	m_harmList.InsertString(index++,list);
	list="C相电压";
	m_harmList.InsertString(index++,list);
}

void CSend1Dlg::OnSelchangeCOMBOadd() 
{
	// TODO: Add your control notification handler code here
	add_cursel=m_addList.GetCurSel();
}

void CSend1Dlg::OnSelchangeCOMBOfreq() 
{
	// TODO: Add your control notification handler code here
	freqdrift_cursel=m_freqList.GetCurSel();
	CString str;
	switch(freqdrift_cursel)
	{
	case Aa:
		str.Format("%f",f_Aa);
		m_freq.SetWindowText(str);
		break;
	case Ab:
		str.Format("%f",f_Ab);
		m_freq.SetWindowText(str);
		break;
	case Ac:
		str.Format("%f",f_Ac);
		m_freq.SetWindowText(str);
		break;
	case Va:
		str.Format("%f",f_Va);
		m_freq.SetWindowText(str);
		break;
	case Vb:
		str.Format("%f",f_Vb);
		m_freq.SetWindowText(str);
		break;
	case Vc:
		str.Format("%f",f_Vc);
		m_freq.SetWindowText(str);
		break;
	}
}

void CSend1Dlg::OnSelchangeCOMBOharm() 
{
	// TODO: Add your control notification handler code here
	harm_cursel=m_harmList.GetCurSel();
}

void CSend1Dlg::OnButton_add_plus() 
{
	// TODO: Add your control notification handler code here
	CString str;
	switch (add_cursel)
	{
	case NN: 
		MessageBox("请选择","请选择",MB_OK);
		break;
	case Aa:
		add[add_i].cursel=Aa;
		m_add_amp.GetWindowText(str);
		add[add_i].amp=atof(str);
		m_add_freq.GetWindowText(str);
		add[add_i].freq=atof(str);
		add_i++;
		str.Format("%d",add_i);
		m_add_i.SetWindowText(str);
		break;
	case Ab:
		add[add_i].cursel=Ab;
		m_add_amp.GetWindowText(str);
		add[add_i].amp=atof(str);
		m_add_freq.GetWindowText(str);
		add[add_i].freq=atof(str);
		add_i++;
		str.Format("%d",add_i);
		m_add_i.SetWindowText(str);
		break;
	case Ac:
		add[add_i].cursel=Ac;
		m_add_amp.GetWindowText(str);
		add[add_i].amp=atof(str);
		m_add_freq.GetWindowText(str);
		add[add_i].freq=atof(str);
		add_i++;
		str.Format("%d",add_i);
		m_add_i.SetWindowText(str);
		break;
	case Va:
		add[add_i].cursel=Va;
		m_add_amp.GetWindowText(str);
		add[add_i].amp=atof(str);
		m_add_freq.GetWindowText(str);
		add[add_i].freq=atof(str);
		add_i++;
		str.Format("%d",add_i);
		m_add_i.SetWindowText(str);
		break;
	case Vb:
		add[add_i].cursel=Vb;
		m_add_amp.GetWindowText(str);
		add[add_i].amp=atof(str);
		m_add_freq.GetWindowText(str);
		add[add_i].freq=atof(str);
		add_i++;
		str.Format("%d",add_i);
		m_add_i.SetWindowText(str);
		break;
	case Vc:
		add[add_i].cursel=Vc;
		m_add_amp.GetWindowText(str);
		add[add_i].amp=atof(str);
		m_add_freq.GetWindowText(str);
		add[add_i].freq=atof(str);
		add_i++;
		str.Format("%d",add_i);
		m_add_i.SetWindowText(str);
		break;
	}
}

void CSend1Dlg::OnButton_add_minus() 
{
	// TODO: Add your control notification handler code here
	
}

void CSend1Dlg::OnButton_harm_plus() 
{
	// TODO: Add your control notification handler code here
	CString str;
	switch (harm_cursel)
	{
	case NN: 
		MessageBox("请选择","请选择",MB_OK);
		break;
	case Aa:
		harm[harm_i].cursel=Aa;
		m_harm_amp.GetWindowText(str);
		harm[harm_i].amp=atof(str);
		m_harm_n.GetWindowText(str);
		harm[harm_i].h=atof(str);
		harm_i++;
		str.Format("%d",harm_i);
		m_harm_i.SetWindowText(str);
		break;
	case Ab:
		harm[harm_i].cursel=Ab;
		m_harm_amp.GetWindowText(str);
		harm[harm_i].amp=atof(str);
		m_harm_n.GetWindowText(str);
		harm[harm_i].h=atof(str);
		harm_i++;
		str.Format("%d",harm_i);
		m_harm_i.SetWindowText(str);
		break;
	case Ac:
		harm[harm_i].cursel=Ac;
		m_harm_amp.GetWindowText(str);
		harm[harm_i].amp=atof(str);
		m_harm_n.GetWindowText(str);
		harm[harm_i].h=atof(str);
		harm_i++;
		str.Format("%d",harm_i);
		m_harm_i.SetWindowText(str);
		break;
	case Va:
		harm[harm_i].cursel=Va;
		m_harm_amp.GetWindowText(str);
		harm[harm_i].amp=atof(str);
		m_harm_n.GetWindowText(str);
		harm[harm_i].h=atof(str);
		harm_i++;
		str.Format("%d",harm_i);
		m_harm_i.SetWindowText(str);
		break;
	case Vb:
		harm[harm_i].cursel=Vb;
		m_harm_amp.GetWindowText(str);
		harm[harm_i].amp=atof(str);
		m_harm_n.GetWindowText(str);
		harm[harm_i].h=atof(str);
		harm_i++;
		str.Format("%d",harm_i);
		m_harm_i.SetWindowText(str);
		break;
	case Vc:
		harm[harm_i].cursel=Vc;
		m_harm_amp.GetWindowText(str);
		harm[harm_i].amp=atof(str);
		m_harm_n.GetWindowText(str);
		harm[harm_i].h=atof(str);
		harm_i++;
		str.Format("%d",harm_i);
		m_harm_i.SetWindowText(str);
		break;
	}
}

void CSend1Dlg::OnButton_harm_minus() 
{
	// TODO: Add your control notification handler code here
	
}


void CSend1Dlg::OnChangeEDITsmprate() 
{
	// TODO: If this is a RICHEDIT control, the control will not
	// send this notification unless you override the CDialog::OnInitDialog()
	// function and call CRichEditCtrl().SetEventMask()
	// with the ENM_CHANGE flag ORed into the mask.
	
	// TODO: Add your control notification handler code here
	CString am;
	m_smprate.GetWindowText(am);
	packet2send.smpRate=atoi(am);
}

void CSend1Dlg::add_harm()
{
	for (int i=0;i<harm_i;i++)
	{
		switch(harm[i].cursel)
		{
		case Aa:
			packet2send.data_to_send.currentA+=harm[i].amp*cos(harm[i].h*2*PI*50*msec);
			break;
		case Ab:
			packet2send.data_to_send.currentB+=harm[i].amp*cos(harm[i].h*2*PI*50*msec);
			break;
		case Ac:
			packet2send.data_to_send.currentC+=harm[i].amp*cos(harm[i].h*2*PI*50*msec);
			break;
		case Va:
			packet2send.data_to_send.VoltageA+=harm[i].amp*cos(harm[i].h*2*PI*50*msec);
			break;
		case Vb:
			packet2send.data_to_send.VoltageB+=harm[i].amp*cos(harm[i].h*2*PI*50*msec);
			break;
		case Vc:
			packet2send.data_to_send.VoltageC+=harm[i].amp*cos(harm[i].h*2*PI*50*msec);
			break;
		}
	}

}

void CSend1Dlg::add_amp()
{
	for (int i=0;i<add_i;i++)
	{
		switch(add[i].cursel)
		{
		case Aa:
			packet2send.data_to_send.currentA+=add[i].amp*cos(add[i].freq*2*PI*50*msec)*packet2send.data_to_send.currentA;
			break;
		case Ab:
			packet2send.data_to_send.currentB+=add[i].amp*cos(add[i].freq*2*PI*50*msec)*packet2send.data_to_send.currentB;
			break;
		case Ac:
			packet2send.data_to_send.currentC+=add[i].amp*cos(add[i].freq*2*PI*50*msec)*packet2send.data_to_send.currentC;
			break;
		case Va:
			packet2send.data_to_send.VoltageA+=add[i].amp*cos(add[i].freq*2*PI*50*msec)*packet2send.data_to_send.VoltageA;
			break;
		case Vb:
			packet2send.data_to_send.VoltageB+=add[i].amp*cos(add[i].freq*2*PI*50*msec)*packet2send.data_to_send.VoltageB;
			break;
		case Vc:
			packet2send.data_to_send.VoltageC+=add[i].amp*cos(add[i].freq*2*PI*50*msec)*packet2send.data_to_send.VoltageC;
			break;
		}
	}
}

void CSend1Dlg::OnButton_freqdrift() 
{
	// TODO: Add your control notification handler code here
	CString str;
	switch (freqdrift_cursel)
	{
	case NN: 
		MessageBox("请选择","请选择",MB_OK);
		break;
	case Aa:
		m_freq.GetWindowText(str);
		f_Aa+=atof(str);
		freqdrift_i++;
		str.Format("%d",freqdrift_i);
		m_freqdrift_i.SetWindowText(str);
		break;
	case Ab:
		m_freq.GetWindowText(str);
		f_Ab+=atof(str);
		freqdrift_i++;
		str.Format("%d",freqdrift_i);
		m_freqdrift_i.SetWindowText(str);
		break;
	case Ac:
		m_freq.GetWindowText(str);
		f_Ac+=atof(str);
		freqdrift_i++;
		str.Format("%d",freqdrift_i);
		m_freqdrift_i.SetWindowText(str);
		break;
	case Va:
		m_freq.GetWindowText(str);
		f_Va+=atof(str);
		freqdrift_i++;
		str.Format("%d",freqdrift_i);
		m_freqdrift_i.SetWindowText(str);
		break;
	case Vb:
		m_freq.GetWindowText(str);
		f_Vb+=atof(str);
		freqdrift_i++;
		str.Format("%d",freqdrift_i);
		m_freqdrift_i.SetWindowText(str);
		break;
	case Vc:
		m_freq.GetWindowText(str);
		f_Vc+=atof(str);
		freqdrift_i++;
		str.Format("%d",freqdrift_i);
		m_freqdrift_i.SetWindowText(str);
		break;
	}
}

void CSend1Dlg::OnButton_about() 
{
	// TODO: Add your control notification handler code here
	CAboutDlg dlgAbout;
	dlgAbout.DoModal();

}

void CSend1Dlg::OnButton_Save() 
{
	// TODO: Add your control notification handler code here
	CString FilePathName="0";
	CFileDialog dlg(false,".txt","Send.txt",OFN_OVERWRITEPROMPT,"Txt Files (*.txt)|*.txt|Data Files (*.dat)|*.dat|All Files (*.*)|*.*||");///TRUE为OPEN对话框，FALSE为SAVE AS对话框
	dlg.m_ofn.lpstrInitialDir=_T(".\\"); //这里就设置了对话框的默认目录
	if(dlg.DoModal()==IDOK) FilePathName=dlg.GetPathName();

	ofstream ofile;
	ofile.open(FilePathName);
	ofile<<"seq:"<<'\t'<<"Ia"<<'\t'<<"Ib"<<'\t'<<"Ic"<<'\t'<<"In"<<'\t'<<"Va"<<'\t'<<"Vb"<<'\t'<<"Vc"<<'\t'<<"Vn"<<endl;
	// 	ofile<<"seq:"<<'\t'<<"Ia:"<<'\t'<<"Ib"<<'\t'<<"Ic"<<'\t'<<endl;
	// 	for(int i=0;i<packet2send.smpCount;i++)
	// 	{
	// 		ofile<<i+1<<'\t'
	// 			<<packet2send.data_to_send.Ia[i]<<'\t'
	// 			<<packet2send.data_to_send.Ib[i]<<'\t'
	// 			<<packet2send.data_to_send.Ic[i]<<'\t'<<endl;
	// 	}
	for(int i=0;i<packet2send.smpCount;i++)
	{
		ofile<<i+1<<'\t'
			<<packet2send.data_to_send.Ia[i]<<'\t'
 			<<packet2send.data_to_send.Ib[i]<<'\t'
 			<<packet2send.data_to_send.Ic[i]<<'\t'
 			<<packet2send.data_to_send.In[i]<<'\t'

 			<<packet2send.data_to_send.Vola[i]<<'\t'
			<<packet2send.data_to_send.Volb[i]<<'\t'
			<<packet2send.data_to_send.Volc[i]<<'\t'
			<<packet2send.data_to_send.Voln[i]<<'\t'
			<<endl;
	}
	ofile.close();
// 	for(int i=0;i<packet2send.smpCount;i++)
// 	{
// 		ofile<<packet2send.data_to_send.Ia[i]<<endl;
// 	}
// 	ofile.close();
// 	
// 	ofile.open("b.txt");
// 	for(int j=0;j<packet2send.smpCount;j++)
// 	{
// 		ofile<<packet2send.data_to_send.Ib[j]<<endl;
// 	}
// 	ofile.close();
// 	
// 	ofile.open("c.txt");
// 	for(int k=0;k<packet2send.smpCount;k++)
// 	{
// 		ofile<<packet2send.data_to_send.Ic[k]<<endl;
// 	}
	
}

void CSend1Dlg::OnCustomdrawSLIDERfault(NMHDR* pNMHDR, LRESULT* pResult) 
{
	// TODO: Add your control notification handler code here
	sliderF=m_slider_f.GetPos();
	f_left=sliderF;
	f_right=100-sliderF;
	CString str;
	str.Format("%d",f_left);
	m_left.SetWindowText(str+"%");
	str.Format("%d",f_right);
	m_right.SetWindowText(str+"%");
	*pResult = 0;
}
