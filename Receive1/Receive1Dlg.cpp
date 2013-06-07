// Receive1Dlg.cpp : implementation file
//

#include "stdafx.h"
#include "Receive1.h"
#include "Receive1Dlg.h"

#include "DataType.h"

#include "stdio.h"
#include <conio.h>
#include "packet32.h"
#include <ntddndis.h>

#include "winsock2.h"
#include "string.h"

#include <pcap.h>
#include <remote-ext.h>

#include "Packet.h"
#include <fstream>
using namespace std;

#pragma comment(lib,"wpcap.lib")
#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib, "packet.lib") 

//获得网卡以及打开网卡用到的参数
pcap_if_t *alldevs=NULL;//获取所有网卡
pcap_if_t *dev=NULL;//当前选择的网卡
int interface_num;//网卡总数
int i=0;
pcap_t *adhandle;
char errbuf[PCAP_ERRBUF_SIZE];
//显示收到包的顺序
int seq=0;

CString soumac;//获得本机mac地址时用
CString soumac_temp="";
	int soumac_len;

volatile BOOL m_bRun;//代表线程是否正在运行
bool already_start=false;//用于判断是否开始过

Packet packet2receive;

// u_char packet[256];//接受的数据包
int wav_A_flg=4;//电流波形显示标记
int wav_V_flg=4;//电压波形显示标记

int list_flg=0;
//电能质量
#define NN -1
#define Aa 0
#define Ab 1
#define Ac 2
#define Va 3
#define Vb 4
#define Vc 5
// int cur_slect;
//谐波
int harm_h;
double harm_hru;
double harm_total;
int harm_cursel;
//电压电流偏移
double skew_urms;
double skew_skew;
int skew_cursel;
//波动闪变
double flick_fluctuate;
double flick_short_flick;
double flick_long_flick;
int flick_cursel;
//不平衡度
double unbalance;
int unbalance_cursel;
//频率偏移
double freqdrift;
int freqdrift_cursel;

CString strtemp;

int sliderA=106;
int sliderV=106;


double Am[100000],Am1[100000],Am2[100000],c,e,ss;
double S/*,S1,S2;*/;
// double Vm[100000],Vm1[100000],Vm2[100000];
// double R,R1,R2;
double caiyanglv;
double youxiaozhi;
int FFT_N;    //定义福利叶变换的点数
struct compx {double real,imag;};                                    //定义一个复数结构
struct compx s[100000],s1[100000],s2[100000],temp[100000];   //FFT输入和输出：从S[1]开始存放，根据大小自己定义
// struct compx s3[100000],s4[100000],s5[100000];

	/*******************************************************************
函数原型：struct compx EE(struct compx b1,struct compx b2)  
函数功能：对两个复数进行乘法运算
输入参数：两个以联合体定义的复数a,b
输出参数：a和b的乘积，以联合体的形式输出
*******************************************************************/
struct compx EE(struct compx a,struct compx b)      
{
	struct compx c;
	c.real=a.real*b.real-a.imag*b.imag;
	c.imag=a.real*b.imag+a.imag*b.real;
	return(c);
}
struct compx AAD(struct compx a,struct compx b)      
{
	 struct compx c;
	 c.real=a.real+b.real;
	 c.imag=a.imag+b.imag;
	 return(c);
}
struct compx M(struct compx a,struct compx b)      
{
	 struct compx c;
	 c.real=a.real-b.real;
	 c.imag=a.imag-b.imag;
	 return(c);
}

/*****************************************************************
函数原型：void FFT(struct compx *xin,int N)
函数功能：对输入的复数组进行快速傅里叶变换（FFT）
输入参数：*xin复数结构体组的首地址指针，struct型
*****************************************************************/
void FFT(struct compx *xin)
{
	int f,m,nv2,nm1,i,k,l,j=0;
	struct compx u,w,t;
   // cout<<FFT_N;
	nv2=FFT_N/2;                  //变址运算，即把自然顺序变成倒位序，采用雷德算法
	nm1=FFT_N-1;  
	for(i=0;i<nm1;i++)        
	{
		if(i<j)                    //如果i<j,即进行变址
		{
			t=xin[j];           
			xin[j]=xin[i];
			xin[i]=t;
		 }
		k=nv2;                    //求j的下一个倒位序
		while(k<=j)               //如果k<=j,表示j的最高位为1   
		{           
			j=j-k;                 //把最高位变成0
			k=k/2;                 //k/2，比较次高位，依次类推，逐个比较，直到某个位为0
		 }
		j=j+k;                   //把0改为1
	 }
     int le,lei,ip;                            //FFT运算核，使用蝶形运算完成FFT运算
	 f=FFT_N;
	 for(l=1;(f=f/2)!=1;l++);                  //计算l的值，即计算蝶形级数
	 for(m=1;m<=l;m++)                         // 控制蝶形结级数
	{                                        //m表示第m级蝶形，l为蝶形级总数l=log（2）N
		le=2<<(m-1);                            //le蝶形结距离，即第m级蝶形的蝶形结相距le点
		lei=le/2;                               //同一蝶形结中参加运算的两点的距离
		u.real=1.0;                             //u为蝶形结运算系数，初始值为1
		u.imag=0.0;
		w.real=cos(PI/lei);                     //w为系数商，即当前系数与前一个系数的商
		w.imag=-sin(PI/lei);
		for(j=0;j<=lei-1;j++)                   //控制计算不同种蝶形结，即计算系数不同的蝶形结
		{
			for(i=j;i<=FFT_N-1;i=i+le)            //控制同一蝶形结运算，即计算系数相同蝶形结
			{
				ip=i+lei;                           //i，ip分别表示参加蝶形运算的两个节点
				t=EE(xin[ip],u);                    //蝶形运算，详见公式
				xin[ip].real=xin[i].real-t.real;
				xin[ip].imag=xin[i].imag-t.imag;
				xin[i].real=xin[i].real+t.real;
				xin[i].imag=xin[i].imag+t.imag;
			}
			u=EE(u,w);                           //改变系数，进行下一个蝶形运算
			}
	   }
 }

void FFT1(struct compx *xin)
{
	int f,m,nv2,nm1,i,k,l,j=0;
	struct compx u,w,t;   
	nv2=256/2;                  //变址运算，即把自然顺序变成倒位序，采用雷德算法
	nm1=256-1;  
	for(i=0;i<nm1;i++)        
	{
		if(i<j)                    //如果i<j,即进行变址
		{
			t=xin[j];           
			xin[j]=xin[i];
			xin[i]=t;
		}
		k=nv2;                    //求j的下一个倒位序
		while(k<=j)               //如果k<=j,表示j的最高位为1   
		{           
			j=j-k;                 //把最高位变成0
			k=k/2;                 //k/2，比较次高位，依次类推，逐个比较，直到某个位为0
		}
		j=j+k;                   //把0改为1
	 }
                         
	{
		int le,lei,ip;                            //FFT运算核，使用蝶形运算完成FFT运算
		f=256;
		for(l=1;(f=f/2)!=1;l++);                  //计算l的值，即计算蝶形级数
		for(m=1;m<=l;m++)                         // 控制蝶形结级数
		{                                        //m表示第m级蝶形，l为蝶形级总数l=log（2）N
			le=2<<(m-1);                            //le蝶形结距离，即第m级蝶形的蝶形结相距le点
			lei=le/2;                               //同一蝶形结中参加运算的两点的距离
			u.real=1.0;                             //u为蝶形结运算系数，初始值为1
			u.imag=0.0;
			w.real=cos(PI/lei);                     //w为系数商，即当前系数与前一个系数的商
			w.imag=-sin(PI/lei);
			for(j=0;j<=lei-1;j++)                   //控制计算不同种蝶形结，即计算系数不同的蝶形结
				{
				for(i=j;i<=256-1;i=i+le)            //控制同一蝶形结运算，即计算系数相同蝶形结
				{
					ip=i+lei;                           //i，ip分别表示参加蝶形运算的两个节点
					t=EE(xin[ip],u);                    //蝶形运算，详见公式
					xin[ip].real=xin[i].real-t.real;
					xin[ip].imag=xin[i].imag-t.imag;
					xin[i].real=xin[i].real+t.real;
					xin[i].imag=xin[i].imag+t.imag;
				}
				u=EE(u,w);                           //改变系数，进行下一个蝶形运算
			}
		}
	}
  
}















struct bpf_program fcode; 
u_int netmask;
char packet_filter_all[] = "";
char packet_filter_notarp[] =/*"ether proto 0x0000";*/ "not arp";
char packet_filter_tcp[] = "ip and tcp";
char packet_filter_udp[] = "ip and udp";
char packet_filter_icmp[] = "ip and icmp";
char packet_filter_src[] = "ether src 02:02:02:02:02:02";
char fileter='1';


struct packet_message 
{
	CString time;
	CString sec;
	CString len;
	CString des;
	CString source;
	CString pro;
	CString data;
}pac;
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////
//定义各种协议类型字段 2字节=16位
typedef enum ethernet_frame_protocol
{
    IEEE = 0x0000, // 0x05DC   IEEE 802.3 长度
    EXP = 0x0101, // 0x01FF   实验
    XEROX_NS_IDP = 0x0600, //   XEROX NS IDP
    DLOG = 0x0661, //   DLOG
    IP = 0x0800, // 网际协议（IP）
    X_75Internet = 0x0801, //   X.75 Internet
    NBS_Internet = 0x0802, //   NBS Internet
    ECMA = 0x0803, // ECMA Internet
    Chaosnet = 0x0804, // Chaosnet
    X25_Level3 = 0x0805,   //X.25 Level 3
    ARP = 0x0806,    //地址解析协议（ARP ： Address Resolution Protocol）
    Frame_Relay_ARP = 0x0808,   //帧中继 ARP （Frame Relay ARP） [RFC1701]
    Raw_Frame_Relay = 0x6559,   //原始帧中继（Raw Frame Relay） [RFC1701]
    DARP = 0x8035,   // 动态 DARP （DRARP：Dynamic RARP）反向地址解析协议（RARP：Reverse Address Resolution Protocol）
    Novell_Netware_IPX = 0x8037,   //Novell Netware IPX
    EtherTalk = 0x809B,   //   EtherTalk
    IBM_SNA_Services = 0x80D5,   // IBM SNA Services over Ethernet
    AARP = 0x80F3,   //   AppleTalk 地址解析协议（AARP：AppleTalk Address Resolution Protocol）
    EAPS = 0x8100,   // 以太网自动保护开关（EAPS：Ethernet Automatic Protection Switching）
    IPX = 0x8137,   //    因特网包交换（IPX：Internet Packet Exchange）
    SNMP = 0x814C,   //简单网络管理协议（SNMP：Simple Network Management Protocol）
    IPV6 = 0x86DD,   //   网际协议v6 （IPv6，Internet Protocol version 6）
    PPP = 0x880B ,   // 点对点协议（PPP：Point-to-Point Protocol）
    GSMP = 0x880C,   //   通用交换管理协议（GSMP：General Switch Management Protocol）
    MPLS_unicast = 0x8847,   //   多协议标签交换（单播） MPLS：Multi-Protocol Label Switching <unicast>）
    MPLS_multicast = 0x8848,   //   多协议标签交换（组播）（MPLS, Multi-Protocol Label Switching <multicast>）
    PPPoE_DS = 0x8863,   //   以太网上的 PPP（发现阶段）（PPPoE：PPP Over Ethernet <Discovery Stage>）
    PPPoE_SS = 0x8864,   //   以太网上的 PPP（PPP 会话阶段） （PPPoE，PPP Over Ethernet<PPP Session Stage>）
    LWAPP = 0x88BB,   // 轻量级访问点协议（LWAPP：Light Weight Access Point Protocol）
    LLDP = 0x88CC,   // 链接层发现协议（LLDP：Link Layer Discovery Protocol）
    EAP = 0x8E88,   // 局域网上的 EAP（EAPOL：EAP over LAN）
    Loopback = 0x9000,   // 配置测试协议（Loopback）
    VLAN_Tag1 = 0x9100,   //   VLAN 标签协议标识符（VLAN Tag Protocol Identifier）
    VLAN_Tag2 = 0x9200,   //VLAN 标签协议标识符（VLAN Tag Protocol Identifier）
    MAINSTAIN = 0xFFFF, // 保留
//	IEC_6185_09_2 = 0x88BA // IEC_6185_09_2
} ETHERNET_FRAME_PROTOCOL;
//????????????????????????????????
typedef struct ethernet_frame_type
{
    ETHERNET_FRAME_PROTOCOL type;
    char description[50];

}ETHERNET_FRAME_TYPE;//typedef struct 用法，typedef与struct的组合。

ETHERNET_FRAME_TYPE eth_match[50];

/*以太网数据帧头部结构*/
typedef struct tagDLCHeader               /*以太网数据帧头部结构*/
{
    unsigned char      DesMAC[6];      /* destination HW addrress */
    unsigned char      SrcMAC[6];      /* source HW addresss */
    unsigned short     Ethertype;      /* ethernet type */
} DLCHEADER, *PDLCHEADER;


/* 4字节的IP地址 */
typedef struct ip_address{
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
}ip_address;

/* IPv4 首部 */
typedef struct ip_header{

    u_char ver_ihl; // 版本 (4 bits) + 首部长度 (4 bits)
    u_char tos; // 服务类型(Type of service)
    u_short tlen; // 总长(Total length)
    u_short identification; // 标识(Identification)
    u_short flags_fo; // 标志位(Flags) (3 bits) + 段偏移量(Fragment offset) (13 bits)
    u_char ttl; // 存活时间(Time to live)
    u_char proto; // 协议(Protocol)
    u_short crc; // 首部校验和(Header checksum)
    ip_address saddr; // 源地址(Source address)
    ip_address daddr; // 目的地址(Destination address)
    u_int op_pad; // 选项与填充(Option + Padding)
}ip_header;

/* TCP首部*/
typedef struct _TCPHeader    //20个字节
{   
    USHORT    sourcePort;        //16位源端口号
    USHORT    destinationPort;//16位目的端口号
    ULONG    sequenceNumber;    //32位序列号
    ULONG    acknowledgeNumber;//32位确认号
    USHORT    dataoffset;        //4位首部长度/6位保留字/6位标志位
    USHORT    windows;        //16位窗口大小
    USHORT    checksum;        //16位校验和
    USHORT    urgentPointer;    //16位紧急数据偏移量
}TCPHeader,*PTCPHeader;


// ARP数据帧
typedef struct tagARPFrame
{
    unsigned short     HW_Type;            /* hardware type */
    unsigned short     Prot_Type;        /* protocol type */
    unsigned char      HW_Addr_Len;     /* length of hardware address */
    unsigned char      Prot_Addr_Len;   /* length of protocol address */
    unsigned short     Opcode;            /* ARP/RARP */
    unsigned char      Send_HW_Addr[6]; /* sender hardware address */
    unsigned char      Send_Prot_Addr[4]; /* sender protocol address */
    unsigned char      Targ_HW_Addr[6]; /* target hardware address */
    unsigned char      Targ_Prot_Addr[4]; /* target protocol address */
    unsigned char      padding[18];
} ARPFRAME, *PARPFRAME;

/* UDP首部*/
typedef struct _UDPHeader
{
    USHORT    sourcePort;        //源端口号
    USHORT    destinationPort;//目的端口号
    USHORT    len;            //封包长度
    USHORT    checksum;        //校验和
}UDPHeader,*PUDPHeader;

// ICMP首部
typedef struct _ICMPHeader
{
    UCHAR    icmp_type;        //消息类型
    UCHAR    icmp_code;        //代码
    USHORT    icmp_checksum;    //校验和
    //下面是回显头
    USHORT    icmp_id;        //用来惟一标识此请求的ID号，通常设置为进程ID
    USHORT    icmp_sequence;    //序列号
    ULONG    icmp_timestamp;    //时间戳
}ICMPHeader,*PICMPHeader;


typedef struct _opcode //ARP操作字段
{
    u_short type;
    char description[50];
}OPCODE;

OPCODE opcode_table[5];

void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

void initial_eth_type_table()
{
    eth_match[0].type = IEEE;
    strcpy(eth_match[0].description, "IEEE 802.3");
    eth_match[1].type = EXP;
    strcpy(eth_match[1] .description, "EXPERIMENT");
//    strcpy(eth_match[1] .description,"EXPERIMENT");
    eth_match[2].type = XEROX_NS_IDP;
    strcpy(eth_match[2] .description," XEROX NS IDP");
    eth_match[3].type = DLOG;
    strcpy(eth_match[3] .description, "DLOG");
    eth_match[4].type = IP;
    strcpy(eth_match[4] .description,"IP");
    eth_match[5].type = X_75Internet;
    strcpy(eth_match[5] .description," X.75 Internet");
    eth_match[6].type = NBS_Internet;
    strcpy(eth_match[6] .description,"NBS Internet");
    eth_match[7].type = ECMA;
    strcpy(eth_match[7] .description,"ECMA Internet");
    eth_match[8].type = Chaosnet;
    strcpy(eth_match[8] .description,"Chaosnet");
    eth_match[9].type = X25_Level3;
    strcpy(eth_match[9] .description,"X.25 Level 3");
    eth_match[10].type = ARP;
    strcpy(eth_match[10] .description,"ARP ： Address Resolution Protocol");
    eth_match[11].type = Frame_Relay_ARP;
    strcpy(eth_match[11] .description,"Frame Relay ARP [RFC1701]");
    eth_match[12].type = Raw_Frame_Relay;
    strcpy(eth_match[12] .description ,"Raw Frame Relay [RFC1701]");
    eth_match[13].type = DARP;
    strcpy(eth_match[13] .description,"Dynamic Reverse Address Resolution Protocol");
    eth_match[14].type = Novell_Netware_IPX;
    strcpy(eth_match[14] .description,"Novell Netware IPX");
    eth_match[15].type = EtherTalk;
    strcpy(eth_match[15] .description," EtherTalk");
    eth_match[16].type = IBM_SNA_Services;
    strcpy(eth_match[16] .description,"IBM SNA Services over Ethernet");
    eth_match[17].type = AARP;
    strcpy(eth_match[17] .description,"AARP：AppleTalk Address Resolution Protocol");
    eth_match[18].type = EAPS;
    strcpy(eth_match[18] .description,"IEC 61850-9-2"/*"EAPS：Ethernet Automatic Protection Switching"*/);
    eth_match[19].type = IPX;
    strcpy(eth_match[19] .description,"IPX：Internet Packet Exchange");
    eth_match[20].type = SNMP;
    strcpy(eth_match[20] .description,"SNMP：Simple Network Management Protocol");
    eth_match[21].type = IPV6;
    strcpy(eth_match[21] .description,"IPv6，Internet Protocol version 6");
    eth_match[22].type = PPP;
    strcpy(eth_match[22] .description,"PPP：Point-to-Point Protocol");
    eth_match[23].type = GSMP;
    strcpy(eth_match[23] .description,"GSMP：General Switch Management Protocol");
    eth_match[24].type = MPLS_unicast;
    strcpy(eth_match[24] .description,"MPLS：Multi-Protocol Label Switching <unicast>"); 
    eth_match[25].type = MPLS_multicast;
    strcpy(eth_match[25] .description,"MPLS, Multi-Protocol Label Switching <multicast>");
    eth_match[26].type = PPPoE_DS;
    strcpy(eth_match[26] .description,"PPPoE：PPP Over Ethernet <Discovery Stage>");
    eth_match[27].type = PPPoE_SS;
    strcpy(eth_match[27] .description,"PPPoE，PPP Over Ethernet<PPP Session Stage>");
    eth_match[28].type = LWAPP;
    strcpy(eth_match[28] .description,"LWAPP：Light Weight Access Point Protocol");
    eth_match[29].type = LLDP;
    strcpy(eth_match[29] .description,"LLDP：Link Layer Discovery Protocol");
    eth_match[30].type = EAP;
    strcpy(eth_match[30] .description,"EAPOL：EAP over LAN");
    eth_match[31].type = Loopback;
    strcpy(eth_match[31] .description,"Loopback");
    eth_match[32].type = VLAN_Tag1;
    strcpy(eth_match[32] .description,"VLAN Tag Protocol Identifier");
    eth_match[33].type = VLAN_Tag2;
    strcpy(eth_match[33] .description,"VLAN Tag Protocol Identifier");
    eth_match[34].type = MAINSTAIN;
    strcpy(eth_match[34].description,"MAINSTAIN");
// 	eth_match[35].type = IEC_6185_09_2;
//     strcpy(eth_match[35].description,"IEC_6185_09_2");

}
ETHERNET_FRAME_TYPE get_eth_type(u_short type, ETHERNET_FRAME_TYPE eth_type_table[])
{
    for (int i = 0; i <= 34; i++)
    {
        if (type == eth_type_table[i].type)
        {
            return eth_type_table[i];
        }
    }
    return eth_type_table[4];//IP?
}
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////
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
// CReceive1Dlg dialog

CReceive1Dlg::CReceive1Dlg(CWnd* pParent /*=NULL*/)
	: CDialog(CReceive1Dlg::IDD, pParent)
{
	//{{AFX_DATA_INIT(CReceive1Dlg)
		// NOTE: the ClassWizard will add member initialization here
	//}}AFX_DATA_INIT
	// Note that LoadIcon does not require a subsequent DestroyIcon in Win32
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CReceive1Dlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	//{{AFX_DATA_MAP(CReceive1Dlg)
	DDX_Control(pDX, IDC_EDIT_youxiaozhi, m_youxiaozhi);
	DDX_Control(pDX, IDC_EDIT_smpcount, m_smpcount);
	DDX_Control(pDX, IDC_COMBO_harm, m_harmList);
	DDX_Control(pDX, IDC_EDIT13, m_freqDrift);
	DDX_Control(pDX, IDC_COMBO_freqDriftList, m_freqdriftList);
	DDX_Control(pDX, IDC_EDIT12, m_unbalance);
	DDX_Control(pDX, IDC_COMBO_unbalance, m_unbalanceList);
	DDX_Control(pDX, IDC_EDIT11, m_flick_longflick);
	DDX_Control(pDX, IDC_EDIT10, m_flick_shortflick);
	DDX_Control(pDX, IDC_EDIT9, m_flick_fluctuate);
	DDX_Control(pDX, IDC_COMBO_flick, m_flickList);
	DDX_Control(pDX, IDC_EDIT8, m_skew_skew);
	DDX_Control(pDX, IDC_EDIT7, m_skew_youxiaozhi);
	DDX_Control(pDX, IDC_COMBO_skew, m_skewList);
	DDX_Control(pDX, IDC_BUTTON_harm_ana, m_harm_analy);
	DDX_Control(pDX, IDC_EDIT5, m_harm_total);
	DDX_Control(pDX, IDC_EDIT4, m_harm_hru);
	DDX_Control(pDX, IDC_EDIT3, m_harm_h);
	DDX_Control(pDX, IDC_RADIO_listoff, m_listoff);
	DDX_Control(pDX, IDC_SLIDER_V, m_slider_v);
	DDX_Control(pDX, IDC_SLIDER_A, m_slider_a);
	DDX_Control(pDX, IDC_PLOT_VOLTAGE_C, m_voltage_c);
	DDX_Control(pDX, IDC_PLOT_VOLTAGE_B, m_voltage_b);
	DDX_Control(pDX, IDC_PLOT_VOLTAGE_A, m_voltage_a);
	DDX_Control(pDX, IDC_PLOT_VOLTAGE_ABC, m_voltage_abc);
	DDX_Control(pDX, IDC_PROGRESS1, m_progress);
	DDX_Control(pDX, IDC_EDIT_fliter_src, m_fliter_src);
	DDX_Control(pDX, IDC_RADIO7, m_radio_Aabc);
	DDX_Control(pDX, IDC_PLOT_CURRENT_ABC, m_current_abc);
	DDX_Control(pDX, IDC_PLOT_CURRENT_C, m_current_c);
	DDX_Control(pDX, IDC_PLOT_CURRENT_B, m_current_b);
	DDX_Control(pDX, IDC_EDIT_soumac, m_soumac);
	DDX_Control(pDX, IDC_PLOT_CURRENT_A, m_current_a);
	DDX_Control(pDX, IDC_RADIO1, m_radio1);
	DDX_Control(pDX, IDC_AdapterList, m_adapter);
	DDX_Control(pDX, IDC_LIST1, m_list);
	//}}AFX_DATA_MAP
}

BEGIN_MESSAGE_MAP(CReceive1Dlg, CDialog)
	//{{AFX_MSG_MAP(CReceive1Dlg)
	ON_MESSAGE(WM_MY_MESSAGE, OnMyMessage)
	ON_MESSAGE(WM_MY_MESSAGE1, OnMyMessage1)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_CBN_DROPDOWN(IDC_AdapterList, OnDropdownAdapterList)
	ON_CBN_SELCHANGE(IDC_AdapterList, OnSelchangeAdapterList)
	ON_BN_CLICKED(IDOK, OnStart)
	ON_BN_CLICKED(IDC_RADIO1, OnRadio1)
	ON_BN_CLICKED(IDC_RADIO2, OnRadio2)
	ON_BN_CLICKED(IDC_RADIO3, OnRadio3)
	ON_BN_CLICKED(IDC_RADIO4, OnRadio4)
	ON_BN_CLICKED(IDC_RADIO5, OnRadio5)
	ON_BN_CLICKED(IDC_RADIO6, OnRadio6)
	ON_BN_CLICKED(IDC_STOP, OnStop)
	ON_BN_CLICKED(IDC_BUTTON_CLEAR, OnButtonClear)
	ON_WM_TIMER()
	ON_BN_CLICKED(IDC_RADIO7, OnRadio_Aabc)
	ON_BN_CLICKED(IDC_RADIO8, OnRadio_Aa)
	ON_BN_CLICKED(IDC_RADIO9, OnRadio_Ab)
	ON_BN_CLICKED(IDC_RADIO10, OnRadio_Ac)
	ON_EN_CHANGE(IDC_EDIT_fliter_src, OnChangeEDITflitersrc)
	ON_BN_CLICKED(IDC_RADIO11, OnRadio_Ashut)
	ON_BN_CLICKED(IDC_RADIO12, OnRadio_Vabc)
	ON_BN_CLICKED(IDC_RADIO13, OnRadio_Va)
	ON_BN_CLICKED(IDC_RADIO14, OnRadio_Vb)
	ON_BN_CLICKED(IDC_RADIO15, OnRadio_Vc)
	ON_BN_CLICKED(IDC_RADIO16, OnRadio_Vshut)
	ON_BN_CLICKED(IDC_RADIO_liston, OnRADIOliston)
	ON_BN_CLICKED(IDC_RADIO_listseq, OnRADIOlistseq)
	ON_CBN_DROPDOWN(IDC_COMBO_harm, OnDropdownCOMBOharm)
	ON_CBN_DROPDOWN(IDC_COMBO_skew, OnDropdownCOMBOskew)
	ON_CBN_DROPDOWN(IDC_COMBO_flick, OnDropdownCOMBOflick)
	ON_CBN_DROPDOWN(IDC_COMBO_freqDriftList, OnDropdownCOMBOfreqDriftList)
	ON_CBN_DROPDOWN(IDC_COMBO_unbalance, OnDropdownCOMBOunbalance)
	ON_CBN_SELCHANGE(IDC_COMBO_flick, OnSelchangeCOMBOflick)
	ON_CBN_SELCHANGE(IDC_COMBO_freqDriftList, OnSelchangeCOMBOfreqDriftList)
	ON_CBN_SELCHANGE(IDC_COMBO_harm, OnSelchangeCOMBOharm)
	ON_CBN_SELCHANGE(IDC_COMBO_skew, OnSelchangeCOMBOskew)
	ON_CBN_SELCHANGE(IDC_COMBO_unbalance, OnSelchangeCOMBOunbalance)
	ON_BN_CLICKED(IDC_BUTTON_harm_ana, OnBUTTONharmana)
	ON_BN_CLICKED(IDC_BUTTON_skew, OnButtonSkew)
	ON_BN_CLICKED(IDC_BUTTON_flick, OnButton_flick)
	ON_BN_CLICKED(IDC_BUTTON_unbalance, OnButton_Unbalance)
	ON_BN_CLICKED(IDC_BUTTON_freqdrift, OnButton_freqdrift)
	ON_BN_CLICKED(IDC_BUTTON1, OnButton_about)
	ON_BN_CLICKED(IDC_BUTTON2, OnButton_Save)
	ON_NOTIFY(NM_OUTOFMEMORY, IDC_SLIDER_A, OnOutofmemorySliderA)
	ON_NOTIFY(NM_OUTOFMEMORY, IDC_SLIDER_V, OnOutofmemorySliderV)
	//}}AFX_MSG_MAP
END_MESSAGE_MAP()

/////////////////////////////////////////////////////////////////////////////
// CReceive1Dlg message handlers

BOOL CReceive1Dlg::OnInitDialog()
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
	
	DWORD dwStyle=GetWindowLong(m_list.GetSafeHwnd(),GWL_STYLE);            
	dwStyle&=~LVS_TYPEMASK;
	dwStyle|=LVS_REPORT;
	SetWindowLong(m_list.GetSafeHwnd(),GWL_STYLE,dwStyle);
//初始化抓包显示框	
	m_list.InsertColumn(1,"序号",LVCFMT_CENTER,36);
    m_list.InsertColumn(2,"时间",LVCFMT_CENTER,100);
	m_list.InsertColumn(3,"长度",LVCFMT_CENTER,40);
	m_list.InsertColumn(4,"源MAC地址",LVCFMT_CENTER,110);
	m_list.InsertColumn(5,"目的MAC地址",LVCFMT_CENTER,110);
	m_list.InsertColumn(6,"协议",LVCFMT_CENTER,36);
	m_list.InsertColumn(7,"数据",LVCFMT_LEFT,1580);    
	// TODO: Add extra initialization here
	m_radio1.SetCheck(TRUE);
//波形显示
//电流显示
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
// 	m_radio_Aabc.SetCheck(TRUE);
	CheckRadioButton(IDC_RADIO7,IDC_RADIO11,IDC_RADIO11);
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
	CheckRadioButton(IDC_RADIO12,IDC_RADIO16,IDC_RADIO16);
	// 	OnRadio_Vshut();

	m_listoff.SetCheck(true);//默认为关闭显示list
//初始化电能质量分析参数
	CString str;
	//谐波
	m_harm_h.SetWindowText("2");
	m_harm_h.GetWindowText(str);
	harm_h=atoi(str);

	m_harm_hru.SetWindowText("0");
	m_harm_hru.GetWindowText(str);
	harm_hru=atof(str);
	m_harm_hru.SetWindowText("—%");

	m_harm_total.SetWindowText("0");
	m_harm_total.GetWindowText(str);
	harm_total=atof(str);
	m_harm_total.SetWindowText("—%");

	harm_cursel=NN;
	//电压电流偏移
	m_skew_youxiaozhi.SetWindowText("0");
	m_skew_youxiaozhi.GetWindowText(str);
	skew_urms=atof(str);
	m_skew_youxiaozhi.SetWindowText("—");

	m_skew_skew.SetWindowText("0");
	m_skew_skew.GetWindowText(str);
	skew_skew=atof(str);
	m_skew_skew.SetWindowText("—%");
	skew_cursel=NN;
	//波动闪变
	m_flick_fluctuate.SetWindowText("—%");
	flick_fluctuate=0;
	m_flick_shortflick.SetWindowText("—");
	flick_short_flick=0;
	m_flick_longflick.SetWindowText("—");
	flick_long_flick=0;
	flick_cursel=NN;
	//不平衡
	m_unbalance.SetWindowText("—%");
	unbalance=0;
	unbalance_cursel=NN;
	//频率偏移
	m_freqDrift.SetWindowText("—%");
	freqdrift=0;
	freqdrift_cursel=NN;

	m_youxiaozhi.SetWindowText("220");
	m_slider_a.SetRange(1,120);
	m_slider_v.SetRange(1,120);

	m_slider_a.SetPos(sliderA);
	m_slider_v.SetPos(sliderV);

	
	GetDlgItem(IDC_BUTTON_harm_ana)->EnableWindow(FALSE);
	GetDlgItem(IDC_BUTTON_skew)->EnableWindow(FALSE);
	GetDlgItem(IDC_BUTTON_flick)->EnableWindow(FALSE);
	GetDlgItem(IDC_BUTTON_unbalance)->EnableWindow(FALSE);
	GetDlgItem(IDC_BUTTON_freqdrift)->EnableWindow(FALSE);

	m_smpcount.SetWindowText("0");
	SetTimer(1,1,NULL);

	return TRUE;  // return TRUE  unless you set the focus to a control
}

void CReceive1Dlg::OnSysCommand(UINT nID, LPARAM lParam)
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

void CReceive1Dlg::OnPaint() 
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
HCURSOR CReceive1Dlg::OnQueryDragIcon()
{
	return (HCURSOR) m_hIcon;
}
CString HexCstringReverse(CString str){//将cstring两个字节两个字节的反转，如“123456”转为“563412”
	CString reversed="";
	for(int i=str.GetLength();i>=2;i-=2){
		reversed+=str.Mid(i-2,2);
	}
	return reversed;
}

int CstringHex2Int(CString str)//将16进制的数转换为整型
{
	int nRet = 0;
	int count = 1;
	for(int i = str.GetLength()-1; i >= 0; --i)
	{
		int nNum = 0;
		u_char chTest;
		chTest = str.GetAt(i);
		if (chTest >= '0' && chTest <= '9')
		{
			nNum = chTest - '0';
		}
		else if (chTest >= 'A' && chTest <= 'F')
		{
			nNum = chTest - 'A' + 10;
		}
		else if (chTest >= 'a' && chTest <= 'f')
		{
			nNum = chTest - 'a' + 10;
		}
		nRet += nNum*count;
		count *= 16;
		
	}
	return nRet;
}
float CstringHex2Float(CString str){
	char cByte[4];//方法一
	for (int i=0;i<4;i++)
	{
		cByte[i] = str[i];
	}
	float pfValue=*(float*)&cByte;
	return  pfValue;
}

void CReceive1Dlg::OnDropdownAdapterList() 
{
	// TODO: Add your control notification handler code here
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
	for(dev=alldevs; dev!=NULL; dev=dev->next)
	{
		adapter="";
		// 		//		printf("%d. %s", ++i, d->name);
		// 		cout<<"No. : "<<++i<<endl;
		// 		cout<<"Name: "<<d->name<<endl;
		++i;
		// 		adapter=d->name;
		if (dev->description)
			adapter+=dev->description;
		/*			cout<<"Description: "<<d->description<<endl<<endl;*/
		//			printf(" (%s)\n", d->description);
		else
			adapter+=dev->name;
		// 			printf(" (No description available)\n\n");
// 		m_adapter.AddString(adapter);
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

void CReceive1Dlg::OnSelchangeAdapterList() 
{
	// TODO: Add your control notification handler code here
	/*选择某个网卡：*/
	int interface_num=0;
	interface_num=m_adapter.GetCurSel();
	
	/* 找到要选择的网卡结构 */
	for(dev=alldevs, i=0; i< interface_num-1 ;dev=dev->next, i++);
	
	/* 打开选择的网卡 */
	if ( (adhandle= pcap_open_live(dev->name, // 设备名称
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

}
void ThreadFunc()//线程函数，实际是处理抓包的，用另一个线程处理，避免用户界面卡死
{
// 	CTime time;
// 	CString strTime;
// 	m_bRun=TRUE;
// 	while(m_bRun)
// 	{
// 		time=CTime::GetCurrentTime();
// 		strTime=time.Format("%H:%M:%S");
// 		::SetDlgItemText(AfxGetMainWnd()->m_hWnd,IDC_TIME,strTime);
// 		Sleep(1000);
// 	}

	if (m_bRun)
	{
		if(dev==NULL){
			MessageBox(NULL,"请先选择网卡","错误",MB_OK);
		}
		else if(already_start==false){
			initial_eth_type_table(); //初始化以太网帧协议表	
		    opcode_table[1].type = 1;                             //初始化ARP操作字段表
		    strcpy(opcode_table[1].description, "ARP request");
		    opcode_table[2].type = 2;
		    strcpy(opcode_table[2].description, "ARP response");
			opcode_table[3].type = 1;
		    strcpy(opcode_table[3].description , "RARP request");
		    opcode_table[4].type = 2;
		    strcpy(opcode_table[4].description , "RARP response");
	
			if(dev->addresses != NULL)
	        /* 获得接口第一个地址的掩码 */
				netmask=((struct sockaddr_in *)(dev->addresses->netmask))->sin_addr.S_un.S_addr;
			else
	        /* 如果接口没有地址，那么我们假设一个C类的掩码 */
				netmask=0xffffff;

///////////////////设置过滤器
			switch (fileter)
			{
			case '1':
				{
					if (pcap_compile(adhandle, &fcode, packet_filter_all, 1, netmask) <0 )
					{
						MessageBox(NULL,"Unable to compile the packet filter. Check the syntax","error",MB_OK);
						/* 释放设备列表 */
						pcap_freealldevs(alldevs);
					}
					break;
				}
			case '2':
				{
					if (pcap_compile(adhandle, &fcode, packet_filter_notarp, 1, netmask) <0 )
					{
						MessageBox(NULL,"Unable to compile the packet filter. Check the syntax","error",MB_OK);
						/* 释放设备列表 */
						pcap_freealldevs(alldevs);
					}
					break;
				}
			case '3':
				{
					if (pcap_compile(adhandle, &fcode, packet_filter_tcp, 1, netmask) <0 )
					{
						MessageBox(NULL,"Unable to compile the packet filter. Check the syntax","error",MB_OK);
						/* 释放设备列表 */
						pcap_freealldevs(alldevs);
					}
					break;
				}
			case '4':
				{
					if (pcap_compile(adhandle, &fcode, packet_filter_udp, 1, netmask) <0 )
					{
						MessageBox(NULL,"Unable to compile the packet filter. Check the syntax","error",MB_OK);
						/* 释放设备列表 */
						pcap_freealldevs(alldevs);
					}
					break;
				}
			case '5':
			  {
			      if (pcap_compile(adhandle, &fcode, packet_filter_icmp, 1, netmask) <0 )
			      {
						MessageBox(NULL,"Unable to compile the packet filter. Check the syntax","error",MB_OK);
			         /* 释放设备列表 */
				        pcap_freealldevs(alldevs);
			      }
			       break;
			    }
			case '6':
		       {
		          if (pcap_compile(adhandle, &fcode, packet_filter_src, 1, netmask) <0 )
		          {
						MessageBox(NULL,"Unable to compile the packet filter. Check the syntax","error",MB_OK);
		             /* 释放设备列表 */
			            pcap_freealldevs(alldevs);
			        }
			        break;
			    }
			
			default:
			  if (pcap_compile(adhandle, &fcode, packet_filter_all, 1, netmask) <0 )
			   {
					MessageBox(NULL,"Unable to compile the packet filter. Check the syntax","error",MB_OK);
			       /* 释放设备列表 */
			       pcap_freealldevs(alldevs);
			   }    
			}
//////////////设置过滤器	
	
			if (pcap_setfilter(adhandle, &fcode)<0)
			{
				MessageBox(NULL,"设置过滤规则失败","错误",MB_OK);
			    /* 释放设备列表 */
			    pcap_freealldevs(alldevs);
			}
					
			/* 释放设备列表 */
			pcap_freealldevs(alldevs);
			/* 开始捕捉 */
			pcap_loop(adhandle, 0, packet_handler, NULL);
// 			already_start=true;
		}
		else if (already_start==true)
		{
			pcap_loop(adhandle, 0, packet_handler, NULL);
		}
	}

}
void CReceive1Dlg::OnStart() 
{
	// TODO: Add your control notification handler code here
	m_bRun=true;

	hThread=CreateThread(NULL,
		0,
		(LPTHREAD_START_ROUTINE)ThreadFunc,
		NULL,
		0,
		&ThreadID);
}

void CReceive1Dlg::OnRadio1() 
{
// 	// TODO: Add your control notification handler code here
// 	if (pcap_compile(adhandle, &fcode, packet_filter_all, 1, netmask) <0 )
// 	{
// // 		fprintf(stderr,"\nUnable to compile the packet filter. Check the syntax.\n");
// 		MessageBox("Unable to compile the packet filter. Check the syntax","error",MB_OK);
// // 		/* 释放设备列表 */
// 		pcap_freealldevs(alldevs);
// 	}
	if (GetCheckedRadioButton(IDC_RADIO1,IDC_RADIO6)!=IDC_RADIO6)
	{
		m_fliter_src.SetReadOnly(true);
		m_fliter_src.SetWindowText("");
	}
	else
		m_fliter_src.SetReadOnly(FALSE);
	fileter='1';
}

void CReceive1Dlg::OnRadio2() 
{
// 	// TODO: Add your control notification handler code here
// 	if (pcap_compile(adhandle, &fcode, packet_filter_notarp, 1, netmask) <0 )
// 	{
// 		// 		fprintf(stderr,"\nUnable to compile the packet filter. Check the syntax.\n");
// 		MessageBox("Unable to compile the packet filter. Check the syntax","error",MB_OK);
// 		// 		/* 释放设备列表 */
// 		pcap_freealldevs(alldevs);
// 	}
	if (GetCheckedRadioButton(IDC_RADIO1,IDC_RADIO6)!=IDC_RADIO6)
	{
		m_fliter_src.SetReadOnly(true);
		m_fliter_src.SetWindowText("");

	}
	else
		m_fliter_src.SetReadOnly(FALSE);
	fileter='2';
}

void CReceive1Dlg::OnRadio3() 
{
// 	// TODO: Add your control notification handler code here
// 	if (pcap_compile(adhandle, &fcode, packet_filter_tcp, 1, netmask) <0 )
// 	{
// 		// 		fprintf(stderr,"\nUnable to compile the packet filter. Check the syntax.\n");
// 		MessageBox("Unable to compile the packet filter. Check the syntax","error",MB_OK);
// 		// 		/* 释放设备列表 */
// 		pcap_freealldevs(alldevs);
// 	}
	if (GetCheckedRadioButton(IDC_RADIO1,IDC_RADIO6)!=IDC_RADIO6)
	{
		m_fliter_src.SetReadOnly(true);
		m_fliter_src.SetWindowText("");

	}
	else
		m_fliter_src.SetReadOnly(FALSE);
	fileter='3';
}

void CReceive1Dlg::OnRadio4() 
{
// 	// TODO: Add your control notification handler code here
// 	if (pcap_compile(adhandle, &fcode, packet_filter_udp, 1, netmask) <0 )
// 	{
// 		// 		fprintf(stderr,"\nUnable to compile the packet filter. Check the syntax.\n");
// 		MessageBox("Unable to compile the packet filter. Check the syntax","error",MB_OK);
// 		// 		/* 释放设备列表 */
// 		pcap_freealldevs(alldevs);
// 	}
	if (GetCheckedRadioButton(IDC_RADIO1,IDC_RADIO6)!=IDC_RADIO6)
	{
		m_fliter_src.SetReadOnly(true);
		m_fliter_src.SetWindowText("");

	}
	else
		m_fliter_src.SetReadOnly(FALSE);
	fileter='4';
}

void CReceive1Dlg::OnRadio5() 
{
// 	// TODO: Add your control notification handler code here
// 	if (pcap_compile(adhandle, &fcode, packet_filter_icmp, 1, netmask) <0 )
// 	{
// 		// 		fprintf(stderr,"\nUnable to compile the packet filter. Check the syntax.\n");
// 		MessageBox("Unable to compile the packet filter. Check the syntax","error",MB_OK);
// 		// 		/* 释放设备列表 */
// 		pcap_freealldevs(alldevs);
// 	}

	fileter='5';
	if (GetCheckedRadioButton(IDC_RADIO1,IDC_RADIO6)!=IDC_RADIO6)
	{
		m_fliter_src.SetReadOnly(true);
		m_fliter_src.SetWindowText("");

	}
	else
		m_fliter_src.SetReadOnly(FALSE);
}

void CReceive1Dlg::OnRadio6() 
{
// 	// TODO: Add your control notification handler code here
// 	if (pcap_compile(adhandle, &fcode, packet_filter_src, 1, netmask) <0 )
// 	{
// // 		// 		fprintf(stderr,"\nUnable to compile the packet filter. Check the syntax.\n");
// 		MessageBox("Unable to compile the packet filter. Check the syntax","error",MB_OK);
// 		// 		/* 释放设备列表 */
// 		pcap_freealldevs(alldevs);
// 	}
	fileter='6';
	if (GetCheckedRadioButton(IDC_RADIO1,IDC_RADIO6)!=IDC_RADIO6)
	{
		m_fliter_src.SetReadOnly(true);
		m_fliter_src.SetWindowText("");
	}
	else
		m_fliter_src.SetReadOnly(FALSE);
	soumac="";
	for (int i=0;i<17;i++)
	{
		soumac_temp.Format("%c",packet_filter_src[10+i]);
		soumac+=soumac_temp;
	}
	m_fliter_src.SetWindowText(soumac);
}
void CReceive1Dlg::OnMyMessage(WPARAM wParam, LPARAM lParam){
	ShowList();
	packet2receive.readPacket();
	strtemp.Format("%d",packet2receive.smpCount);
	m_smpcount.SetWindowText(strtemp);

	//显示波形
	ShowWave();
	if (packet2receive.smpCount>=packet2receive.smpRate*256)
	{
		GetDlgItem(IDC_BUTTON_harm_ana)->EnableWindow(true);
		GetDlgItem(IDC_BUTTON_skew)->EnableWindow(true);
		GetDlgItem(IDC_BUTTON_flick)->EnableWindow(true);
		GetDlgItem(IDC_BUTTON_unbalance)->EnableWindow(true);
		GetDlgItem(IDC_BUTTON_freqdrift)->EnableWindow(true);
	}
}


/* 每次捕获到数据包时，会自动调用这个回调函数*/
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	if (m_bRun)
	{
//		::MessageBox(NULL,"Unable to compile the packet filter. Check the syntax","error",MB_OK);
	    struct tm *ltime;
	    char timestr[16];
	    time_t local_tv_sec;

//	    ip_header *ih;
//	    UDPHeader *uh;
//	    ARPFRAME *ah;
//	    u_int ip_len;
//	    u_short sport,dport; 
	    DLCHEADER *dlcheader;
	    u_short ethernet_type;
//	    ETHERNET_FRAME_PROTOCOL eth_pro;
	    ETHERNET_FRAME_TYPE eth_type;
	    unsigned char *ch;
		int i=0;
		CString str1;

	    /* 将时间戳转换成可识别的格式*/
	    local_tv_sec = header->ts.tv_sec;
	    ltime=localtime(&local_tv_sec);
	    strftime( timestr, sizeof timestr, "%H:%M:%S", ltime);

		pac.time.Format("%s",timestr);
		pac.sec.Format("%.6d",header->ts.tv_usec);
//		pac.time+=" :"+pac.sec;
		pac.len.Format("%d",header->len);

//		printf("\n%s, %.6d len:%d\n", timestr, header->ts.tv_usec, header->len);
	
	//	::MessageBox(NULL,timestr,"error",MB_OK);
	
//	    printf("-------------------以太网帧内容-------------------\n");
	    dlcheader = (DLCHEADER *)pkt_data; //获取以太网帧的首部

		pac.data="";
	    ch = ( unsigned char *)pkt_data;
	    for (unsigned ii = 0; ii < header ->len; ii++)
	    {
			packet2receive.packet[ii]=*(ch + ii);
			str1.Format("%02x",packet2receive.packet[ii]/**(ch + ii)*/);
//			memcpy(&r_packet[ii],str1,8);
// 			if (ii==53)
// 			{
// 				pac.data+="    ";
// 			}
			pac.data+=str1;

//	        printf("%02x ", *(ch + i));
//	        if (i % 16 == 15)
//	        {
//	            printf("\n");
//	        }    
	    }
// 		CString test=pac.data.Mid(53*2,4*2);
// // 		::MessageBox(NULL,"1234567890","error",MB_OK);
// // 		::MessageBox(NULL,HexCstringReverse("1234567890"),"error",MB_OK);
// 		int ttt=CstringHex2Int(test);
// 		if (ttt==8888)
// 		{
// 			::MessageBox(NULL,"睡觉吧","error",MB_OK);
// 
// 		}
// 		for (unsigned j = 0; j < header ->len; j++)
// 		{
// 			packet[j]=*(ch + j);
// 		}

//  		INT16U iii=packet[12] | packet[12]<<8;
//  		if (iii==8888)
//  		{
//  			::MessageBox(NULL,"4","error",MB_OK);
//  		}
	//	    printf("\n");
	//////////////////////////////////////////////////////////////////////////
// 		dlcheader = (DLCHEADER *)pkt_data; //获取以太网帧的首部
// 		ch=( unsigned char *)pkt_data;
// 		CString data="";
// 	    for ( i = 0; i < header ->len; i++)
// 			data+=*(ch+i);
// 	       printf("%02x ", *(ch + i));
	
	
// 	    printf("\n--------------------以太网帧首部--------------------\n");
// 	    printf("目标MAC地址: " );
		pac.des="";
	    for ( i = 0; i < 6; i++)
	    {
	        if (i != 5)
	        {
// 	            printf("%02x-", dlcheader->DesMAC[i]);
				str1.Format("%02x-",dlcheader->DesMAC[i]);
				pac.des+=str1;
	        }
			else{
// 	            printf("%02x\n", dlcheader->DesMAC[i]);
				str1.Format("%02x",dlcheader->DesMAC[i]);
				pac.des+=str1;
			}

	    }
		pac.des.MakeUpper();
// 	    printf("源MAC地址: " );
		pac.source="";
	    for ( i = 0; i < 6; i++)
	    {
	        if (i != 5)
	        {
// 	            printf("%02x-", dlcheader->SrcMAC[i]);
				str1.Format("%02x-",dlcheader->SrcMAC[i]);
				pac.source+=str1;
	        }
			else{
// 	            printf("%02x\n", dlcheader->SrcMAC[i]);
				str1.Format("%02x",dlcheader->SrcMAC[i]);
				pac.source+=str1;
			}
	    }
		pac.source.MakeUpper();


	    ethernet_type = ntohs(dlcheader->Ethertype);
	    eth_type = get_eth_type(ethernet_type, eth_match);

		pac.pro.Format("%s",eth_type.description);
//		pac.pro.Format("%02x",ethernet_type);

// 	    printf("以太网帧格式：0x%04x (%s)\n", ethernet_type, eth_type.description);
	
	    /* 获得IP数据包头部的位置 */
// 	    if (eth_type.type == IP)
// 	    {
// 	        ih = (ip_header *) (pkt_data +
// 	            14); //以太网头部长度
// 	        printf("\n--------------------IP头部详细内容--------------------\n");
// 	        printf("版本号和头长度(各占4位): 0x%02x", ih ->ver_ihl);
// 	        int lenth_byte = (ih ->ver_ihl) % 16;
// 	        int ip_type = (ih ->ver_ihl)/16;
// 	        if (ip_type == 4)
// 	        {
// 	            printf("(IPv4)\n");
// 	        }
// 	        else 
// 	            printf("\n");
// 	        printf("服务类型: 0x%02x\n", ih->tos);
// 	        printf("封包总长度(即整个IP报的长度): %d\n", ntohs(ih->tlen));
// 	        printf("封包标识(惟一标识发送的每一个数据报): 0x%04x\n", ntohs(ih->identification));
// 	        printf("标志(3位)和片位移(13位)： 0x%04x\n", ntohs(ih->flags_fo) );
// 	        printf("生存时间TTL: 0x%02x\n", ih ->ttl);
// 	        printf("协议类型: 0x%02x", ih->proto);
// 	        if (ih ->proto == 1)
// 	        {
// 	            printf("(ICMP)\n");
// 	        }
// 	        else if (ih ->proto == 6)
// 	        {
// 	            printf("(TCP)\n");
// 	        }
// 	        else if (ih ->proto == 17)
// 	        {
// 	            printf("(UDP)\n");
// 	        }
// 	        else if (ih ->proto == 2)
// 	        {
// 	            printf("(IGMP)\n");
// 	        }
// 	        else
// 	            printf("\n");
// 	        printf("16位首部校验和: 0x%04x\n", ntohs(ih ->crc));
// 	        printf("32位源ip地址： %d. %d. %d. %d\n", (ih ->saddr).byte1, (ih ->saddr).byte2, (ih ->saddr).byte3, (ih ->saddr).byte4);
// 	        printf("32位目的ip地址： %d. %d. %d. %d\n", (ih ->daddr).byte1, (ih ->daddr).byte2, (ih ->daddr).byte3, (ih ->daddr).byte4);
// 	        if (lenth_byte == 5)
// 	        {
// 	            printf("可选项内容为: 无\n");
// 	        }
// 	        else
// 	        {
// 	            printf("可选项内容为: ");
// 	            for (int i = 34; i < (lenth_byte - 5) * 4 + 34; i++ )
// 	            {
// 	                printf("%02x ", *(ch+ i));
// 	            }
// 	            printf("\n");
// 	        }
// 	        if (ih ->proto == 1)
// 	        {
// 	            printf("\n--------------------ICMP首部内容--------------------\n");
// 	            _ICMPHeader *icmph;
// 	            icmph = (_ICMPHeader *)(pkt_data + 34 + (lenth_byte - 5) * 4);
// 	            printf("ICMP类型： 0x%02x\n", icmph->icmp_type);
// 	            printf("ICMP代码：0x%02x\n", icmph ->icmp_code);
// 	            printf("校验和： 0x%04x\n", ntohs(icmph->icmp_checksum));
// 	            printf("标志符： 0x%04x\n", ntohs(icmph->icmp_id));
// 	            printf("序号： 0x%04x\n", ntohs(icmph->icmp_sequence));
// 	        }
// 	        else if (ih ->proto == 6)
// 	        {
// 	            printf("\n--------------------TCP首部内容--------------------\n");
// 	            _TCPHeader *tcph;
// 	            tcph = (_TCPHeader *)(pkt_data + 34 + (lenth_byte - 5) * 4);
// 	            printf("16位源端口：%d\n", ntohs(tcph ->sourcePort));
// 	            printf("16位目的端口：%d\n", ntohs(tcph->destinationPort));
// 	            printf("32位发送序号：%ld\n", ntohs(tcph->sequenceNumber));
// 	            printf("32位接收序号：%ld\n", ntohs(tcph->acknowledgeNumber));
// 	            printf("4位首部长度/6位保留字/6位标志位: 0x%04x\n", ntohs(tcph->dataoffset));
// 	            printf("16位窗口大小: %d\n", ntohs(tcph->windows));
// 	            printf("16位校验和: 0x%04x\n", ntohs(tcph->checksum));
// 	            printf("16位紧急数据偏移量： 0x%04x\n", ntohs(tcph->urgentPointer));
// 	        }
// 	        else if (ih ->proto == 17)
// 	        {
// 	            printf("\n--------------------UDP首部内容--------------------\n");
// 	            UDPHeader *udph;
// 	            udph = (UDPHeader *)(pkt_data + 34 + (lenth_byte - 5) * 4);
// 	            sport = ntohs( udph->sourcePort );
// 	            dport = ntohs( udph->destinationPort );
// 	            printf("16位UDP源端口号： %d\n", sport);
// 	            printf("16位UDP目的端口号： %d\n", dport);
// 	            printf("16位UDP长度： %d\n", ntohs(udph ->len));
// 	            printf("16位UDP校验和： 0x%04x\n", ntohs(udph ->checksum));
// 	        }
// 	        else
// 	            printf("\n");
// 	    }

// 	    else if (eth_type.type == ARP) //解析ARP数据包
// 	    {
// 	        ah = (ARPFRAME *) (pkt_data +
// 	            14); //以太网头部长度
// 	        printf("\n--------------------ARP数据帧详细内容--------------------\n");
// 	        printf("Hardware type: 0x%04x ", ntohs(ah->HW_Type));
// 	        if (ntohs(ah->HW_Type) == 1)
// 	        {
// 	            printf("(Ethernet)\n");
// 	        }
// 	        else
// 	            printf("\n");
// 	        printf("Protocol type: 0x%04x (%s)\n", ntohs(ah ->Prot_Type), get_eth_type( ntohs(ah ->Prot_Type), eth_match).description);
// 	        printf("Length of hardware address: %d\n", ah ->HW_Addr_Len);
// 	        printf("Length of protocol address: %d\n", ah ->Prot_Addr_Len);
// 	        printf("Opcode: 0x%04x (%s)\n", ntohs(ah ->Opcode), opcode_table[ntohs(ah ->Opcode)].description);
// 	        printf("Sender hardware address: ");
// 	        for ( i = 0; i < 6; i++)
// 	        {
// 	            if (i != 5)
// 	            {
// 	                printf("%x-", ah->Send_HW_Addr[i]);
// 	            }
// 	            else
// 	                printf("%x\n", ah ->Send_HW_Addr[i]);
// 	        }
// 	        printf("Sender ip address: ");
// 	        for ( i = 0; i < 4; i++)
// 	        {
// 	            if (i != 3)
// 	            {
// 	                printf("%d. ", ah ->Send_Prot_Addr[i]);
// 	            }
// 	            else 
// 	                printf("%d\n", ah ->Send_Prot_Addr[i]);
// 	        }
// 	        printf("Target hardware address: ");
// 	        for ( i = 0; i < 6; i++)
// 	        {
// 	            if (i != 5)
// 	            {
// 	                printf("%x-", ah->Targ_HW_Addr[i]);
// 	            }
// 	            else
// 	                printf("%x\n", ah ->Targ_HW_Addr[i]);
// 	        }
// 	        printf("Target ip address: ");
// 	        for (int i = 0; i < 4; i++)
// 	        {
// 	            if (i != 3)
// 	            {
// 	                printf("%d. ", ah ->Targ_Prot_Addr[i]);
// 	            }
// 	            else 
// 	                printf("%d\n", ah ->Targ_Prot_Addr[i]);
// 	        }
// 	    }
// 	    else
// 	        return;
	}
 	else
 		return;
//发送自定义消息
//	packet_message *pp=&pac;
	CWnd *p=AfxGetMainWnd();
	p->PostMessage(WM_MY_MESSAGE,0,0/*(WPARAM)pp,(LPARAM)pp*/);

}

void CReceive1Dlg::OnStop() 
{
	// TODO: Add your control notification handler code here
	m_bRun=false;
}

void CReceive1Dlg::OnButtonClear() 
{
	// TODO: Add your control notification handler code here
	m_list.DeleteAllItems();
	seq=0;
}

void CReceive1Dlg::OnTimer(UINT nIDEvent) 
{
	// TODO: Add your message handler code here and/or call default
//  	m_current_a.SetData( ( float ) GetRandom(20000,50000)/100 ) ;
	// 	m_ctrlMultiColorPlot.SetData( /*( float ) GetRandom(20000,50000)/100 */300) ;
// 	hThread=CreateThread(NULL,
// 		0,
// 		(LPTHREAD_START_ROUTINE)ThreadFunc1,
// 		this,
// 		0,
// 		&ThreadID);
	for (int ii=1;ii<=101;ii+=5)
	{
		m_progress.SetPos(ii);
		Sleep(1);
	}
	KillTimer(nIDEvent);

	CDialog::OnTimer(nIDEvent);
}

void CReceive1Dlg::GetMacAddress()
{
	//
	// 打开选定的网卡
	//
	LPADAPTER	lpAdapter = 0;
	PPACKET_OID_DATA  OidData;
	lpAdapter = PacketOpenAdapter(dev->name);
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
		(OidData->Data)[0];
		(OidData->Data)[1];
		(OidData->Data)[2];
		(OidData->Data)[3];
		(OidData->Data)[4];
		(OidData->Data)[5];
		CString str1;
		soumac="";
		for (int i = 0; i < 6; i++)
		{
			if (i != 5)
			{
				str1.Format("%02x:",(OidData->Data)[i]);
				soumac+=str1;
			}
			else{
				str1.Format("%02x",(OidData->Data)[i]);
				soumac+=str1;
			}
			
		}
		soumac.MakeUpper();
		m_soumac.SetWindowText(soumac);
		//			GetDlgItem(IDC_EDIT14)->EnableWindow(FALSE);
	}
	else
	{
		MessageBox("error retrieving the MAC address of the adapter!\n","error",MB_OK);
		//		printf("error retrieving the MAC address of the adapter!\n");
	}
	
	free(OidData);
	PacketCloseAdapter(lpAdapter);
}
void CReceive1Dlg::OnMyMessage1(WPARAM wParam, LPARAM lParam){
// 	LARGE_INTEGER litmp; 
// 	LONGLONG QPart1;
// 	double dfMinus, dfFreq, dfTim; 
// 	QueryPerformanceFrequency(&litmp); 
	// 获得计数器的时钟频率 
// 	dfFreq = (double)litmp.QuadPart; 
// 	QueryPerformanceCounter(&litmp); 
	// 获得初始值 
// 	QPart1 = litmp.QuadPart; 
	//  	Sleep(100) ; 
	//  	QueryPerformanceCounter(&litmp); 
	//  	// 获得终止值 
	//  	QPart2 = litmp.QuadPart; 
	//  	dfMinus = (double)(QPart2 - QPart1); 
	//  	dfTim = dfMinus / dfFreq; 
	//  	// 获得对应的时间值 
	// 	msec=::GetTickCount();
// 	double msec=(double)QPart1;
// 	msec/=1e11;//设置为秒
// 	m_current_a.SetData(300*sin(2*3.141592653*50*msec)) ;
}

void ThreadFunc1(CReceive1Dlg *DlgThis){
// 	CWnd *p=AfxGetMainWnd();
// 	p->PostMessage(WM_MY_MESSAGE1,0,0/*(WPARAM)pp,(LPARAM)pp*/);
// 	LARGE_INTEGER litmp; 
// 	LONGLONG QPart1;
// 	double dfMinus, dfFreq, dfTim; 
// 	QueryPerformanceFrequency(&litmp); 
	// 获得计数器的时钟频率 
// 	dfFreq = (double)litmp.QuadPart; 
// 	QueryPerformanceCounter(&litmp); 
	// 获得初始值 
// 	QPart1 = litmp.QuadPart; 
	//  	Sleep(100) ; 
	//  	QueryPerformanceCounter(&litmp); 
	//  	// 获得终止值 
	//  	QPart2 = litmp.QuadPart; 
	//  	dfMinus = (double)(QPart2 - QPart1); 
	//  	dfTim = dfMinus / dfFreq; 
	//  	// 获得对应的时间值 
	// 	msec=::GetTickCount();
// 	double msec=(double)QPart1;
// 	msec/=1e11;//设置为秒
// 	DlgThis->m_current_a.SetData(300*sin(2*3.141592653*50*msec)) ;
}

//DEL void CReceive1Dlg::DataRead_32(CString pdata, float value,int point)
//DEL {
//DEL //	CString str=pdata.Mid(point*2,4*2);
//DEL // 	value=CstringHex2Float(pdata.Mid(point*2,4*2));
//DEL 	unsigned char byte[4];
//DEL 	for(int i=0;i<4;i++){
//DEL 		byte[i]=packet[point++];
//DEL 	}
//DEL 	value=Hex_To_Decimal(byte);
//DEL }

//DEL void CReceive1Dlg::ReadSin(float A, float B, float C)
//DEL {
//DEL 
//DEL }

void CReceive1Dlg::OnRadio_Aabc() 
{
	// TODO: Add your control notification handler code here
	wav_A_flg=0;
	GetDlgItem(IDC_PLOT_CURRENT_A)->ShowWindow(!SW_HIDE);
	GetDlgItem(IDC_PLOT_CURRENT_B)->ShowWindow(!SW_HIDE);
	GetDlgItem(IDC_PLOT_CURRENT_C)->ShowWindow(!SW_HIDE);
	GetDlgItem(IDC_PLOT_CURRENT_ABC)->ShowWindow(SW_HIDE);
}

void CReceive1Dlg::OnRadio_Aa() 
{
	// TODO: Add your control notification handler code here
	wav_A_flg=1;
	GetDlgItem(IDC_PLOT_CURRENT_A)->ShowWindow(SW_HIDE);
	GetDlgItem(IDC_PLOT_CURRENT_B)->ShowWindow(SW_HIDE);
	GetDlgItem(IDC_PLOT_CURRENT_C)->ShowWindow(SW_HIDE);
	GetDlgItem(IDC_PLOT_CURRENT_ABC)->ShowWindow(!SW_HIDE);
	m_current_abc.SetTitle("A相电流:");
}

void CReceive1Dlg::OnRadio_Ab() 
{
	// TODO: Add your control notification handler code here
	wav_A_flg=2;
	GetDlgItem(IDC_PLOT_CURRENT_A)->ShowWindow(SW_HIDE);
	GetDlgItem(IDC_PLOT_CURRENT_B)->ShowWindow(SW_HIDE);
	GetDlgItem(IDC_PLOT_CURRENT_C)->ShowWindow(SW_HIDE);
	GetDlgItem(IDC_PLOT_CURRENT_ABC)->ShowWindow(!SW_HIDE);
	m_current_abc.SetTitle("B相电流:");
}

void CReceive1Dlg::OnRadio_Ac() 
{
	// TODO: Add your control notification handler code here
	wav_A_flg=3;
	GetDlgItem(IDC_PLOT_CURRENT_A)->ShowWindow(SW_HIDE);
	GetDlgItem(IDC_PLOT_CURRENT_B)->ShowWindow(SW_HIDE);
	GetDlgItem(IDC_PLOT_CURRENT_C)->ShowWindow(SW_HIDE);
	GetDlgItem(IDC_PLOT_CURRENT_ABC)->ShowWindow(!SW_HIDE);
	m_current_abc.SetTitle("C相电流:");
}
void CReceive1Dlg::OnRadio_Ashut() 
{
	// TODO: Add your control notification handler code here
	wav_A_flg=4;
	GetDlgItem(IDC_PLOT_CURRENT_A)->ShowWindow(SW_HIDE);
	GetDlgItem(IDC_PLOT_CURRENT_B)->ShowWindow(SW_HIDE);
	GetDlgItem(IDC_PLOT_CURRENT_C)->ShowWindow(SW_HIDE);
	GetDlgItem(IDC_PLOT_CURRENT_ABC)->ShowWindow(SW_HIDE);

}


//DEL void CReceive1Dlg::SetWave(float * value, int point)
//DEL {
//DEL 	unsigned char byte[4];
//DEL 	for(int i=0;i<4;i++){
//DEL 		byte[i]=packet[point++];
//DEL 	}
//DEL 	*(value)=Hex_To_Decimal(byte);
//DEL }

void CReceive1Dlg::OnChangeEDITflitersrc() 
{
	// TODO: If this is a RICHEDIT control, the control will not
	// send this notification unless you override the CDialog::OnInitDialog()
	// function and call CRichEditCtrl().SetEventMask()
	// with the ENM_CHANGE flag ORed into the mask.
	
	// TODO: Add your control notification handler code here
	m_fliter_src.GetWindowText(soumac);
	soumac_len=soumac.GetLength();
	//12:12:12:12:12:12
	if(soumac_len<=17)
		soumac_temp=soumac;
	else {
		m_fliter_src.SetWindowText(soumac_temp);
		soumac=soumac_temp;
		m_fliter_src.SetSel(-1);//是光标放在最后
	}
	if(soumac_len==2 || soumac_len==5 || soumac_len==8 || soumac_len==11 || soumac_len==14){
		soumac+=":";
		m_fliter_src.SetWindowText(soumac);
		m_fliter_src.SetSel(-1);//是光标放在最后
	}
//	sscanf(soumac,"%x:%x:%x:%x:%x:%x",&packet[6],&packet[7],&packet[8],&packet[9],&packet[10],&packet[11]);
//	char packet_filter_src[] = "ether src 02:02:02:02:02:02";
	if(soumac_len==17){
		for (int i=0;i<17;i++)
		{
			packet_filter_src[10+i]=soumac[i];
		}
	}
}


void CReceive1Dlg::OnRadio_Vabc() 
{
	// TODO: Add your control notification handler code here
	wav_V_flg=0;
	GetDlgItem(IDC_PLOT_VOLTAGE_A)->ShowWindow(!SW_HIDE);
	//	SetBkMode(GetDlgItem(IDC_PLOT_CURRENT_A),TRANSPARENT);
	GetDlgItem(IDC_PLOT_VOLTAGE_B)->ShowWindow(!SW_HIDE);
	GetDlgItem(IDC_PLOT_VOLTAGE_C)->ShowWindow(!SW_HIDE);
	GetDlgItem(IDC_PLOT_VOLTAGE_ABC)->ShowWindow(SW_HIDE);
// 
}

void CReceive1Dlg::OnRadio_Va() 
{
	// TODO: Add your control notification handler code here
	wav_V_flg=1;
	GetDlgItem(IDC_PLOT_VOLTAGE_A)->ShowWindow(SW_HIDE);
	GetDlgItem(IDC_PLOT_VOLTAGE_B)->ShowWindow(SW_HIDE);
	GetDlgItem(IDC_PLOT_VOLTAGE_C)->ShowWindow(SW_HIDE);
	GetDlgItem(IDC_PLOT_VOLTAGE_ABC)->ShowWindow(!SW_HIDE);
	m_voltage_abc.SetTitle("A相电压:");
}

void CReceive1Dlg::OnRadio_Vb() 
{
	// TODO: Add your control notification handler code here
	wav_V_flg=2;
	GetDlgItem(IDC_PLOT_VOLTAGE_A)->ShowWindow(SW_HIDE);
	GetDlgItem(IDC_PLOT_VOLTAGE_B)->ShowWindow(SW_HIDE);
	GetDlgItem(IDC_PLOT_VOLTAGE_C)->ShowWindow(SW_HIDE);
	GetDlgItem(IDC_PLOT_VOLTAGE_ABC)->ShowWindow(!SW_HIDE);
	m_voltage_abc.SetTitle("B相电压:");	
}

void CReceive1Dlg::OnRadio_Vc() 
{
	// TODO: Add your control notification handler code here
	wav_V_flg=3;
	GetDlgItem(IDC_PLOT_VOLTAGE_A)->ShowWindow(SW_HIDE);
	GetDlgItem(IDC_PLOT_VOLTAGE_B)->ShowWindow(SW_HIDE);
	GetDlgItem(IDC_PLOT_VOLTAGE_C)->ShowWindow(SW_HIDE);
	GetDlgItem(IDC_PLOT_VOLTAGE_ABC)->ShowWindow(!SW_HIDE);
	m_voltage_abc.SetTitle("C相电压:");
}

void CReceive1Dlg::OnRadio_Vshut() 
{
	// TODO: Add your control notification handler code here
	wav_V_flg=4;
	GetDlgItem(IDC_PLOT_VOLTAGE_A)->ShowWindow(SW_HIDE);
	GetDlgItem(IDC_PLOT_VOLTAGE_B)->ShowWindow(SW_HIDE);
	GetDlgItem(IDC_PLOT_VOLTAGE_C)->ShowWindow(SW_HIDE);
	GetDlgItem(IDC_PLOT_VOLTAGE_ABC)->ShowWindow(SW_HIDE);
	
}

void CReceive1Dlg::ShowWave()
{
	if (wav_A_flg!=4 && packet2receive.smpCount%sliderA==0)
	{
		if(wav_A_flg==0){
			m_current_a.SetData(packet2receive.data_to_receive.currentA[packet2receive.smpCount-1]);
			m_current_b.SetData(packet2receive.data_to_receive.currentB[packet2receive.smpCount-1]);
			m_current_c.SetData(packet2receive.data_to_receive.currentC[packet2receive.smpCount-1]);
		}
		else if (wav_A_flg==1)
		{
			m_current_abc.SetData(packet2receive.data_to_receive.currentA[packet2receive.smpCount-1]);
		}
		else if (wav_A_flg==2)
		{
			m_current_abc.SetData(packet2receive.data_to_receive.currentB[packet2receive.smpCount-1]);
		}
		else if (wav_A_flg==3)
		{
			m_current_abc.SetData(packet2receive.data_to_receive.currentC[packet2receive.smpCount-1]);
		}
	}
	if (wav_V_flg!=4 && packet2receive.smpCount%sliderA==0)
	{
		//波形显示
		if(wav_V_flg==0){
			m_voltage_a.SetData(packet2receive.data_to_receive.VoltageA[packet2receive.smpCount-1]);
			m_voltage_b.SetData(packet2receive.data_to_receive.VoltageB[packet2receive.smpCount-1]);
			m_voltage_c.SetData(packet2receive.data_to_receive.VoltageC[packet2receive.smpCount-1]);
		}
		else if (wav_V_flg==1)
		{
			m_voltage_abc.SetData(packet2receive.data_to_receive.VoltageA[packet2receive.smpCount-1]);
		}
		else if (wav_V_flg==2)
		{
			m_voltage_abc.SetData(packet2receive.data_to_receive.VoltageB[packet2receive.smpCount-1]);
		}
		else if (wav_V_flg==3)
		{
			m_voltage_abc.SetData(packet2receive.data_to_receive.VoltageC[packet2receive.smpCount-1]);
		}
	}
}

void CReceive1Dlg::ShowList()
{
	if (list_flg!=0)
	{
		CString strText;
		// 		int nColumnCount = m_list.GetHeaderCtrl()->GetItemCount();
		
		// Insert 10 items in the list view control.
		// 		for (int i=0;i < 20;i++)
		// 		{
		//显示序号
		
		strText.Format(TEXT("%d"), seq+1);		
		// Insert the item, select every other item.
		m_list.InsertItem(LVIF_TEXT|LVIF_STATE, seq, strText, 
			(seq%2)==0 ? LVIS_SELECTED : 0, LVIS_SELECTED,
			0, 0);

		if (list_flg==1)
		{
			m_list.SetItemText(seq,1,pac.time);  
			m_list.SetItemText(seq,2,pac.len);  
			m_list.SetItemText(seq,3,pac.source);  
			m_list.SetItemText(seq,4,pac.des);
			m_list.SetItemText(seq,5,pac.pro); 
			m_list.SetItemText(seq,6,pac.data); 
		}

		seq++;
		
		// Ensure that the last item is visible.
		m_list.EnsureVisible(seq-1, FALSE);
		
		
		
		// 				int nCount = m_list.GetItemCount();
		// 				if (nCount > 0)
		// 					m_list.EnsureVisible(nCount-1, FALSE);
	// 			}
	}
}

void CReceive1Dlg::OnRADIOliston() 
{
	// TODO: Add your control notification handler code here
	list_flg=1;
}

void CReceive1Dlg::OnRADIOlistseq() 
{
	// TODO: Add your control notification handler code here
	list_flg=2;
}

BOOL CReceive1Dlg::DestroyWindow() 
{
	// TODO: Add your specialized code here and/or call the base class

	return CDialog::DestroyWindow();
}

void CReceive1Dlg::OnDropdownCOMBOharm() 
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

void CReceive1Dlg::OnDropdownCOMBOskew() 
{
	// TODO: Add your control notification handler code here
	m_skewList.ResetContent();
	CString list="";
	int index=0;
	list="A相电流";
	m_skewList.InsertString(index++,list);
	list="B相电流";
	m_skewList.InsertString(index++,list);
	list="C相电流";
	m_skewList.InsertString(index++,list);
	list="A相电压";
	m_skewList.InsertString(index++,list);
	list="B相电压";
	m_skewList.InsertString(index++,list);
	list="C相电压";
	m_skewList.InsertString(index++,list);

}

void CReceive1Dlg::OnDropdownCOMBOflick() 
{
	// TODO: Add your control notification handler code here
	m_flickList.ResetContent();
	CString list="";
	int index=0;
	list="A相电流";
	m_flickList.InsertString(index++,list);
	list="B相电流";
	m_flickList.InsertString(index++,list);
	list="C相电流";
	m_flickList.InsertString(index++,list);
	list="A相电压";
	m_flickList.InsertString(index++,list);
	list="B相电压";
	m_flickList.InsertString(index++,list);
	list="C相电压";
	m_flickList.InsertString(index++,list);

}

void CReceive1Dlg::OnDropdownCOMBOfreqDriftList() 
{
	// TODO: Add your control notification handler code here
	m_freqdriftList.ResetContent();
	CString list="";
	int index=0;
	list="A相电流";
	m_freqdriftList.InsertString(index++,list);
	list="B相电流";
	m_freqdriftList.InsertString(index++,list);
	list="C相电流";
	m_freqdriftList.InsertString(index++,list);
	list="A相电压";
	m_freqdriftList.InsertString(index++,list);
	list="B相电压";
	m_freqdriftList.InsertString(index++,list);
	list="C相电压";
	m_freqdriftList.InsertString(index++,list);

}

void CReceive1Dlg::OnDropdownCOMBOunbalance() 
{
	// TODO: Add your control notification handler code here
	m_unbalanceList.ResetContent();
	CString list="";
	int index=0;
	list="电流";
	m_unbalanceList.InsertString(index++,list);
	list="电压";
	m_unbalanceList.InsertString(index++,list);
}

void CReceive1Dlg::OnSelchangeCOMBOflick() 
{
	// TODO: Add your control notification handler code here
	flick_cursel=m_flickList.GetCurSel();
}

void CReceive1Dlg::OnSelchangeCOMBOfreqDriftList() 
{
	// TODO: Add your control notification handler code here
	freqdrift_cursel=m_freqdriftList.GetCurSel();
}

void CReceive1Dlg::OnSelchangeCOMBOharm() 
{
	// TODO: Add your control notification handler code here
	harm_cursel=m_harmList.GetCurSel();
}

void CReceive1Dlg::OnSelchangeCOMBOskew() 
{
	// TODO: Add your control notification handler code here
	skew_cursel=m_skewList.GetCurSel();
}

void CReceive1Dlg::OnSelchangeCOMBOunbalance() 
{
	// TODO: Add your control notification handler code here
	unbalance_cursel=m_unbalanceList.GetCurSel();
}

void CReceive1Dlg::OnBUTTONharmana() 
{
	// TODO: Add your control notification handler code here
	Calculate();
	CString str;
	int h;
	int x,j;
	int b=0;
	double d[100]={0},am[100]={0},fm[100]={0};
	double Hru;
	double U1=sqrt(2)*youxiaozhi;
	m_harm_h.GetWindowText(str);
	int hh=atoi(str);
	double Uh=0,Thd;

	switch (harm_cursel)
	{
	case NN: MessageBox("请选择分析项","请选择",MB_OK);
		break;
	case Aa:
		S=0;
		for(i=0;i<256*caiyanglv;i++)                           //给结构体赋值
		{
			double w=0.5-0.5*cos(2*PI*i/FFT_N);
			s[i].real=packet2receive.data_to_receive.currentA[i]; //实部为正弦波FFT_N点采样，赋值为1
			s[i].imag=0;                                //虚部为0
			temp[i].real=s[i].real;
			temp[i].imag=0;
			S=S+s[i].real*s[i].real; 
			s[i].real=s[i].real*w; 
		}
		FFT(s);    //进行快速福利叶变换
		for(i=0;i<FFT_N;i++)
		{                           //求变换后结果的模值
			Am[i]=sqrt(s[i].real*s[i].real+s[i].imag*s[i].imag);
			//	cout<<Am[i]<<endl;
		}

		for(h=1;h<=31;h++)
		{
			for(i=(int)(h*50*(FFT_N*0.02/caiyanglv))-2;i<=(int)(h*50*(FFT_N*0.02/caiyanglv))+3;i++)
			{
				if(Am[i]<=Am[i+1]) j=i+1;
				else if(Am[j]<=Am[i])j=i;
				else j=j;
				
			}
			x=-1;
			c=Am[j+1]/Am[j];
			e=sqrt((2*c-1)/(c+1)*(2*c-1)/(c+1));
			am[h]=2*PI*e*(1-e*e)/sin(PI*e)*Am[j];
			am[h]=am[h]*2/FFT_N;
			fm[h]=(j-e)*1/(FFT_N*0.02/caiyanglv);
			d[h]=atan2(s[j].imag,s[j].real)-x*e*PI*(FFT_N-1)/FFT_N;
			d[h]=d[h]*180/PI;
		}
		Hru=am[hh]/U1*100;
		str.Format("%f",Hru);
		m_harm_hru.SetWindowText(str+"%");

		for (i=2;i<=31;i++)
		{
			//	cout<<am[i]<<endl;
			Uh+=am[i]*am[i];
			//	cout<<Uh<<endl;
		}
		Uh=sqrt(Uh);
		Thd =Uh/U1*100;
		str.Format("%f",Thd);
		m_harm_total.SetWindowText(str+"%");
		break;
	case Ab:
		S=0;
		for(i=0;i<256*caiyanglv;i++)                           //给结构体赋值
		{
			double w=0.5-0.5*cos(2*PI*i/FFT_N);
			s[i].real=packet2receive.data_to_receive.currentB[i]; //实部为正弦波FFT_N点采样，赋值为1
			s[i].imag=0;                                //虚部为0
			temp[i].real=s[i].real;
			temp[i].imag=0;
			S=S+s[i].real*s[i].real; 
			s[i].real=s[i].real*w; 
		}
		FFT(s);    //进行快速福利叶变换
		for(i=0;i<FFT_N;i++)
		{                           //求变换后结果的模值
			Am[i]=sqrt(s[i].real*s[i].real+s[i].imag*s[i].imag);
			//	cout<<Am[i]<<endl;
		}
		
		for(h=1;h<=31;h++)
		{
			for(i=(int)(h*50*(FFT_N*0.02/caiyanglv))-2;i<=(int)(h*50*(FFT_N*0.02/caiyanglv))+3;i++)
			{
				if(Am[i]<=Am[i+1]) j=i+1;
				else if(Am[j]<=Am[i])j=i;
				else j=j;
				
			}
			x=-1;
			c=Am[j+1]/Am[j];
			e=sqrt((2*c-1)/(c+1)*(2*c-1)/(c+1));
			am[h]=2*PI*e*(1-e*e)/sin(PI*e)*Am[j];
			am[h]=am[h]*2/FFT_N;
			fm[h]=(j-e)*1/(FFT_N*0.02/caiyanglv);
			d[h]=atan2(s[j].imag,s[j].real)-x*e*PI*(FFT_N-1)/FFT_N;
			d[h]=d[h]*180/PI;
		}
		Hru=am[hh]/U1*100;
		str.Format("%f",Hru);
		m_harm_hru.SetWindowText(str+"%");
		
		for (i=2;i<=31;i++)
		{
			//	cout<<am[i]<<endl;
			Uh+=am[i]*am[i];
			//	cout<<Uh<<endl;
		}
		Uh=sqrt(Uh);
		Thd =Uh/U1*100;
		str.Format("%f",Thd);
		m_harm_total.SetWindowText(str+"%");
		break;
	case Ac:
		S=0;
		for(i=0;i<256*caiyanglv;i++)                           //给结构体赋值
		{
			double w=0.5-0.5*cos(2*PI*i/FFT_N);
			s[i].real=packet2receive.data_to_receive.currentC[i]; //实部为正弦波FFT_N点采样，赋值为1
			s[i].imag=0;                                //虚部为0
			temp[i].real=s[i].real;
			temp[i].imag=0;
			S=S+s[i].real*s[i].real; 
			s[i].real=s[i].real*w; 
		}
		FFT(s);    //进行快速福利叶变换
		for(i=0;i<FFT_N;i++)
		{                           //求变换后结果的模值
			Am[i]=sqrt(s[i].real*s[i].real+s[i].imag*s[i].imag);
			//	cout<<Am[i]<<endl;
		}
		
		for(h=1;h<=31;h++)
		{
			for(i=(int)(h*50*(FFT_N*0.02/caiyanglv))-2;i<=(int)(h*50*(FFT_N*0.02/caiyanglv))+3;i++)
			{
				if(Am[i]<=Am[i+1]) j=i+1;
				else if(Am[j]<=Am[i])j=i;
				else j=j;
				
			}
			x=-1;
			c=Am[j+1]/Am[j];
			e=sqrt((2*c-1)/(c+1)*(2*c-1)/(c+1));
			am[h]=2*PI*e*(1-e*e)/sin(PI*e)*Am[j];
			am[h]=am[h]*2/FFT_N;
			fm[h]=(j-e)*1/(FFT_N*0.02/caiyanglv);
			d[h]=atan2(s[j].imag,s[j].real)-x*e*PI*(FFT_N-1)/FFT_N;
			d[h]=d[h]*180/PI;
		}
		Hru=am[hh]/U1*100;
		str.Format("%f",Hru);
		m_harm_hru.SetWindowText(str+"%");
		
		for (i=2;i<=31;i++)
		{
			//	cout<<am[i]<<endl;
			Uh+=am[i]*am[i];
			//	cout<<Uh<<endl;
		}
		Uh=sqrt(Uh);
		Thd =Uh/U1*100;
		str.Format("%f",Thd);
		m_harm_total.SetWindowText(str+"%");
		break;
	case Va:
		S=0;
		for(i=0;i<256*caiyanglv;i++)                           //给结构体赋值
		{
			double w=0.5-0.5*cos(2*PI*i/FFT_N);
			s[i].real=packet2receive.data_to_receive.VoltageA[i]; //实部为正弦波FFT_N点采样，赋值为1
			s[i].imag=0;                                //虚部为0
			temp[i].real=s[i].real;
			temp[i].imag=0;
			S=S+s[i].real*s[i].real; 
			s[i].real=s[i].real*w; 
		}
		FFT(s);    //进行快速福利叶变换
		for(i=0;i<FFT_N;i++)
		{                           //求变换后结果的模值
			Am[i]=sqrt(s[i].real*s[i].real+s[i].imag*s[i].imag);
			//	cout<<Am[i]<<endl;
		}
		
		for(h=1;h<=31;h++)
		{
			for(i=(int)(h*50*(FFT_N*0.02/caiyanglv))-2;i<=(int)(h*50*(FFT_N*0.02/caiyanglv))+3;i++)
			{
				if(Am[i]<=Am[i+1]) j=i+1;
				else if(Am[j]<=Am[i])j=i;
				else j=j;
				
			}
			x=-1;
			c=Am[j+1]/Am[j];
			e=sqrt((2*c-1)/(c+1)*(2*c-1)/(c+1));
			am[h]=2*PI*e*(1-e*e)/sin(PI*e)*Am[j];
			am[h]=am[h]*2/FFT_N;
			fm[h]=(j-e)*1/(FFT_N*0.02/caiyanglv);
			d[h]=atan2(s[j].imag,s[j].real)-x*e*PI*(FFT_N-1)/FFT_N;
			d[h]=d[h]*180/PI;
		}
		Hru=am[hh]/U1*100;
		str.Format("%f",Hru);
		m_harm_hru.SetWindowText(str+"%");
		
		for (i=2;i<=31;i++)
		{
			//	cout<<am[i]<<endl;
			Uh+=am[i]*am[i];
			//	cout<<Uh<<endl;
		}
		Uh=sqrt(Uh);
		Thd =Uh/U1*100;
		str.Format("%f",Thd);
		m_harm_total.SetWindowText(str+"%");
		break;
	case Vb:
		S=0;
		for(i=0;i<256*caiyanglv;i++)                           //给结构体赋值
		{
			double w=0.5-0.5*cos(2*PI*i/FFT_N);
			s[i].real=packet2receive.data_to_receive.VoltageB[i]; //实部为正弦波FFT_N点采样，赋值为1
			s[i].imag=0;                                //虚部为0
			temp[i].real=s[i].real;
			temp[i].imag=0;
			S=S+s[i].real*s[i].real; 
			s[i].real=s[i].real*w; 
		}
		FFT(s);    //进行快速福利叶变换
		for(i=0;i<FFT_N;i++)
		{                           //求变换后结果的模值
			Am[i]=sqrt(s[i].real*s[i].real+s[i].imag*s[i].imag);
			//	cout<<Am[i]<<endl;
		}
		
		for(h=1;h<=31;h++)
		{
			for(i=(int)(h*50*(FFT_N*0.02/caiyanglv))-2;i<=(int)(h*50*(FFT_N*0.02/caiyanglv))+3;i++)
			{
				if(Am[i]<=Am[i+1]) j=i+1;
				else if(Am[j]<=Am[i])j=i;
				else j=j;
				
			}
			x=-1;
			c=Am[j+1]/Am[j];
			e=sqrt((2*c-1)/(c+1)*(2*c-1)/(c+1));
			am[h]=2*PI*e*(1-e*e)/sin(PI*e)*Am[j];
			am[h]=am[h]*2/FFT_N;
			fm[h]=(j-e)*1/(FFT_N*0.02/caiyanglv);
			d[h]=atan2(s[j].imag,s[j].real)-x*e*PI*(FFT_N-1)/FFT_N;
			d[h]=d[h]*180/PI;
		}
		Hru=am[hh]/U1*100;
		str.Format("%f",Hru);
		m_harm_hru.SetWindowText(str+"%");
		
		for (i=2;i<=31;i++)
		{
			//	cout<<am[i]<<endl;
			Uh+=am[i]*am[i];
			//	cout<<Uh<<endl;
		}
		Uh=sqrt(Uh);
		Thd =Uh/U1*100;
		str.Format("%f",Thd);
		m_harm_total.SetWindowText(str+"%");
		break;
	case Vc:
		S=0;
		for(i=0;i<256*caiyanglv;i++)                           //给结构体赋值
		{
			double w=0.5-0.5*cos(2*PI*i/FFT_N);
			s[i].real=packet2receive.data_to_receive.VoltageC[i]; //实部为正弦波FFT_N点采样，赋值为1
			s[i].imag=0;                                //虚部为0
			temp[i].real=s[i].real;
			temp[i].imag=0;
			S=S+s[i].real*s[i].real; 
			s[i].real=s[i].real*w; 
		}
		FFT(s);    //进行快速福利叶变换
		for(i=0;i<FFT_N;i++)
		{                           //求变换后结果的模值
			Am[i]=sqrt(s[i].real*s[i].real+s[i].imag*s[i].imag);
			//	cout<<Am[i]<<endl;
		}
		
		for(h=1;h<=31;h++)
		{
			for(i=(int)(h*50*(FFT_N*0.02/caiyanglv))-2;i<=(int)(h*50*(FFT_N*0.02/caiyanglv))+3;i++)
			{
				if(Am[i]<=Am[i+1]) j=i+1;
				else if(Am[j]<=Am[i])j=i;
				else j=j;
				
			}
			x=-1;
			c=Am[j+1]/Am[j];
			e=sqrt((2*c-1)/(c+1)*(2*c-1)/(c+1));
			am[h]=2*PI*e*(1-e*e)/sin(PI*e)*Am[j];
			am[h]=am[h]*2/FFT_N;
			fm[h]=(j-e)*1/(FFT_N*0.02/caiyanglv);
			d[h]=atan2(s[j].imag,s[j].real)-x*e*PI*(FFT_N-1)/FFT_N;
			d[h]=d[h]*180/PI;
		}
		Hru=am[hh]/U1*100;
		str.Format("%f",Hru);
		m_harm_hru.SetWindowText(str+"%");
		
		for (i=2;i<=31;i++)
		{
			//	cout<<am[i]<<endl;
			Uh+=am[i]*am[i];
			//	cout<<Uh<<endl;
		}
		Uh=sqrt(Uh);
		Thd =Uh/U1*100;
		str.Format("%f",Thd);
		m_harm_total.SetWindowText(str+"%");
		break;
	}
}

void CReceive1Dlg::OnButtonSkew() 
{
	// TODO: Add your control notification handler code here
	Calculate();
	CString str;
	double oU;
	switch (skew_cursel)
	{
	case NN: MessageBox("请选择分析项","请选择",MB_OK);
		break;
	case Aa:
		S=0;
		for(i=0;i<256*caiyanglv;i++)                           //给结构体赋值
		{
			double w=0.5-0.5*cos(2*PI*i/FFT_N);
			s[i].real=packet2receive.data_to_receive.currentA[i]; //实部为正弦波FFT_N点采样，赋值为1
			s[i].imag=0;                                //虚部为0
			temp[i].real=s[i].real;
			temp[i].imag=0;
			S=S+s[i].real*s[i].real; 
			s[i].real=s[i].real*w; 
		}
		FFT(s);    //进行快速福利叶变换
		for(i=0;i<FFT_N;i++)
		{                           //求变换后结果的模值
			Am[i]=sqrt(s[i].real*s[i].real+s[i].imag*s[i].imag);
			//	cout<<Am[i]<<endl;
		}
		ss=0;
		ss=sqrt(1.0/(256*caiyanglv)*S);
		str.Format("%f",ss);
		m_skew_youxiaozhi.SetWindowText(str);

		oU=sqrt((ss-youxiaozhi)*(ss-youxiaozhi));
		oU=oU/youxiaozhi*100;
		str.Format("%f",oU);
		m_skew_skew.SetWindowText(str+"%");

		break;
	case Ab:
		S=0;
		for(i=0;i<256*caiyanglv;i++)                           //给结构体赋值
		{
			double w=0.5-0.5*cos(2*PI*i/FFT_N);
			s[i].real=packet2receive.data_to_receive.currentB[i]; //实部为正弦波FFT_N点采样，赋值为1
			s[i].imag=0;                                //虚部为0
			temp[i].real=s[i].real;
			temp[i].imag=0;
			S=S+s[i].real*s[i].real; 
			s[i].real=s[i].real*w; 
		}
		FFT(s);    //进行快速福利叶变换
		for(i=0;i<FFT_N;i++)
		{                           //求变换后结果的模值
			Am[i]=sqrt(s[i].real*s[i].real+s[i].imag*s[i].imag);
			//	cout<<Am[i]<<endl;
		}
		ss=0;
		ss=sqrt(1.0/(256*caiyanglv)*S);
		str.Format("%f",ss);
		m_skew_youxiaozhi.SetWindowText(str);
		
		oU=sqrt((ss-youxiaozhi)*(ss-youxiaozhi));
		oU=oU/youxiaozhi*100;
		str.Format("%f",oU);
		m_skew_skew.SetWindowText(str+"%");
		break;
	case Ac:
		S=0;
		for(i=0;i<256*caiyanglv;i++)                           //给结构体赋值
		{
			double w=0.5-0.5*cos(2*PI*i/FFT_N);
			s[i].real=packet2receive.data_to_receive.currentC[i]; //实部为正弦波FFT_N点采样，赋值为1
			s[i].imag=0;                                //虚部为0
			temp[i].real=s[i].real;
			temp[i].imag=0;
			S=S+s[i].real*s[i].real; 
			s[i].real=s[i].real*w; 
		}
		FFT(s);    //进行快速福利叶变换
		for(i=0;i<FFT_N;i++)
		{                           //求变换后结果的模值
			Am[i]=sqrt(s[i].real*s[i].real+s[i].imag*s[i].imag);
			//	cout<<Am[i]<<endl;
		}
		ss=0;
		ss=sqrt(1.0/(256*caiyanglv)*S);
		str.Format("%f",ss);
		m_skew_youxiaozhi.SetWindowText(str);
		
		oU=sqrt((ss-youxiaozhi)*(ss-youxiaozhi));
		oU=oU/youxiaozhi*100;
		str.Format("%f",oU);
		m_skew_skew.SetWindowText(str+"%");
		break;
	case Va:
		S=0;
		for(i=0;i<256*caiyanglv;i++)                           //给结构体赋值
		{
			double w=0.5-0.5*cos(2*PI*i/FFT_N);
			s[i].real=packet2receive.data_to_receive.VoltageA[i]; //实部为正弦波FFT_N点采样，赋值为1
			s[i].imag=0;                                //虚部为0
			temp[i].real=s[i].real;
			temp[i].imag=0;
			S=S+s[i].real*s[i].real; 
			s[i].real=s[i].real*w; 
		}
		FFT(s);    //进行快速福利叶变换
		for(i=0;i<FFT_N;i++)
		{                           //求变换后结果的模值
			Am[i]=sqrt(s[i].real*s[i].real+s[i].imag*s[i].imag);
			//	cout<<Am[i]<<endl;
		}
		ss=0;
		ss=sqrt(1.0/(256*caiyanglv)*S);
		str.Format("%f",ss);
		m_skew_youxiaozhi.SetWindowText(str);
		
		oU=sqrt((ss-youxiaozhi)*(ss-youxiaozhi));
		oU=oU/youxiaozhi*100;
		str.Format("%f",oU);
		m_skew_skew.SetWindowText(str+"%");
		break;
	case Vb:
		S=0;
		for(i=0;i<256*caiyanglv;i++)                           //给结构体赋值
		{
			double w=0.5-0.5*cos(2*PI*i/FFT_N);
			s[i].real=packet2receive.data_to_receive.VoltageB[i]; //实部为正弦波FFT_N点采样，赋值为1
			s[i].imag=0;                                //虚部为0
			temp[i].real=s[i].real;
			temp[i].imag=0;
			S=S+s[i].real*s[i].real; 
			s[i].real=s[i].real*w; 
		}
		FFT(s);    //进行快速福利叶变换
		for(i=0;i<FFT_N;i++)
		{                           //求变换后结果的模值
			Am[i]=sqrt(s[i].real*s[i].real+s[i].imag*s[i].imag);
			//	cout<<Am[i]<<endl;
		}
		ss=0;
		ss=sqrt(1.0/(256*caiyanglv)*S);
		str.Format("%f",ss);
		m_skew_youxiaozhi.SetWindowText(str);
		
		oU=sqrt((ss-youxiaozhi)*(ss-youxiaozhi));
		oU=oU/youxiaozhi*100;
		str.Format("%f",oU);
		m_skew_skew.SetWindowText(str+"%");
		break;
	case Vc:
		S=0;
		for(i=0;i<256*caiyanglv;i++)                           //给结构体赋值
		{
			double w=0.5-0.5*cos(2*PI*i/FFT_N);
			s[i].real=packet2receive.data_to_receive.VoltageC[i]; //实部为正弦波FFT_N点采样，赋值为1
			s[i].imag=0;                                //虚部为0
			temp[i].real=s[i].real;
			temp[i].imag=0;
			S=S+s[i].real*s[i].real; 
			s[i].real=s[i].real*w; 
		}
		FFT(s);    //进行快速福利叶变换
		for(i=0;i<FFT_N;i++)
		{                           //求变换后结果的模值
			Am[i]=sqrt(s[i].real*s[i].real+s[i].imag*s[i].imag);
			//	cout<<Am[i]<<endl;
		}
		ss=0;
		ss=sqrt(1.0/(256*caiyanglv)*S);
		str.Format("%f",ss);
		m_skew_youxiaozhi.SetWindowText(str);
		
		oU=sqrt((ss-youxiaozhi)*(ss-youxiaozhi));
		oU=oU/youxiaozhi*100;
		str.Format("%f",oU);
		m_skew_skew.SetWindowText(str+"%");
		break;
	}

}

void CReceive1Dlg::OnButton_flick() 
{	
	Calculate();
	CString str;
	double U0,U[256],A[256];
	double d,j=0,h,t,p,b=0;
	compx z[500];
	int f=0,U_N;

	U_N=256*caiyanglv; 
	d=U_N/256;
	while(j<U_N)
	{
		U0=0;
		for(i=j;i<j+d;i++)                       
		{
			U0=U0+temp[i].real*temp[i].real; 			
		}
		U[(int)(j/d)]=sqrt(1.0/d*U0);
		z[(int)(j/d)].real=U[(int)(j/d)];
		z[(int)(j/d)].imag=0;
		j=j+d;
	}

	double high,low;

	switch (flick_cursel)
	{
	case NN: MessageBox("请选择分析项","请选择",MB_OK);
		break;
	case Aa:
		S=0;
		for(i=0;i<256*caiyanglv;i++)                           //给结构体赋值
		{
			double w=0.5-0.5*cos(2*PI*i/FFT_N);
			s[i].real=packet2receive.data_to_receive.currentA[i]; //实部为正弦波FFT_N点采样，赋值为1
			s[i].imag=0;                                //虚部为0
			temp[i].real=s[i].real;
			temp[i].imag=0;
			S=S+s[i].real*s[i].real; 
			s[i].real=s[i].real*w; 
		}
		FFT(s);    //进行快速福利叶变换
		for(i=0;i<FFT_N;i++)
		{                           //求变换后结果的模值
			Am[i]=sqrt(s[i].real*s[i].real+s[i].imag*s[i].imag);
			//	cout<<Am[i]<<endl;
		}
		high=U[0],low=U[0];

		for(i=0;i<256;i++)
		{
			if(U[i]>high)
			{
				high=U[i];
				//		   cout<<i<<"       "<<h<<endl;
			}
			else if(U[i]<low)
			{
				low=U[i];
			}
		}
		d=high-low;
		d=d/youxiaozhi*100;
		str.Format("%f",d);
		m_flick_fluctuate.SetWindowText(str+"%");

		FFT1(z);
		for(i=0;i<256;i++)
		{                           //求变换后结果的模值
			A[i]=sqrt(z[i].real*z[i].real+z[i].imag*z[i].imag);
		}
		h=A[1];
		for(i=1;i<154;i++)
		{
			if(h<=A[i])
			{
				h=A[i];
				t=i;
			}
		}
		h=h*2.0/256.0;
		t=t*0.195;
		//cout<<h<<"   "<<t<<endl;
		if(-0.25<=t-0.5&&t-0.5<0.25)
		{
			b=2.34;
		}
		else if(-0.25<=t-1&&t-1<0.25)
		{
			 b=1.432;
		}
		else if(-0.25<=t-1.5&&t-1.5<0.25)
		{
			b=1.080;
		}
		else if(-0.25<=t-2&&t-2<0.25)
		{
			b=0.882;
		}	
		else if(-0.25<=t-2.5&&t-2.5<0.25)
		{
			 b=0.754;
		}
		else if(-0.25<=t-3&&t-3<0.25)
		{
			 b=0.654;
		}
		else if(-0.25<=t-3.5&&t-3.5<0.25)
		{
			 b=0.568;
		}
		else if(-0.25<=t-4&&t-4<0.25)
		{
			 b=0.5;
		}
		else if(-0.25<=t-4.5&&t-4.5<0.25)
		{
			 b=0.446;
		}
		else if(-0.25<=t-5&&t-5&&t-5<0.25)
		{
			b=0.398;
		}
		else if(-0.25<=t-5.5&&t-5.5<0.25)
		{
			 b=0.36;
		}
		else if(-0.25<=t-6&&t-6<0.25)
		{
			 b=0.328;
		}
		else if(-0.25<=t-6.5&&t-6.5<0.25)
		{
			 b=0.3;
		}
		else if(-0.25<=t-7&&t-7<0.25)
		{
			 b=0.28;
		}
		else if(-0.25<=t-7.5&&t-7.5<0.25)
		{
			 b=0.266;
		}
		else if(-0.25<=t-8&&t-8<0.25)
		{
			 b=0.256;
		}
		else if(-0.25<=t-8.5&&t-8.5<0.5)
		{
			 b=0.250;
		}
		else if(-0.5<=t-9.5&&t-9.5<0.25)
		{
			 b=0.254;
		}
		else if(-0.25<=t-10&&t-10<0.25)
		{
			 b=0.26;
		}
		else if(-0.25<=t-10.5&&t-10.5<0.25)
		{
			 b=0.27;
		}
		else if(-0.25<=t-11&&t-11<0.25)
		{
			 b=0.282;
		}
		else if(-0.25<=t-11.5&&t-11.5<0.25)
		{
			b=0.296;
		}
		else if(-0.25<=t-12&&t-12<0.5)
		{
			 b=0.312;
		}
		else if(-0.5<=t-13&&t-13<0.5)
		{
			 b=0.348;
		}
		else if(-0.5<=t-14&&t-14<0.5)
		{
			 b=0.388;//cout<<11111<<endl;
		}
		else if(-0.5<=t-15&&t-15<0.5)
		{
			 b=0.432;//cout<<1<<endl;
		}
		else if(-0.5<=t-16&&t-16<0.5)
		{
			 b=0.48;//cout<<1<<endl;
		}
		else if(-0.5<=t-17&&t-17<0.5)
		{
			 b=0.53;
		}
		else if(-0.5<=t-18&&t-18<0.5)
		{
			 b=0.584;
		}
		else if(-0.5<=t-19&&t-19<0.5)
		{
			 b=0.64;
		}
		else if(-0.5<=t-20&&t-20<0.5)
		{
			 b=0.7;
		}
		else if(-0.5<=t-21&&t-21<0.5)
		{
			 b=0.76;
		}
		else if(-0.5<=t-22&&t-22<0.5)
		{
			 b=0.824;
		}		
		else if(-0.5<=t-23&&t-23<0.5)
		{
			b=0.89;
		}
		else if(-0.5<=t-24&&t-24<0.5)
		{
			 b=0.962;
		}
		else if(-0.5<=t-25&&t-25<0.5)
		{
			 b=1.042;
		}

		p=h*2.0*100.0/b/youxiaozhi;
		p=0.714*p;
		str.Format("%f",p);
		m_flick_shortflick.SetWindowText(str);
		m_flick_longflick.SetWindowText("请等待……");
		break;
	case Ab:
				S=0;
		for(i=0;i<256*caiyanglv;i++)                           //给结构体赋值
		{
			double w=0.5-0.5*cos(2*PI*i/FFT_N);
			s[i].real=packet2receive.data_to_receive.currentB[i]; //实部为正弦波FFT_N点采样，赋值为1
			s[i].imag=0;                                //虚部为0
			temp[i].real=s[i].real;
			temp[i].imag=0;
			S=S+s[i].real*s[i].real; 
			s[i].real=s[i].real*w; 
		}
		FFT(s);    //进行快速福利叶变换
		for(i=0;i<FFT_N;i++)
		{                           //求变换后结果的模值
			Am[i]=sqrt(s[i].real*s[i].real+s[i].imag*s[i].imag);
			//	cout<<Am[i]<<endl;
		}
		high=U[0],low=U[0];

		for(i=0;i<256;i++)
		{
			if(U[i]>high)
			{
				high=U[i];
				//		   cout<<i<<"       "<<h<<endl;
			}
			else if(U[i]<low)
			{
				low=U[i];
			}
		}
		d=high-low;
		d=d/youxiaozhi*100;
		str.Format("%f",d);
		m_flick_fluctuate.SetWindowText(str+"%");

		FFT1(z);
		for(i=0;i<256;i++)
		{                           //求变换后结果的模值
			A[i]=sqrt(z[i].real*z[i].real+z[i].imag*z[i].imag);
		}
		h=A[1];
		for(i=1;i<154;i++)
		{
			if(h<=A[i])
			{
				h=A[i];
				t=i;
			}
		}
		h=h*2.0/256.0;
		t=t*0.195;
		//cout<<h<<"   "<<t<<endl;
		if(-0.25<=t-0.5&&t-0.5<0.25)
		{
			b=2.34;
		}
		else if(-0.25<=t-1&&t-1<0.25)
		{
			 b=1.432;
		}
		else if(-0.25<=t-1.5&&t-1.5<0.25)
		{
			b=1.080;
		}
		else if(-0.25<=t-2&&t-2<0.25)
		{
			b=0.882;
		}	
		else if(-0.25<=t-2.5&&t-2.5<0.25)
		{
			 b=0.754;
		}
		else if(-0.25<=t-3&&t-3<0.25)
		{
			 b=0.654;
		}
		else if(-0.25<=t-3.5&&t-3.5<0.25)
		{
			 b=0.568;
		}
		else if(-0.25<=t-4&&t-4<0.25)
		{
			 b=0.5;
		}
		else if(-0.25<=t-4.5&&t-4.5<0.25)
		{
			 b=0.446;
		}
		else if(-0.25<=t-5&&t-5&&t-5<0.25)
		{
			b=0.398;
		}
		else if(-0.25<=t-5.5&&t-5.5<0.25)
		{
			 b=0.36;
		}
		else if(-0.25<=t-6&&t-6<0.25)
		{
			 b=0.328;
		}
		else if(-0.25<=t-6.5&&t-6.5<0.25)
		{
			 b=0.3;
		}
		else if(-0.25<=t-7&&t-7<0.25)
		{
			 b=0.28;
		}
		else if(-0.25<=t-7.5&&t-7.5<0.25)
		{
			 b=0.266;
		}
		else if(-0.25<=t-8&&t-8<0.25)
		{
			 b=0.256;
		}
		else if(-0.25<=t-8.5&&t-8.5<0.5)
		{
			 b=0.250;
		}
		else if(-0.5<=t-9.5&&t-9.5<0.25)
		{
			 b=0.254;
		}
		else if(-0.25<=t-10&&t-10<0.25)
		{
			 b=0.26;
		}
		else if(-0.25<=t-10.5&&t-10.5<0.25)
		{
			 b=0.27;
		}
		else if(-0.25<=t-11&&t-11<0.25)
		{
			 b=0.282;
		}
		else if(-0.25<=t-11.5&&t-11.5<0.25)
		{
			b=0.296;
		}
		else if(-0.25<=t-12&&t-12<0.5)
		{
			 b=0.312;
		}
		else if(-0.5<=t-13&&t-13<0.5)
		{
			 b=0.348;
		}
		else if(-0.5<=t-14&&t-14<0.5)
		{
			 b=0.388;//cout<<11111<<endl;
		}
		else if(-0.5<=t-15&&t-15<0.5)
		{
			 b=0.432;//cout<<1<<endl;
		}
		else if(-0.5<=t-16&&t-16<0.5)
		{
			 b=0.48;//cout<<1<<endl;
		}
		else if(-0.5<=t-17&&t-17<0.5)
		{
			 b=0.53;
		}
		else if(-0.5<=t-18&&t-18<0.5)
		{
			 b=0.584;
		}
		else if(-0.5<=t-19&&t-19<0.5)
		{
			 b=0.64;
		}
		else if(-0.5<=t-20&&t-20<0.5)
		{
			 b=0.7;
		}
		else if(-0.5<=t-21&&t-21<0.5)
		{
			 b=0.76;
		}
		else if(-0.5<=t-22&&t-22<0.5)
		{
			 b=0.824;
		}		
		else if(-0.5<=t-23&&t-23<0.5)
		{
			b=0.89;
		}
		else if(-0.5<=t-24&&t-24<0.5)
		{
			 b=0.962;
		}
		else if(-0.5<=t-25&&t-25<0.5)
		{
			 b=1.042;
		}

		p=h*2.0*100.0/b/youxiaozhi;
		p=0.714*p;
		str.Format("%f",p);
		m_flick_shortflick.SetWindowText(str);
		m_flick_longflick.SetWindowText("请等待……");
		break;
	case Ac:
		S=0;
		for(i=0;i<256*caiyanglv;i++)                           //给结构体赋值
		{
			double w=0.5-0.5*cos(2*PI*i/FFT_N);
			s[i].real=packet2receive.data_to_receive.currentC[i]; //实部为正弦波FFT_N点采样，赋值为1
			s[i].imag=0;                                //虚部为0
			temp[i].real=s[i].real;
			temp[i].imag=0;
			S=S+s[i].real*s[i].real; 
			s[i].real=s[i].real*w; 
		}
		FFT(s);    //进行快速福利叶变换
		for(i=0;i<FFT_N;i++)
		{                           //求变换后结果的模值
			Am[i]=sqrt(s[i].real*s[i].real+s[i].imag*s[i].imag);
			//	cout<<Am[i]<<endl;
		}
		high=U[0],low=U[0];

		for(i=0;i<256;i++)
		{
			if(U[i]>high)
			{
				high=U[i];
				//		   cout<<i<<"       "<<h<<endl;
			}
			else if(U[i]<low)
			{
				low=U[i];
			}
		}
		d=high-low;
		d=d/youxiaozhi*100;
		str.Format("%f",d);
		m_flick_fluctuate.SetWindowText(str+"%");

		FFT1(z);
		for(i=0;i<256;i++)
		{                           //求变换后结果的模值
			A[i]=sqrt(z[i].real*z[i].real+z[i].imag*z[i].imag);
		}
		h=A[1];
		for(i=1;i<154;i++)
		{
			if(h<=A[i])
			{
				h=A[i];
				t=i;
			}
		}
		h=h*2.0/256.0;
		t=t*0.195;
		//cout<<h<<"   "<<t<<endl;
		if(-0.25<=t-0.5&&t-0.5<0.25)
		{
			b=2.34;
		}
		else if(-0.25<=t-1&&t-1<0.25)
		{
			 b=1.432;
		}
		else if(-0.25<=t-1.5&&t-1.5<0.25)
		{
			b=1.080;
		}
		else if(-0.25<=t-2&&t-2<0.25)
		{
			b=0.882;
		}	
		else if(-0.25<=t-2.5&&t-2.5<0.25)
		{
			 b=0.754;
		}
		else if(-0.25<=t-3&&t-3<0.25)
		{
			 b=0.654;
		}
		else if(-0.25<=t-3.5&&t-3.5<0.25)
		{
			 b=0.568;
		}
		else if(-0.25<=t-4&&t-4<0.25)
		{
			 b=0.5;
		}
		else if(-0.25<=t-4.5&&t-4.5<0.25)
		{
			 b=0.446;
		}
		else if(-0.25<=t-5&&t-5&&t-5<0.25)
		{
			b=0.398;
		}
		else if(-0.25<=t-5.5&&t-5.5<0.25)
		{
			 b=0.36;
		}
		else if(-0.25<=t-6&&t-6<0.25)
		{
			 b=0.328;
		}
		else if(-0.25<=t-6.5&&t-6.5<0.25)
		{
			 b=0.3;
		}
		else if(-0.25<=t-7&&t-7<0.25)
		{
			 b=0.28;
		}
		else if(-0.25<=t-7.5&&t-7.5<0.25)
		{
			 b=0.266;
		}
		else if(-0.25<=t-8&&t-8<0.25)
		{
			 b=0.256;
		}
		else if(-0.25<=t-8.5&&t-8.5<0.5)
		{
			 b=0.250;
		}
		else if(-0.5<=t-9.5&&t-9.5<0.25)
		{
			 b=0.254;
		}
		else if(-0.25<=t-10&&t-10<0.25)
		{
			 b=0.26;
		}
		else if(-0.25<=t-10.5&&t-10.5<0.25)
		{
			 b=0.27;
		}
		else if(-0.25<=t-11&&t-11<0.25)
		{
			 b=0.282;
		}
		else if(-0.25<=t-11.5&&t-11.5<0.25)
		{
			b=0.296;
		}
		else if(-0.25<=t-12&&t-12<0.5)
		{
			 b=0.312;
		}
		else if(-0.5<=t-13&&t-13<0.5)
		{
			 b=0.348;
		}
		else if(-0.5<=t-14&&t-14<0.5)
		{
			 b=0.388;//cout<<11111<<endl;
		}
		else if(-0.5<=t-15&&t-15<0.5)
		{
			 b=0.432;//cout<<1<<endl;
		}
		else if(-0.5<=t-16&&t-16<0.5)
		{
			 b=0.48;//cout<<1<<endl;
		}
		else if(-0.5<=t-17&&t-17<0.5)
		{
			 b=0.53;
		}
		else if(-0.5<=t-18&&t-18<0.5)
		{
			 b=0.584;
		}
		else if(-0.5<=t-19&&t-19<0.5)
		{
			 b=0.64;
		}
		else if(-0.5<=t-20&&t-20<0.5)
		{
			 b=0.7;
		}
		else if(-0.5<=t-21&&t-21<0.5)
		{
			 b=0.76;
		}
		else if(-0.5<=t-22&&t-22<0.5)
		{
			 b=0.824;
		}		
		else if(-0.5<=t-23&&t-23<0.5)
		{
			b=0.89;
		}
		else if(-0.5<=t-24&&t-24<0.5)
		{
			 b=0.962;
		}
		else if(-0.5<=t-25&&t-25<0.5)
		{
			 b=1.042;
		}

		p=h*2.0*100.0/b/youxiaozhi;
		p=0.714*p;
		str.Format("%f",p);
		m_flick_shortflick.SetWindowText(str);
		m_flick_longflick.SetWindowText("请等待……");
		break;
	case Va:
		S=0;
		for(i=0;i<256*caiyanglv;i++)                           //给结构体赋值
		{
			double w=0.5-0.5*cos(2*PI*i/FFT_N);
			s[i].real=packet2receive.data_to_receive.VoltageA[i]; //实部为正弦波FFT_N点采样，赋值为1
			s[i].imag=0;                                //虚部为0
			temp[i].real=s[i].real;
			temp[i].imag=0;
			S=S+s[i].real*s[i].real; 
			s[i].real=s[i].real*w; 
		}
		FFT(s);    //进行快速福利叶变换
		for(i=0;i<FFT_N;i++)
		{                           //求变换后结果的模值
			Am[i]=sqrt(s[i].real*s[i].real+s[i].imag*s[i].imag);
			//	cout<<Am[i]<<endl;
		}
		high=U[0],low=U[0];

		for(i=0;i<256;i++)
		{
			if(U[i]>high)
			{
				high=U[i];
				//		   cout<<i<<"       "<<h<<endl;
			}
			else if(U[i]<low)
			{
				low=U[i];
			}
		}
		d=high-low;
		d=d/youxiaozhi*100;
		str.Format("%f",d);
		m_flick_fluctuate.SetWindowText(str+"%");

		FFT1(z);
		for(i=0;i<256;i++)
		{                           //求变换后结果的模值
			A[i]=sqrt(z[i].real*z[i].real+z[i].imag*z[i].imag);
		}
		h=A[1];
		for(i=1;i<154;i++)
		{
			if(h<=A[i])
			{
				h=A[i];
				t=i;
			}
		}
		h=h*2.0/256.0;
		t=t*0.195;
		//cout<<h<<"   "<<t<<endl;
		if(-0.25<=t-0.5&&t-0.5<0.25)
		{
			b=2.34;
		}
		else if(-0.25<=t-1&&t-1<0.25)
		{
			 b=1.432;
		}
		else if(-0.25<=t-1.5&&t-1.5<0.25)
		{
			b=1.080;
		}
		else if(-0.25<=t-2&&t-2<0.25)
		{
			b=0.882;
		}	
		else if(-0.25<=t-2.5&&t-2.5<0.25)
		{
			 b=0.754;
		}
		else if(-0.25<=t-3&&t-3<0.25)
		{
			 b=0.654;
		}
		else if(-0.25<=t-3.5&&t-3.5<0.25)
		{
			 b=0.568;
		}
		else if(-0.25<=t-4&&t-4<0.25)
		{
			 b=0.5;
		}
		else if(-0.25<=t-4.5&&t-4.5<0.25)
		{
			 b=0.446;
		}
		else if(-0.25<=t-5&&t-5&&t-5<0.25)
		{
			b=0.398;
		}
		else if(-0.25<=t-5.5&&t-5.5<0.25)
		{
			 b=0.36;
		}
		else if(-0.25<=t-6&&t-6<0.25)
		{
			 b=0.328;
		}
		else if(-0.25<=t-6.5&&t-6.5<0.25)
		{
			 b=0.3;
		}
		else if(-0.25<=t-7&&t-7<0.25)
		{
			 b=0.28;
		}
		else if(-0.25<=t-7.5&&t-7.5<0.25)
		{
			 b=0.266;
		}
		else if(-0.25<=t-8&&t-8<0.25)
		{
			 b=0.256;
		}
		else if(-0.25<=t-8.5&&t-8.5<0.5)
		{
			 b=0.250;
		}
		else if(-0.5<=t-9.5&&t-9.5<0.25)
		{
			 b=0.254;
		}
		else if(-0.25<=t-10&&t-10<0.25)
		{
			 b=0.26;
		}
		else if(-0.25<=t-10.5&&t-10.5<0.25)
		{
			 b=0.27;
		}
		else if(-0.25<=t-11&&t-11<0.25)
		{
			 b=0.282;
		}
		else if(-0.25<=t-11.5&&t-11.5<0.25)
		{
			b=0.296;
		}
		else if(-0.25<=t-12&&t-12<0.5)
		{
			 b=0.312;
		}
		else if(-0.5<=t-13&&t-13<0.5)
		{
			 b=0.348;
		}
		else if(-0.5<=t-14&&t-14<0.5)
		{
			 b=0.388;//cout<<11111<<endl;
		}
		else if(-0.5<=t-15&&t-15<0.5)
		{
			 b=0.432;//cout<<1<<endl;
		}
		else if(-0.5<=t-16&&t-16<0.5)
		{
			 b=0.48;//cout<<1<<endl;
		}
		else if(-0.5<=t-17&&t-17<0.5)
		{
			 b=0.53;
		}
		else if(-0.5<=t-18&&t-18<0.5)
		{
			 b=0.584;
		}
		else if(-0.5<=t-19&&t-19<0.5)
		{
			 b=0.64;
		}
		else if(-0.5<=t-20&&t-20<0.5)
		{
			 b=0.7;
		}
		else if(-0.5<=t-21&&t-21<0.5)
		{
			 b=0.76;
		}
		else if(-0.5<=t-22&&t-22<0.5)
		{
			 b=0.824;
		}		
		else if(-0.5<=t-23&&t-23<0.5)
		{
			b=0.89;
		}
		else if(-0.5<=t-24&&t-24<0.5)
		{
			 b=0.962;
		}
		else if(-0.5<=t-25&&t-25<0.5)
		{
			 b=1.042;
		}

		p=h*2.0*100.0/b/youxiaozhi;
		p=0.714*p;
		str.Format("%f",p);
		m_flick_shortflick.SetWindowText(str);
		m_flick_longflick.SetWindowText("请等待……");
		break;
	case Vb:
		S=0;
		for(i=0;i<256*caiyanglv;i++)                           //给结构体赋值
		{
			double w=0.5-0.5*cos(2*PI*i/FFT_N);
			s[i].real=packet2receive.data_to_receive.VoltageB[i]; //实部为正弦波FFT_N点采样，赋值为1
			s[i].imag=0;                                //虚部为0
			temp[i].real=s[i].real;
			temp[i].imag=0;
			S=S+s[i].real*s[i].real; 
			s[i].real=s[i].real*w; 
		}
		FFT(s);    //进行快速福利叶变换
		for(i=0;i<FFT_N;i++)
		{                           //求变换后结果的模值
			Am[i]=sqrt(s[i].real*s[i].real+s[i].imag*s[i].imag);
			//	cout<<Am[i]<<endl;
		}
		high=U[0],low=U[0];

		for(i=0;i<256;i++)
		{
			if(U[i]>high)
			{
				high=U[i];
				//		   cout<<i<<"       "<<h<<endl;
			}
			else if(U[i]<low)
			{
				low=U[i];
			}
		}
		d=high-low;
		d=d/youxiaozhi*100;
		str.Format("%f",d);
		m_flick_fluctuate.SetWindowText(str+"%");

		FFT1(z);
		for(i=0;i<256;i++)
		{                           //求变换后结果的模值
			A[i]=sqrt(z[i].real*z[i].real+z[i].imag*z[i].imag);
		}
		h=A[1];
		for(i=1;i<154;i++)
		{
			if(h<=A[i])
			{
				h=A[i];
				t=i;
			}
		}
		h=h*2.0/256.0;
		t=t*0.195;
		//cout<<h<<"   "<<t<<endl;
		if(-0.25<=t-0.5&&t-0.5<0.25)
		{
			b=2.34;
		}
		else if(-0.25<=t-1&&t-1<0.25)
		{
			 b=1.432;
		}
		else if(-0.25<=t-1.5&&t-1.5<0.25)
		{
			b=1.080;
		}
		else if(-0.25<=t-2&&t-2<0.25)
		{
			b=0.882;
		}	
		else if(-0.25<=t-2.5&&t-2.5<0.25)
		{
			 b=0.754;
		}
		else if(-0.25<=t-3&&t-3<0.25)
		{
			 b=0.654;
		}
		else if(-0.25<=t-3.5&&t-3.5<0.25)
		{
			 b=0.568;
		}
		else if(-0.25<=t-4&&t-4<0.25)
		{
			 b=0.5;
		}
		else if(-0.25<=t-4.5&&t-4.5<0.25)
		{
			 b=0.446;
		}
		else if(-0.25<=t-5&&t-5&&t-5<0.25)
		{
			b=0.398;
		}
		else if(-0.25<=t-5.5&&t-5.5<0.25)
		{
			 b=0.36;
		}
		else if(-0.25<=t-6&&t-6<0.25)
		{
			 b=0.328;
		}
		else if(-0.25<=t-6.5&&t-6.5<0.25)
		{
			 b=0.3;
		}
		else if(-0.25<=t-7&&t-7<0.25)
		{
			 b=0.28;
		}
		else if(-0.25<=t-7.5&&t-7.5<0.25)
		{
			 b=0.266;
		}
		else if(-0.25<=t-8&&t-8<0.25)
		{
			 b=0.256;
		}
		else if(-0.25<=t-8.5&&t-8.5<0.5)
		{
			 b=0.250;
		}
		else if(-0.5<=t-9.5&&t-9.5<0.25)
		{
			 b=0.254;
		}
		else if(-0.25<=t-10&&t-10<0.25)
		{
			 b=0.26;
		}
		else if(-0.25<=t-10.5&&t-10.5<0.25)
		{
			 b=0.27;
		}
		else if(-0.25<=t-11&&t-11<0.25)
		{
			 b=0.282;
		}
		else if(-0.25<=t-11.5&&t-11.5<0.25)
		{
			b=0.296;
		}
		else if(-0.25<=t-12&&t-12<0.5)
		{
			 b=0.312;
		}
		else if(-0.5<=t-13&&t-13<0.5)
		{
			 b=0.348;
		}
		else if(-0.5<=t-14&&t-14<0.5)
		{
			 b=0.388;//cout<<11111<<endl;
		}
		else if(-0.5<=t-15&&t-15<0.5)
		{
			 b=0.432;//cout<<1<<endl;
		}
		else if(-0.5<=t-16&&t-16<0.5)
		{
			 b=0.48;//cout<<1<<endl;
		}
		else if(-0.5<=t-17&&t-17<0.5)
		{
			 b=0.53;
		}
		else if(-0.5<=t-18&&t-18<0.5)
		{
			 b=0.584;
		}
		else if(-0.5<=t-19&&t-19<0.5)
		{
			 b=0.64;
		}
		else if(-0.5<=t-20&&t-20<0.5)
		{
			 b=0.7;
		}
		else if(-0.5<=t-21&&t-21<0.5)
		{
			 b=0.76;
		}
		else if(-0.5<=t-22&&t-22<0.5)
		{
			 b=0.824;
		}		
		else if(-0.5<=t-23&&t-23<0.5)
		{
			b=0.89;
		}
		else if(-0.5<=t-24&&t-24<0.5)
		{
			 b=0.962;
		}
		else if(-0.5<=t-25&&t-25<0.5)
		{
			 b=1.042;
		}

		p=h*2.0*100.0/b/youxiaozhi;
		p=0.714*p;
		str.Format("%f",p);
		m_flick_shortflick.SetWindowText(str);
		m_flick_longflick.SetWindowText("请等待……");
		break;
	case Vc:
		S=0;
		for(i=0;i<256*caiyanglv;i++)                           //给结构体赋值
		{
			double w=0.5-0.5*cos(2*PI*i/FFT_N);
			s[i].real=packet2receive.data_to_receive.VoltageC[i]; //实部为正弦波FFT_N点采样，赋值为1
			s[i].imag=0;                                //虚部为0
			temp[i].real=s[i].real;
			temp[i].imag=0;
			S=S+s[i].real*s[i].real; 
			s[i].real=s[i].real*w; 
		}
		FFT(s);    //进行快速福利叶变换
		for(i=0;i<FFT_N;i++)
		{                           //求变换后结果的模值
			Am[i]=sqrt(s[i].real*s[i].real+s[i].imag*s[i].imag);
			//	cout<<Am[i]<<endl;
		}
		high=U[0],low=U[0];

		for(i=0;i<256;i++)
		{
			if(U[i]>high)
			{
				high=U[i];
				//		   cout<<i<<"       "<<h<<endl;
			}
			else if(U[i]<low)
			{
				low=U[i];
			}
		}
		d=high-low;
		d=d/youxiaozhi*100;
		str.Format("%f",d);
		m_flick_fluctuate.SetWindowText(str+"%");

		FFT1(z);
		for(i=0;i<256;i++)
		{                           //求变换后结果的模值
			A[i]=sqrt(z[i].real*z[i].real+z[i].imag*z[i].imag);
		}
		h=A[1];
		for(i=1;i<154;i++)
		{
			if(h<=A[i])
			{
				h=A[i];
				t=i;
			}
		}
		h=h*2.0/256.0;
		t=t*0.195;
		//cout<<h<<"   "<<t<<endl;
		if(-0.25<=t-0.5&&t-0.5<0.25)
		{
			b=2.34;
		}
		else if(-0.25<=t-1&&t-1<0.25)
		{
			 b=1.432;
		}
		else if(-0.25<=t-1.5&&t-1.5<0.25)
		{
			b=1.080;
		}
		else if(-0.25<=t-2&&t-2<0.25)
		{
			b=0.882;
		}	
		else if(-0.25<=t-2.5&&t-2.5<0.25)
		{
			 b=0.754;
		}
		else if(-0.25<=t-3&&t-3<0.25)
		{
			 b=0.654;
		}
		else if(-0.25<=t-3.5&&t-3.5<0.25)
		{
			 b=0.568;
		}
		else if(-0.25<=t-4&&t-4<0.25)
		{
			 b=0.5;
		}
		else if(-0.25<=t-4.5&&t-4.5<0.25)
		{
			 b=0.446;
		}
		else if(-0.25<=t-5&&t-5&&t-5<0.25)
		{
			b=0.398;
		}
		else if(-0.25<=t-5.5&&t-5.5<0.25)
		{
			 b=0.36;
		}
		else if(-0.25<=t-6&&t-6<0.25)
		{
			 b=0.328;
		}
		else if(-0.25<=t-6.5&&t-6.5<0.25)
		{
			 b=0.3;
		}
		else if(-0.25<=t-7&&t-7<0.25)
		{
			 b=0.28;
		}
		else if(-0.25<=t-7.5&&t-7.5<0.25)
		{
			 b=0.266;
		}
		else if(-0.25<=t-8&&t-8<0.25)
		{
			 b=0.256;
		}
		else if(-0.25<=t-8.5&&t-8.5<0.5)
		{
			 b=0.250;
		}
		else if(-0.5<=t-9.5&&t-9.5<0.25)
		{
			 b=0.254;
		}
		else if(-0.25<=t-10&&t-10<0.25)
		{
			 b=0.26;
		}
		else if(-0.25<=t-10.5&&t-10.5<0.25)
		{
			 b=0.27;
		}
		else if(-0.25<=t-11&&t-11<0.25)
		{
			 b=0.282;
		}
		else if(-0.25<=t-11.5&&t-11.5<0.25)
		{
			b=0.296;
		}
		else if(-0.25<=t-12&&t-12<0.5)
		{
			 b=0.312;
		}
		else if(-0.5<=t-13&&t-13<0.5)
		{
			 b=0.348;
		}
		else if(-0.5<=t-14&&t-14<0.5)
		{
			 b=0.388;//cout<<11111<<endl;
		}
		else if(-0.5<=t-15&&t-15<0.5)
		{
			 b=0.432;//cout<<1<<endl;
		}
		else if(-0.5<=t-16&&t-16<0.5)
		{
			 b=0.48;//cout<<1<<endl;
		}
		else if(-0.5<=t-17&&t-17<0.5)
		{
			 b=0.53;
		}
		else if(-0.5<=t-18&&t-18<0.5)
		{
			 b=0.584;
		}
		else if(-0.5<=t-19&&t-19<0.5)
		{
			 b=0.64;
		}
		else if(-0.5<=t-20&&t-20<0.5)
		{
			 b=0.7;
		}
		else if(-0.5<=t-21&&t-21<0.5)
		{
			 b=0.76;
		}
		else if(-0.5<=t-22&&t-22<0.5)
		{
			 b=0.824;
		}		
		else if(-0.5<=t-23&&t-23<0.5)
		{
			b=0.89;
		}
		else if(-0.5<=t-24&&t-24<0.5)
		{
			 b=0.962;
		}
		else if(-0.5<=t-25&&t-25<0.5)
		{
			 b=1.042;
		}

		p=h*2.0*100.0/b/youxiaozhi;
		p=0.714*p;
		str.Format("%f",p);
		m_flick_shortflick.SetWindowText(str);
		m_flick_longflick.SetWindowText("请等待……");
		break;
	}
	
}

void CReceive1Dlg::OnButton_Unbalance() 
{
	// TODO: Add your control notification handler code here
	Calculate();
	CString str;
	struct compx y,z,U1,U2,t[10000];
	double F[3],A[3],U[3],r;
	int j;
	switch (unbalance_cursel)
	{
	case NN: MessageBox("请选择分析项","请选择",MB_OK);
		break;
	case Aa://算电流
		S=0;
		for(i=0;i<256*caiyanglv;i++)                           //给结构体赋值
		{
			double w=0.5-0.5*cos(2*PI*i/FFT_N);
			s[i].real=packet2receive.data_to_receive.currentA[i]; //实部为正弦波FFT_N点采样，赋值为1
			s[i].imag=0;                                //虚部为0
			temp[i].real=s[i].real;
			temp[i].imag=0;
			S=S+s[i].real*s[i].real; 
			s[i].real=s[i].real*w; 
		}
		FFT(s);    //进行快速福利叶变换
		for(i=0;i<FFT_N;i++)
		{                           //求变换后结果的模值
			Am[i]=sqrt(s[i].real*s[i].real+s[i].imag*s[i].imag);
			//	cout<<Am[i]<<endl;
		}

		S=0;
		for(i=0;i<256*caiyanglv;i++)                           //给结构体赋值
		{
			double w=0.5-0.5*cos(2*PI*i/FFT_N);
			s1[i].real=packet2receive.data_to_receive.currentB[i]; //实部为正弦波FFT_N点采样，赋值为1
			s1[i].imag=0;                                //虚部为0
			temp[i].real=s1[i].real;
			temp[i].imag=0;
			S=S+s1[i].real*s1[i].real; 
			s1[i].real=s1[i].real*w; 
		}
		FFT(s1);    //进行快速福利叶变换
		for(i=0;i<FFT_N;i++)
		{                           //求变换后结果的模值
			Am1[i]=sqrt(s1[i].real*s1[i].real+s1[i].imag*s1[i].imag);
		}

		S=0;
		for(i=0;i<256*caiyanglv;i++)                           //给结构体赋值
		{
			double w=0.5-0.5*cos(2*PI*i/FFT_N);
			s2[i].real=packet2receive.data_to_receive.currentC[i]; //实部为正弦波FFT_N点采样，赋值为1
			s2[i].imag=0;                                //虚部为0
			temp[i].real=s2[i].real;
			temp[i].imag=0;
			S=S+s2[i].real*s2[i].real; 
			s2[i].real=s2[i].real*w; 
		}
		FFT(s2);    //进行快速福利叶变换
		for(i=0;i<FFT_N;i++)
		{                           //求变换后结果的模值
			Am2[i]=sqrt(s2[i].real*s2[i].real+s2[i].imag*s2[i].imag);
		}
///////////////////////////////

		for(i=(int)(50*(FFT_N*0.02/caiyanglv))-2;i<=(int)(50*(FFT_N*0.02/caiyanglv))+3;i++)
		{
			if(Am[i]<=Am[i+1]) j=i+1;
			else if(Am[j]<=Am[i])j=i;
			else j=j;
		}
		c=Am[j+1]/Am[j];
		e=sqrt((2*c-1)/(c+1)*(2*c-1)/(c+1));
		U[0]=2*PI*e*(1-e*e)/sin(PI*e)*sqrt(s[j].real*s[j].real+s[j].imag*s[j].imag);
		U[0]=U[0]*2/FFT_N;
		F[0]=(j+e)/(FFT_N*0.02/caiyanglv);
// 		cout<< "a相频率： "<<F[0]<<"    ";
		A[0]=atan2(s[j].imag,s[j].real)+e*PI*(FFT_N-1)/FFT_N;
		A[0]=A[0]*180/PI;
// 		cout<<"a相角度： " <<A[0]<<"    ";
// 			cout<<"a相幅值： "<<U[0]<<endl;

		for(i=int(50*(FFT_N*0.02/caiyanglv))-2;i<=int(50*(FFT_N*0.02/caiyanglv))+3;i++)
		{
			if(Am1[i]<=Am1[i+1]) j=i+1;
			else if(Am1[j]<=Am1[i])j=i;
			else j=j;
		}
		c=Am1[j+1]/Am1[j];
		e=sqrt((2*c-1)/(c+1)*(2*c-1)/(c+1));
		U[1]=2*PI*e*(1-e*e)/sin(PI*e)*Am1[j];
		U[1]=U[1]*2/FFT_N;
		F[1]=(j+e)/(FFT_N*0.02/caiyanglv);
// 		cout<< "b相频率： "<<F[1]<<"    ";
		A[1]=atan2(s1[j].imag,s1[j].real)+e*PI*(FFT_N-1)/FFT_N;
		A[1]=A[1]*180/PI;
// 		cout<<"b相角度： " <<A[1]<<"    ";
// 		cout<<"b相幅值： "<<U[1]<<endl;
		
		for(i=int(50*(FFT_N*0.02/caiyanglv))-2;i<=int(50*(FFT_N*0.02/caiyanglv))+3;i++)
		{
			if(Am2[i]<=Am2[i+1]) j=i+1;
			else if(Am2[j]<=Am2[i])j=i;
			else j=j;
		}
		c=Am2[j+1]/Am2[j];
		e=sqrt((2*c-1)/(c+1)*(2*c-1)/(c+1));
		U[2]=2*PI*e*(1-e*e)/sin(PI*e)*Am2[j];
		U[2]=U[2]*2/FFT_N;
		F[2]=(j+e)/(FFT_N*0.02/caiyanglv);
// 		cout<< "c相频率： "<<F[2]<<"    ";
		A[2]=atan2(s2[j].imag,s2[j].real)+e*PI*(FFT_N-1)/FFT_N;
		A[2]=A[2]*180/PI;
// 		cout<<"c相角度： " <<A[2]<<"    ";
// 		cout<<"c相幅值： "<<U[2]<<endl;
		y.real=-0.5;
		y.imag=0.866025;
		for(i=0;i<3;i++)
		{
			t[i].real=U[i]*cos(A[i]*PI/180);//cout<<s[i].real<<endl;
			t[i].imag=U[i]*sin(A[i]*PI/180);//cout<<s[i].imag<<endl;
		}
		z.real=1.0/3;
		z.imag=0;
		U1=EE(z,(AAD(AAD(t[0],EE(t[1],y)),EE(EE(y,y),t[2]))));
		U[1]=sqrt(U1.real*U1.real+U1.imag*U1.imag);
		U2=EE(z,(AAD(AAD(t[0],EE(t[2],y)),EE(EE(y,y),t[1]))));
		U[2]=sqrt(U2.real*U2.real+U2.imag*U2.imag);
		r=U[2]/U[1]*100;
// 			cout<<"三相不平衡度为："<<r<<"%"<<endl;
		str.Format("%f",r);
		m_unbalance.SetWindowText(str+"%");
		break;
	case Ab://算电压
		S=0;
		for(i=0;i<256*caiyanglv;i++)                           //给结构体赋值
		{
			double w=0.5-0.5*cos(2*PI*i/FFT_N);
			s[i].real=packet2receive.data_to_receive.VoltageA[i]; //实部为正弦波FFT_N点采样，赋值为1
			s[i].imag=0;                                //虚部为0
			temp[i].real=s[i].real;
			temp[i].imag=0;
			S=S+s[i].real*s[i].real; 
			s[i].real=s[i].real*w; 
		}
		FFT(s);    //进行快速福利叶变换
		for(i=0;i<FFT_N;i++)
		{                           //求变换后结果的模值
			Am[i]=sqrt(s[i].real*s[i].real+s[i].imag*s[i].imag);
			//	cout<<Am[i]<<endl;
		}

		S=0;
		for(i=0;i<256*caiyanglv;i++)                           //给结构体赋值
		{
			double w=0.5-0.5*cos(2*PI*i/FFT_N);
			s1[i].real=packet2receive.data_to_receive.VoltageB[i]; //实部为正弦波FFT_N点采样，赋值为1
			s1[i].imag=0;                                //虚部为0
			temp[i].real=s1[i].real;
			temp[i].imag=0;
			S=S+s1[i].real*s1[i].real; 
			s1[i].real=s1[i].real*w; 
		}
		FFT(s1);    //进行快速福利叶变换
		for(i=0;i<FFT_N;i++)
		{                           //求变换后结果的模值
			Am1[i]=sqrt(s1[i].real*s1[i].real+s1[i].imag*s1[i].imag);
		}

		S=0;
		for(i=0;i<256*caiyanglv;i++)                           //给结构体赋值
		{
			double w=0.5-0.5*cos(2*PI*i/FFT_N);
			s2[i].real=packet2receive.data_to_receive.VoltageC[i]; //实部为正弦波FFT_N点采样，赋值为1
			s2[i].imag=0;                                //虚部为0
			temp[i].real=s2[i].real;
			temp[i].imag=0;
			S=S+s2[i].real*s2[i].real; 
			s2[i].real=s2[i].real*w; 
		}
		FFT(s2);    //进行快速福利叶变换
		for(i=0;i<FFT_N;i++)
		{                           //求变换后结果的模值
			Am2[i]=sqrt(s2[i].real*s2[i].real+s2[i].imag*s2[i].imag);
		}
///////////////////////////////

		for(i=(int)(50*(FFT_N*0.02/caiyanglv))-2;i<=(int)(50*(FFT_N*0.02/caiyanglv))+3;i++)
		{
			if(Am[i]<=Am[i+1]) j=i+1;
			else if(Am[j]<=Am[i])j=i;
			else j=j;
		}
		c=Am[j+1]/Am[j];
		e=sqrt((2*c-1)/(c+1)*(2*c-1)/(c+1));
		U[0]=2*PI*e*(1-e*e)/sin(PI*e)*sqrt(s[j].real*s[j].real+s[j].imag*s[j].imag);
		U[0]=U[0]*2/FFT_N;
		F[0]=(j+e)/(FFT_N*0.02/caiyanglv);
// 		cout<< "a相频率： "<<F[0]<<"    ";
		A[0]=atan2(s[j].imag,s[j].real)+e*PI*(FFT_N-1)/FFT_N;
		A[0]=A[0]*180/PI;
// 		cout<<"a相角度： " <<A[0]<<"    ";
// 			cout<<"a相幅值： "<<U[0]<<endl;

		for(i=int(50*(FFT_N*0.02/caiyanglv))-2;i<=int(50*(FFT_N*0.02/caiyanglv))+3;i++)
		{
			if(Am1[i]<=Am1[i+1]) j=i+1;
			else if(Am1[j]<=Am1[i])j=i;
			else j=j;
		}
		c=Am1[j+1]/Am1[j];
		e=sqrt((2*c-1)/(c+1)*(2*c-1)/(c+1));
		U[1]=2*PI*e*(1-e*e)/sin(PI*e)*Am1[j];
		U[1]=U[1]*2/FFT_N;
		F[1]=(j+e)/(FFT_N*0.02/caiyanglv);
// 		cout<< "b相频率： "<<F[1]<<"    ";
		A[1]=atan2(s1[j].imag,s1[j].real)+e*PI*(FFT_N-1)/FFT_N;
		A[1]=A[1]*180/PI;
// 		cout<<"b相角度： " <<A[1]<<"    ";
// 		cout<<"b相幅值： "<<U[1]<<endl;
		
		for(i=int(50*(FFT_N*0.02/caiyanglv))-2;i<=int(50*(FFT_N*0.02/caiyanglv))+3;i++)
		{
			if(Am2[i]<=Am2[i+1]) j=i+1;
			else if(Am2[j]<=Am2[i])j=i;
			else j=j;
		}
		c=Am2[j+1]/Am2[j];
		e=sqrt((2*c-1)/(c+1)*(2*c-1)/(c+1));
		U[2]=2*PI*e*(1-e*e)/sin(PI*e)*Am2[j];
		U[2]=U[2]*2/FFT_N;
		F[2]=(j+e)/(FFT_N*0.02/caiyanglv);
// 		cout<< "c相频率： "<<F[2]<<"    ";
		A[2]=atan2(s2[j].imag,s2[j].real)+e*PI*(FFT_N-1)/FFT_N;
		A[2]=A[2]*180/PI;
// 		cout<<"c相角度： " <<A[2]<<"    ";
// 		cout<<"c相幅值： "<<U[2]<<endl;
		y.real=-0.5;
		y.imag=0.866025;
		for(i=0;i<3;i++)
		{
			t[i].real=U[i]*cos(A[i]*PI/180);//cout<<s[i].real<<endl;
			t[i].imag=U[i]*sin(A[i]*PI/180);//cout<<s[i].imag<<endl;
		}
		z.real=1.0/3;
		z.imag=0;
		U1=EE(z,(AAD(AAD(t[0],EE(t[1],y)),EE(EE(y,y),t[2]))));
		U[1]=sqrt(U1.real*U1.real+U1.imag*U1.imag);
		U2=EE(z,(AAD(AAD(t[0],EE(t[2],y)),EE(EE(y,y),t[1]))));
		U[2]=sqrt(U2.real*U2.real+U2.imag*U2.imag);
		r=U[2]/U[1]*100;
// 			cout<<"三相不平衡度为："<<r<<"%"<<endl;
		str.Format("%f",r);
		m_unbalance.SetWindowText(str+"%");
		break;
	}
	
}


void CReceive1Dlg::OnButton_freqdrift() 
{
	// TODO: Add your control notification handler code here
	Calculate();
	CString str;
	double oU=0;
	double F[3];
	int j;

	switch (freqdrift_cursel)
	{
	case NN: MessageBox("请选择分析项","请选择",MB_OK);
		break;
	case Aa:
		S=0;
		for(i=0;i<256*caiyanglv;i++)                           //给结构体赋值
		{
			double w=0.5-0.5*cos(2*PI*i/FFT_N);
			s[i].real=packet2receive.data_to_receive.currentA[i]; //实部为正弦波FFT_N点采样，赋值为1
			s[i].imag=0;                                //虚部为0
			temp[i].real=s[i].real;
			temp[i].imag=0;
			S=S+s[i].real*s[i].real; 
			s[i].real=s[i].real*w; 
		}
		FFT(s);    //进行快速福利叶变换
		for(i=0;i<FFT_N;i++)
		{                           //求变换后结果的模值
			Am[i]=sqrt(s[i].real*s[i].real+s[i].imag*s[i].imag);
			//	cout<<Am[i]<<endl;
		}

		for(i=(int)(50*(FFT_N*0.02/caiyanglv))-2;i<=(int)(50*(FFT_N*0.02/caiyanglv))+3;i++)
		{
			if(Am[i]<=Am[i+1]) j=i+1;
			else if(Am[j]<=Am[i])j=i;
			else j=j;
		}
		c=Am[j+1]/Am[j];
		e=sqrt((2*c-1)/(c+1)*(2*c-1)/(c+1));	
		F[0]=(j-e)*1/(FFT_N*0.02/caiyanglv);
// 		cout<<F[0]<<endl;
		oU=sqrt((F[0]-50.0)*(F[0]-50.0));
// 		cout<<oU<<endl;
		oU=oU/50.0*100.0;
// 		cout<<"供电频率偏差为："<<oU<<"%"<<endl;
		str.Format("%f",oU);
		m_freqDrift.SetWindowText(str+"%");
		break;
	case Ab:
		S=0;
		for(i=0;i<256*caiyanglv;i++)                           //给结构体赋值
		{
			double w=0.5-0.5*cos(2*PI*i/FFT_N);
			s[i].real=packet2receive.data_to_receive.currentB[i]; //实部为正弦波FFT_N点采样，赋值为1
			s[i].imag=0;                                //虚部为0
			temp[i].real=s[i].real;
			temp[i].imag=0;
			S=S+s[i].real*s[i].real; 
			s[i].real=s[i].real*w; 
		}
		FFT(s);    //进行快速福利叶变换
		for(i=0;i<FFT_N;i++)
		{                           //求变换后结果的模值
			Am[i]=sqrt(s[i].real*s[i].real+s[i].imag*s[i].imag);
			//	cout<<Am[i]<<endl;
		}
		for(i=(int)(50*(FFT_N*0.02/caiyanglv))-2;i<=(int)(50*(FFT_N*0.02/caiyanglv))+3;i++)
		{
			if(Am[i]<=Am[i+1]) j=i+1;
			else if(Am[j]<=Am[i])j=i;
			else j=j;
		}
		c=Am[j+1]/Am[j];
		e=sqrt((2*c-1)/(c+1)*(2*c-1)/(c+1));	
		F[0]=(j-e)*1/(FFT_N*0.02/caiyanglv);
// 		cout<<F[0]<<endl;
		oU=sqrt((F[0]-50.0)*(F[0]-50.0));
// 		cout<<oU<<endl;
		oU=oU/50.0*100.0;
		// 		cout<<"供电频率偏差为："<<oU<<"%"<<endl;
		str.Format("%f",oU);
		m_freqDrift.SetWindowText(str+"%");
		break;
	case Ac:
		S=0;
		for(i=0;i<256*caiyanglv;i++)                           //给结构体赋值
		{
			double w=0.5-0.5*cos(2*PI*i/FFT_N);
			s[i].real=packet2receive.data_to_receive.currentC[i]; //实部为正弦波FFT_N点采样，赋值为1
			s[i].imag=0;                                //虚部为0
			temp[i].real=s[i].real;
			temp[i].imag=0;
			S=S+s[i].real*s[i].real; 
			s[i].real=s[i].real*w; 
		}
		FFT(s);    //进行快速福利叶变换
		for(i=0;i<FFT_N;i++)
		{                           //求变换后结果的模值
			Am[i]=sqrt(s[i].real*s[i].real+s[i].imag*s[i].imag);
			//	cout<<Am[i]<<endl;
		}
		for(i=(int)(50*(FFT_N*0.02/caiyanglv))-2;i<=(int)(50*(FFT_N*0.02/caiyanglv))+3;i++)
		{
			if(Am[i]<=Am[i+1]) j=i+1;
			else if(Am[j]<=Am[i])j=i;
			else j=j;
		}
		c=Am[j+1]/Am[j];
		e=sqrt((2*c-1)/(c+1)*(2*c-1)/(c+1));	
		F[0]=(j-e)*1/(FFT_N*0.02/caiyanglv);
// 		cout<<F[0]<<endl;
		oU=sqrt((F[0]-50.0)*(F[0]-50.0));
// 		cout<<oU<<endl;
		oU=oU/50.0*100.0;
		// 		cout<<"供电频率偏差为："<<oU<<"%"<<endl;
		str.Format("%f",oU);
		m_freqDrift.SetWindowText(str+"%");
		break;
	case Va:
		S=0;
		for(i=0;i<256*caiyanglv;i++)                           //给结构体赋值
		{
			double w=0.5-0.5*cos(2*PI*i/FFT_N);
			s[i].real=packet2receive.data_to_receive.VoltageA[i]; //实部为正弦波FFT_N点采样，赋值为1
			s[i].imag=0;                                //虚部为0
			temp[i].real=s[i].real;
			temp[i].imag=0;
			S=S+s[i].real*s[i].real; 
			s[i].real=s[i].real*w; 
		}
		FFT(s);    //进行快速福利叶变换
		for(i=0;i<FFT_N;i++)
		{                           //求变换后结果的模值
			Am[i]=sqrt(s[i].real*s[i].real+s[i].imag*s[i].imag);
			//	cout<<Am[i]<<endl;
		}
		for(i=(int)(50*(FFT_N*0.02/caiyanglv))-2;i<=(int)(50*(FFT_N*0.02/caiyanglv))+3;i++)
		{
			if(Am[i]<=Am[i+1]) j=i+1;
			else if(Am[j]<=Am[i])j=i;
			else j=j;
		}
		c=Am[j+1]/Am[j];
		e=sqrt((2*c-1)/(c+1)*(2*c-1)/(c+1));	
		F[0]=(j-e)*1/(FFT_N*0.02/caiyanglv);
// 		cout<<F[0]<<endl;
		oU=sqrt((F[0]-50.0)*(F[0]-50.0));
// 		cout<<oU<<endl;
		oU=oU/50.0*100.0;
		// 		cout<<"供电频率偏差为："<<oU<<"%"<<endl;
		str.Format("%f",oU);
		m_freqDrift.SetWindowText(str+"%");
		break;
	case Vb:
		S=0;
		for(i=0;i<256*caiyanglv;i++)                           //给结构体赋值
		{
			double w=0.5-0.5*cos(2*PI*i/FFT_N);
			s[i].real=packet2receive.data_to_receive.VoltageB[i]; //实部为正弦波FFT_N点采样，赋值为1
			s[i].imag=0;                                //虚部为0
			temp[i].real=s[i].real;
			temp[i].imag=0;
			S=S+s[i].real*s[i].real; 
			s[i].real=s[i].real*w; 
		}
		FFT(s);    //进行快速福利叶变换
		for(i=0;i<FFT_N;i++)
		{                           //求变换后结果的模值
			Am[i]=sqrt(s[i].real*s[i].real+s[i].imag*s[i].imag);
			//	cout<<Am[i]<<endl;
		}
		for(i=(int)(50*(FFT_N*0.02/caiyanglv))-2;i<=(int)(50*(FFT_N*0.02/caiyanglv))+3;i++)
		{
			if(Am[i]<=Am[i+1]) j=i+1;
			else if(Am[j]<=Am[i])j=i;
			else j=j;
		}
		c=Am[j+1]/Am[j];
		e=sqrt((2*c-1)/(c+1)*(2*c-1)/(c+1));	
		F[0]=(j-e)*1/(FFT_N*0.02/caiyanglv);
// 		cout<<F[0]<<endl;
		oU=sqrt((F[0]-50.0)*(F[0]-50.0));
// 		cout<<oU<<endl;
		oU=oU/50.0*100.0;
		// 		cout<<"供电频率偏差为："<<oU<<"%"<<endl;
		str.Format("%f",oU);
		m_freqDrift.SetWindowText(str+"%");
		break;
	case Vc:
		S=0;
		for(i=0;i<256*caiyanglv;i++)                           //给结构体赋值
		{
			double w=0.5-0.5*cos(2*PI*i/FFT_N);
			s[i].real=packet2receive.data_to_receive.VoltageC[i]; //实部为正弦波FFT_N点采样，赋值为1
			s[i].imag=0;                                //虚部为0
			temp[i].real=s[i].real;
			temp[i].imag=0;
			S=S+s[i].real*s[i].real; 
			s[i].real=s[i].real*w; 
		}
		FFT(s);    //进行快速福利叶变换
		for(i=0;i<FFT_N;i++)
		{                           //求变换后结果的模值
			Am[i]=sqrt(s[i].real*s[i].real+s[i].imag*s[i].imag);
			//	cout<<Am[i]<<endl;
		}
		for(i=(int)(50*(FFT_N*0.02/caiyanglv))-2;i<=(int)(50*(FFT_N*0.02/caiyanglv))+3;i++)
		{
			if(Am[i]<=Am[i+1]) j=i+1;
			else if(Am[j]<=Am[i])j=i;
			else j=j;
		}
		c=Am[j+1]/Am[j];
		e=sqrt((2*c-1)/(c+1)*(2*c-1)/(c+1));	
		F[0]=(j-e)*1/(FFT_N*0.02/caiyanglv);
// 		cout<<F[0]<<endl;
		oU=sqrt((F[0]-50.0)*(F[0]-50.0));
// 		cout<<oU<<endl;
		oU=oU/50.0*100.0;
		// 		cout<<"供电频率偏差为："<<oU<<"%"<<endl;
		str.Format("%f",oU);
		m_freqDrift.SetWindowText(str+"%");
		break;
	}
	
}


void CReceive1Dlg::OnButton_about() 
{
	// TODO: Add your control notification handler code here
	CAboutDlg dlgAbout;
	dlgAbout.DoModal();
}

void CReceive1Dlg::OnButton_Save() 
{
	// TODO: Add your control notification handler code here
	CString FilePathName="0";
	CFileDialog dlg(false,".txt","Receive.txt",OFN_OVERWRITEPROMPT,"Txt Files (*.txt)|*.txt|Data Files (*.dat)|*.dat|All Files (*.*)|*.*||");///TRUE为OPEN对话框，FALSE为SAVE AS对话框
	dlg.m_ofn.lpstrInitialDir=_T(".\\"); //这里就设置了对话框的默认目录
	if(dlg.DoModal()==IDOK) FilePathName=dlg.GetPathName();

 	ofstream ofile;
	ofile.open(FilePathName);
	ofile<<"seq:"<<'\t'<<"Ia"<<'\t'<<"Ib"<<'\t'<<"Ic"<<'\t'<<"In"<<'\t'<<"Va"<<'\t'<<"Vb"<<'\t'<<"Vc"<<'\t'<<"Vn"<<endl;
	for(int i=0;i<packet2receive.smpCount;i++)
	{
		ofile<<i+1<<'\t'
			<<packet2receive.data_to_receive.currentA[i]<<'\t'
			<<packet2receive.data_to_receive.currentB[i]<<'\t'
			<<packet2receive.data_to_receive.currentC[i]<<'\t'
			<<packet2receive.data_to_receive.currentN[i]<<'\t'

			<<packet2receive.data_to_receive.VoltageA[i]<<'\t'
			<<packet2receive.data_to_receive.VoltageB[i]<<'\t'
			<<packet2receive.data_to_receive.VoltageC[i]<<'\t'
			<<packet2receive.data_to_receive.VoltageN[i]<<'\t'
			<<endl;
	}
	ofile.close();
// 	ofile.open("a.txt");
//  	for(int i=0;i<packet2receive.smpCount;i++)
//  	{
//  		ofile<<packet2receive.data_to_receive.currentA[i]<<endl;
//  	}
//  	ofile.close();
// 	
// 	ofile.open("b.txt");
//  	for(int j=0;j<packet2receive.smpCount;j++)
// 	{
//  		ofile<<packet2receive.data_to_receive.currentB[j]<<endl;
//  	}
//  	ofile.close();
//  	
//  	ofile.open("c.txt");
//  	for(int k=0;k<packet2receive.smpCount;k++)
//  	{
//  		ofile<<packet2receive.data_to_receive.currentC[k]<<endl;
//  	}
// 	ofile.close();
}

void CReceive1Dlg::Calculate()
{
	CString str;
	S=0;
// 	S1=0;
// 	S2=0;
// 	R=0;
// 	R1=0;
// 	R2=0;
	caiyanglv=packet2receive.smpRate;
	m_youxiaozhi.GetWindowText(str);
	youxiaozhi=atof(str);
	FFT_N=8192;

}

void CReceive1Dlg::OnOutofmemorySliderA(NMHDR* pNMHDR, LRESULT* pResult) 
{
	// TODO: Add your control notification handler code here
	sliderA=m_slider_a.GetPos();
	*pResult = 0;
}

void CReceive1Dlg::OnOutofmemorySliderV(NMHDR* pNMHDR, LRESULT* pResult) 
{
	// TODO: Add your control notification handler code here
	sliderV=m_slider_v.GetPos();
	*pResult = 0;
}
