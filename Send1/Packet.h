// Packet.h: interface for the Packet class.
//
//////////////////////////////////////////////////////////////////////

#if !defined(AFX_PACKET_H__C7D7C268_5F84_4661_BB44_2AA211DEFB64__INCLUDED_)
#define AFX_PACKET_H__C7D7C268_5F84_4661_BB44_2AA211DEFB64__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#include "DataType.h"

// #define TPID 0x8100
// #define TCI  0x8000
#define ETHERTYPE_61850_8_1_GOOSE 0x88B8
#define ETHERTYPE_61850_9_1_SAMPLE 0x88BA
#define ETHERTYPE_61850_9_2_SAMPLE 0x88BA

class Packet  
{
public:
	void SetType(INT16U type);
	void SetTCI(INT8U tci[]);
	void SetAppID(INT16U appid);
	unsigned char packet[110];//发送的数据包
	int send_len;//设置发送长度
	INT16U smpCount;
	INT16U smpRate;
	//Attributes
// 	INT8U dstAddr [6];			//MAC目的地址
// 	INT8U srcAddr [6];			//MAC源地址
// 	INT8U TPID [2];				//以太网类型,固定0x8100
// 	INT8U TCI [2];				//可配置,默认0x80 00
// 	INT16U type;				//固定,goose: 0x88 b8; smv: 0x88ba
 	INT16U APPID;				//默认:goose最高两位是00,保留0x000-0x3fff;
	//smv最高两位01，保留0x4000-0x4fff;
	INT16U AppidLen;				//组贞时计算，从APPID开始，是APDU的长度
// 	INT8U Reserved [4];			//0x0000
	INT8U APDULen;
	INT8U ASDUnum;
// 	struct asdu{
// 		INT8U asduTAG;
// 		INT8U asduLEN;
// 		char ID;
// 		INT16U sample_count;
// 		INT16U sample_rate;
// 		INT8U sample_len;
// 	}/**pasdu*/;
	struct data2send 
	{
		float am_Aa;
		float am_Ab;
		float am_Ac;
		float am_An;
		float currentA;
		float currentB;
		float currentC;
		float currentN;
		float Ia[100000];
		float Ib[100000];
		float Ic[100000];
		float In[100000];
		
		float am_Va;
		float am_Vb;
		float am_Vc;
		float am_Vn;
		float VoltageA;
		float VoltageB;
		float VoltageC;
		float VoltageN;
		float Vola[100000];
		float Volb[100000];
		float Volc[100000];
		float Voln[100000];
	}data_to_send;

	struct asdu{
		//attributes
		INT8U	*pSvID;				//0x80, M. sample value ID
		INT8U	*pDatset;			//0x81, M. data set
		INT16U	smpCnt;				//0x82, M. sample count
		INT32U	confRev;			//0x83, O. configure reverse
// 		INT8U	refrTm [REFRTMLEN];	//0x84, O. refresh time
		BOOLEAN	smpSynch;			//0x85, O. sample synchronase
		INT16U	smpRate;			//0x86, M. sample rate
// 		DATA_TYPE	*pData;			//0x87, M. sequence of data
		////number of data
		INT8U	noData;				//number of data
		INT8U	cfgByte;			//configure of optional fields
		INT8U	Len;				//len of asdu
		//methods
		BOOLEAN initial ();
		BOOLEAN configure (INT8U cf);
		BOOLEAN setSvID (char *psvid);
		BOOLEAN setDatSet (char *pdatset);
		BOOLEAN setSmpCnt (INT16U cnt);
		BOOLEAN setConfRev (INT32U confrev);
		BOOLEAN setRefrTim (INT8U tim []);
		BOOLEAN setSmpSynch (BOOLEAN isSyn);
		BOOLEAN setSmpRate (INT16U smprt);
// 		BOOLEAN setData (DATA_TYPE *pd);
		BOOLEAN setNoData (INT8U no);
	BOOLEAN destroy ();
	}ASDU;

	unsigned char asduN[37];
	unsigned char asduM[37];
	Packet(INT8U num=2);
	virtual ~Packet();
	void RecCurrent_Voltage();
	void CreatFrame();
	void destroy_asdu();
	void DataSet_16(INT16U value, unsigned char *des);
	void DataSet_32(float value,unsigned char *des);
	void DataSet_32_i(INT32U value,unsigned char *des);

	void creat_asdu_a(INT8U len,char id,INT16U scount,INT16U srate,INT8U slen,data2send *data);
	void creat_asdu_v(INT8U len,char id,INT16U scount,INT16U srate,INT8U slen,data2send *data);


// 	SetPriority_tagged(/*UINT32 = TPID,UINT32 = TCI*/);

};

#endif // !defined(AFX_PACKET_H__C7D7C268_5F84_4661_BB44_2AA211DEFB64__INCLUDED_)
