// Packet.h: interface for the Packet class.
//
//////////////////////////////////////////////////////////////////////

#if !defined(AFX_PACKET_H__D7EBC7B8_F5C3_40B6_9C82_F2174B77E4A4__INCLUDED_)
#define AFX_PACKET_H__D7EBC7B8_F5C3_40B6_9C82_F2174B77E4A4__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#include "DataType.h"

class Packet  
{
public:
	void DataRead_32_f(float * value, int point);
	float Hex_To_Decimal_f(unsigned char *Byte);
	void DataRead_32_i(INT32U * value, int point);
	INT32U Hex_To_Decimal_i_32(unsigned char *Byte);
	void DataRead_16_i(INT16U * value, int point);	
	INT16U Hex_To_Decimal_i(unsigned char *Byte);
	unsigned char packet[110];//发送的数据包
// 	int send_len;//设置发送长度
	INT32U rate;
	INT16U smpCount;
	INT16U smpRate;
	INT16U AppidLen;				//组贞时计算，从APPID开始，是APDU的长度
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
	struct data2receive 
	{
// 		float am_Aa;
// 		float am_Ab;
// 		float am_Ac;
// 		float am_An;
		float currentA[100000];
		float currentB[100000];
		float currentC[100000];
		float currentN[100000];
		
// 		float am_Va;
// 		float am_Vb;
// 		float am_Vc;
// 		float am_Vn;
		float VoltageA[100000];
		float VoltageB[100000];
		float VoltageC[100000];
		float VoltageN[100000];
	}data_to_receive;
// 	
// 	unsigned char *asduN;
// 	unsigned char *asduM;

	void readPacket();
// 	void destroy_asdu();
// 	void DataSet_16(INT16U value, unsigned char *des);
// 	void DataSet_32(float value,unsigned char *des);
	
// 	void creat_asdu_a(INT8U len,char id,INT16U scount,INT16U srate,INT8U slen,data2send *data);
// 	void creat_asdu_v(INT8U len,char id,INT16U scount,INT16U srate,INT8U slen,data2send *data);
	Packet();
	virtual ~Packet();

};

#endif // !defined(AFX_PACKET_H__D7EBC7B8_F5C3_40B6_9C82_F2174B77E4A4__INCLUDED_)
