// Packet.cpp: implementation of the Packet class.
//
//////////////////////////////////////////////////////////////////////

#include "stdafx.h"
#include "Send1.h"
#include "Packet.h"

#ifdef _DEBUG
#undef THIS_FILE
static char THIS_FILE[]=__FILE__;
#define new DEBUG_NEW
#endif

//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

Packet::Packet(INT8U num)
{
	send_len=0;//设置发送长度
	smpCount=0;
	smpRate=0;
// 	for(int i=0;i<256;i++){
// 		packet[i]=0x00;
// 	}
	for (int i = 0; i < 6; i++)
	{
		packet [i] = 0xff;
		packet [i+6] = 0;
	}
// 	TPID [0] = 0x81;						//以太网类型,固定0x8100
// 	TPID [1] = 0x00;
	packet[12]=0x81;
 	packet[13]=0x00;
// 	TCI [0]	= 0x80;							//可配置,默认0x80 00
// 	TCI [1] = 0x00;
	packet[14]=0x80;
	packet[15]=0x00;

// 	type	= ETHERTYPE_61850_9_2_SAMPLE;	//固定0x88ba
	packet[16]=0x88;
	packet[17]=0xBA;

// 	APPID	= 0x4000;	//默认					//默认最高两位是01,smv保留0x4000-0x4fff
	packet[18]=0x40;//本处采用4000为APPID
	packet[19]=0x00;


// 	长度Length：从 APPID开始的字节数。 
//需要修改
	packet[20]=0x00;
	packet[21]=0;//length  发送的数组减去17 如packet[96],则len=96-17=79
	AppidLen	= 0;//初始化16wei
// 	Reserved [0]	= 0;					//0x0000
// 	Reserved [1]	= 0;
// 	Reserved [2]	= 0;
// 	Reserved [3]	= 0;
	//Reserved1
	packet[22]=0x00;
	packet[23]=0x00;
	//Reserved2
	packet[24]=0x00;
	packet[25]=0x00;
//apdu SAV PDU
	packet[26]=0x60;////APDU 标记（=0x60） 9-2
//需要修改
	packet[27]=69;//APDU长度
	APDULen	= 0;//初始化
	packet[28]=0x80;//ASDU数目：标记（=0x80）固定
	packet[29]=0x01;//ASDU数目：长度 固定
//需要修改
    packet[30]=0x02;//ASDU数目：值（=1）  类型  INT16U 编码为 asn.1 整型编码
	ASDUnum=num;
//	pasdu=new asdu[ASDUnum];
//以下就是ASDU的组装
	//Asdus head
	packet[31]=0xa2;//ASDU序列 标记（=0xA2）
//需要修改
	packet[32]=64;//length //Sequence of ASDU 长度

}

Packet::~Packet()
{
// 	destroy_asdu();
// 	delete []asduN;
// 	delete []asduM;
}

void Packet::DataSet_32(float value, unsigned char *des)
{
	float *p_f=&value;
	unsigned char *src=(unsigned char *)p_f;
	memcpy(des,src+3,8);
	memcpy(des+1,src+2,8);
	memcpy(des+2,src+1,8);
	memcpy(des+3,src,8);
}

void Packet::DataSet_32_i(INT32U value, unsigned char *des)
{
	INT32U *p_f=&value;
	unsigned char *src=(unsigned char *)p_f;
	memcpy(des,src+3,8);
	memcpy(des+1,src+2,8);
	memcpy(des+2,src+1,8);
	memcpy(des+3,src,8);
}
void Packet::DataSet_16(INT16U value, unsigned char *des)
{
	INT16U *p_f=&value;
	unsigned char *src=(unsigned char *)p_f;
	memcpy(des,src+1,8);
	memcpy(des+1,src,8);
}

void Packet::creat_asdu_a(INT8U len, char id, INT16U scount, INT16U srate, INT8U slen,data2send *data)
{
// 	asduN=new unsigned char[len+2];
	asduN[0]=0x30;
	asduN[1]=len;
	asduN[2]=0x80;//id
	asduN[3]=0x01;
	asduN[4]=id;

	asduN[5]=0x82;//count
	asduN[6]=0x02;
 	DataSet_16(scount,&asduN[7]);//[7][8][9][10]

	asduN[9]=0x83;
	asduN[10]=0x01;
	asduN[11]=1;
	asduN[12]=0x85;
	asduN[13]=0x01;
	asduN[14]=1;

	asduN[15]=0x86;//rate
	asduN[16]=0x02;
	DataSet_16(srate,&asduN[17]);//[19][20]
	
	asduN[19]=0x87;
	asduN[20]=slen;
	DataSet_32(data->currentA,&asduN[21]);//[22][23][24][25]
	DataSet_32(data->currentB,&asduN[25]);//[26][27][28][29]
	DataSet_32(data->currentC,&asduN[29]);//[30][31][32][33]
	DataSet_32(data->currentN,&asduN[33]);//[35][36][37][38]
}
void Packet::creat_asdu_v(INT8U len, char id, INT16U scount, INT16U srate, INT8U slen,data2send *data)
{
// 	asduM=new unsigned char[len+2];
	asduM[0]=0x30;
	asduM[1]=len;
	asduM[2]=0x80;//id
	asduM[3]=0x01;
	asduM[4]=id;

	asduM[5]=0x82;//count
	asduM[6]=0x02;
	DataSet_16(scount,&asduM[7]);//[7][8][9][10]

	asduM[9]=0x83;
	asduM[10]=0x01;
	asduM[11]=1;
	asduM[12]=0x85;
	asduM[13]=0x01;
	asduM[14]=1;

	asduM[15]=0x86;//rate
	asduM[16]=0x02;
	DataSet_16(srate,&asduM[17]);//[19][20]

	asduM[19]=0x87;
	asduM[20]=slen;
	DataSet_32(data->VoltageA,&asduM[21]);//[22][23][24][25]
	DataSet_32(data->VoltageB,&asduM[25]);//[26][27][28][29]
	DataSet_32(data->VoltageC,&asduM[29]);//[30][31][32][33]
	DataSet_32(data->VoltageN,&asduM[33]);//[35][36][37][38]

// 	asduM[15]=0x87;
// 	asduM[16]=slen;
// 	DataSet_32(data->VoltageA,&asduM[17]);//[22][23][24][25]
// 	DataSet_32(data->VoltageB,&asduM[21]);//[26][27][28][29]
// 	DataSet_32(data->VoltageC,&asduM[25]);//[30][31][32][33]
// 	DataSet_32(data->VoltageN,&asduM[29]);//[33][34][35][36]
// 	asduM[33]=0x86;//rate
// 	asduM[34]=0x02;
// 	DataSet_16(srate,&asduM[35]);//[18][19]
}

void Packet::destroy_asdu()
{
// 	delete []asduN;
// 	delete []asduM;
}

void Packet::CreatFrame()
{
	smpCount++;
	// 	TPID [0] = 0x81;						//以太网类型,固定0x8100
	// 	TPID [1] = 0x00;
	packet[12]=0x81;
	packet[13]=0x00;
	// 	TCI [0]	= 0x80;							//可配置,默认0x80 00
	// 	TCI [1] = 0x00;
	packet[14]=0x80;
	packet[15]=0x00;


	packet[20]=0x00;
	packet[21]=89;//length  发送的数组减去17 如packet[96],则len=96-17=79 106-17=89 110-17=
				//此处需要计算长度，暂时做个测试，不计算，直接设置
	AppidLen= 89;

	packet[27]=79;//APDU长度
	APDULen	= 79;//初始化

    packet[30]=0x02;//ASDU数目：值（=1）  类型  INT16U 编码为 asn.1 整型编码
	packet[32]=74;//length //Sequence of ASDU 长度

	creat_asdu_v(35,'V',smpCount,smpRate,16,&data_to_send);
	for (int i=0;i<37;i++)
	{
		packet[33+i]=asduM[i];
	}

// 	destroy_asdu();
	creat_asdu_a(35,'A',smpCount,smpRate,16,&data_to_send);

	for (int j=0;j<37;j++)
	{
		packet[70+j]=asduN[j];//从70开始
	}
// 	destroy_asdu();
	send_len=107;
// 	delete asduM;
// 	delete asduN;
}

void Packet::RecCurrent_Voltage()
{
	data_to_send.Ia[smpCount]=data_to_send.currentA;
	data_to_send.Ib[smpCount]=data_to_send.currentB;
	data_to_send.Ic[smpCount]=data_to_send.currentC;
	data_to_send.In[smpCount]=data_to_send.currentN;

	data_to_send.Vola[smpCount]=data_to_send.VoltageA;
	data_to_send.Volb[smpCount]=data_to_send.VoltageB;
	data_to_send.Volc[smpCount]=data_to_send.VoltageC;
	data_to_send.Voln[smpCount]=data_to_send.VoltageN;

}

void Packet::SetAppID(INT16U appid)
{
	//用来设置应用ID
	APPID=appid;
}

void Packet::SetTCI(INT8U tci[])
{

}

void Packet::SetType(INT16U type)
{

}
