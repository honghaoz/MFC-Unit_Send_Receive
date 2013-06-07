// Packet.cpp: implementation of the Packet class.
//
//////////////////////////////////////////////////////////////////////

#include "stdafx.h"
#include "Receive1.h"
#include "Packet.h"

#ifdef _DEBUG
#undef THIS_FILE
static char THIS_FILE[]=__FILE__;
#define new DEBUG_NEW
#endif

//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

Packet::Packet()
{
	smpCount=0;
	smpRate=0;
}
void Packet::readPacket(){
//读电压，正常应该是通过分析标记字及长度来读取，现在从简，简单处理
	DataRead_16_i(&smpCount,40);
// 	DataRead_32_i(&rate,42);
	DataRead_16_i(&smpRate,50);

	DataRead_32_f(&data_to_receive.VoltageA[smpCount-1],54);
	DataRead_32_f(&data_to_receive.VoltageB[smpCount-1],58);
	DataRead_32_f(&data_to_receive.VoltageC[smpCount-1],62);
	DataRead_32_f(&data_to_receive.VoltageN[smpCount-1],66);
//读电流
	DataRead_16_i(&smpCount,77);
	DataRead_16_i(&smpRate,87);

	DataRead_32_f(&data_to_receive.currentA[smpCount-1],91);
	DataRead_32_f(&data_to_receive.currentB[smpCount-1],95);
	DataRead_32_f(&data_to_receive.currentC[smpCount-1],99);
	DataRead_32_f(&data_to_receive.currentN[smpCount-1],103);

}
Packet::~Packet()
{

}

void Packet::DataRead_32_f(float * value, int point)
{
	unsigned char byte[4];
	for(int i=0;i<4;i++){
		byte[i]=packet[point++];
	}
	*(value)=Hex_To_Decimal_f(byte);
}


void Packet::DataRead_16_i(INT16U * value, int point)
{
	unsigned char byte[2];
	for(int i=0;i<2;i++){
		byte[i]=packet[point++];
	}
	*(value)=Hex_To_Decimal_i(byte);
}

void Packet::DataRead_32_i(INT32U * value, int point)
{
	unsigned char byte[4];
	for(int i=0;i<4;i++){
		byte[i]=packet[point++];
	}
	*(value)=Hex_To_Decimal_i_32(byte);

}

float Packet::Hex_To_Decimal_f(unsigned char *Byte)
{
	unsigned char cByte[4];//方法一
    for (int i=0;i<4;i++)
    {
		cByte[i] = Byte[3-i];
    }
	
	float pfValue=*(float*)&cByte;
	
	return  pfValue;
	
	/*		return *((float*)Byte);//方法二*/
}
INT16U Packet::Hex_To_Decimal_i(unsigned char *Byte)
{
	unsigned char cByte[2];//方法一
    for (int i=0;i<2;i++)
    {
		cByte[i] = Byte[1-i];
    }
	
	INT16U pfValue=*(INT16U*)&cByte;
	
	return  pfValue;
	
	/*		return *((float*)Byte);//方法二*/
}
INT32U Packet::Hex_To_Decimal_i_32(unsigned char *Byte)
{
	unsigned char cByte[4];//方法一
	for (int i=0;i<4;i++)
    {
		cByte[i] = Byte[3-i];
    }
	
	INT32U pfValue=*(INT32U*)&cByte;
	
	return  pfValue;
	/*		return *((float*)Byte);//方法二*/
}
