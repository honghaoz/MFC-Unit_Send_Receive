// highPerformanceTimer.cpp: implementation of the ChighPerformanceTimer class.
//
//////////////////////////////////////////////////////////////////////

#include "stdafx.h"
#include "Send1.h"
#include "highPerformanceTimer.h"
// #include "Winbase.h"
// #include "Windows.h"
// #include "Winnt.h"
// 
// #pragma comment(lib,"Advapi32.lib")
#ifdef _DEBUG
#undef THIS_FILE
static char THIS_FILE[]=__FILE__;
#define new DEBUG_NEW
#endif

//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

ChighPerformanceTimer::ChighPerformanceTimer(CString p_TimerName,bool p_Periodic,LONG p_Period)
{
// 	p_TimerName ��ʱ������
// 	p_Periodic �����Ƿ�Ϊ�����Զ�ʱ����
// 	p_Periodʱ������
	g_Valid=false;
	if (p_Periodic)
	{
		g_TimerPeriod=p_Period;
		g_ManualReset=false;
	}
	else
	{
		g_TimerPeriod=0;
		g_ManualReset=true;
	}
	g_Set=false;
	g_TimerExpires.QuadPart=Int32x32To64(-10000,p_Period);
	memset(g_Name,0,MAX_PATH);
	if (! p_TimerName.IsEmpty())
		if(p_TimerName.GetLength()>MAX_PATH)
			memcpy(g_Name,p_TimerName,MAX_PATH);
		else
			memcpy(g_Name,p_TimerName,p_TimerName.GetLength());
		//�����ʱ���Ѿ������� ��ʹ�����еĶ�ʱ����������һ���µĶ�ʱ��
		g_TimerHandle=OpenWaitableTimer(TIMER_ALL_ACCESS | TIMER_MODIFY_STATE | SYNCHRONIZE,TRUE,(char *) g_Name);
		if (g_TimerHandle==NULL)
		{
			//�������ҳ�ʼ��ȱʡ�İ�ȫ������������
			g_SecurityAttributes.lpSecurityDescriptor=&g_SecurityDescriptor;
			InitializeSecurityDescriptor(g_SecurityAttributes.lpSecurityDescriptor,SECURITY_DESCRIPTOR_REVISION);
			SetSecurityDescriptorDacl(g_SecurityAttributes.lpSecurityDescriptor,TRUE,(PACL)NULL,FALSE);
			g_SecurityAttributes.nLength = sizeof SECURITY_ATTRIBUTES;
			g_SecurityAttributes.bInheritHandle=TRUE;
			g_TimerHandle=CreateWaitableTimer(&g_SecurityAttributes,g_ManualReset,(char *)g_Name);
		}
		if(g_TimerHandle==NULL)
		{
			//ERROR AND RETURN
			return;
		}
		g_Result=g_WaitableTimer_TickOkay;//?????????
		g_Valid=true;
}

ChighPerformanceTimer::~ChighPerformanceTimer()
{

}

void ChighPerformanceTimer::Expires(__int64 p_Expires, bool p_Relative, int p_BaseTime)
{
// 	p_Expires�����ö�ʱ����Ϊ����״̬��ʱ�������� 100 ����Ϊ��λ�� ���ȸߡ�
// 	p_Relative�� ���������ʱ�仹�Ǿ���ʱ�䣬 ���ʱ���뵱ǰ��ϵͳ�йأ� ����ʱ����Ϊ��������ʱ�䡣
// 	p_BaseTime�� ��Ϊ���ʱ�䣬 ָ�� p_Expires ��ʱ���׼��λ�� ���롢 ΢�뻹�Ǻ��롣
	g_TimerExpires.QuadPart=1*p_Expires;
	if (p_Relative)
		g_TimerExpires.QuadPart=-1*p_Expires;
	if(p_BaseTime==0)//��100����Ϊ��λ
		return;
	g_TimerExpires.QuadPart=10*g_TimerExpires.QuadPart;
	if(p_BaseTime==1)//��΢��Ϊ��λ
		return;
	g_TimerExpires.QuadPart=1000*g_TimerExpires.QuadPart;
	if(p_BaseTime==2)//�Ժ���Ϊ��λ
		return;
	g_TimerExpires.QuadPart=1000*g_TimerExpires.QuadPart;
	if(p_BaseTime==3)//����Ϊ��λ
		return;
	g_TimerExpires.QuadPart=60*g_TimerExpires.QuadPart;
	if(p_BaseTime==4)//�Է�Ϊ��λ
		return;
	g_TimerExpires.QuadPart=60*g_TimerExpires.QuadPart;//��СʱΪ��λ
	return;
}

void ChighPerformanceTimer::Period(LONG p_Period)
{
	g_TimerPeriod=p_Period;
}

bool ChighPerformanceTimer::Start()
{
	if ((! g_Valid) || (g_TimerHandle==NULL))
	{
		g_Result=g_WaitableTimer_NotValid;
		return false;
	}
	g_Set=false;
	if (! SetWaitableTimer(g_TimerHandle,&g_TimerExpires,g_TimerPeriod,NULL,NULL,FALSE))
	{
 		g_Error=GetLastError();
		g_Result=g_WaitableTimer_TickError;
		return false;
	}
	g_Set=true;
	return true;
}

bool ChighPerformanceTimer::Stop()
{
	g_Error=0;
	if (g_TimerHandle==NULL)
	{
		g_Result=g_WaitableTimer_NotValid;
		return false;
	}
	g_Set=false;
	if (! CancelWaitableTimer(g_TimerHandle))
	{
		g_Error=GetLastError();
		g_Result=g_WaitableTimer_TickError;
		return false;
	}
	return true;
}

HANDLE ChighPerformanceTimer::TimerHandle()
{
	return g_TimerHandle;
}
