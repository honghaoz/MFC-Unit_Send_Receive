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
// 	p_TimerName 定时器名；
// 	p_Periodic 设置是否为周期性定时器；
// 	p_Period时钟周期
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
		//如果定时器已经创建， 则使用已有的定时器；否则建立一个新的定时器
		g_TimerHandle=OpenWaitableTimer(TIMER_ALL_ACCESS | TIMER_MODIFY_STATE | SYNCHRONIZE,TRUE,(char *) g_Name);
		if (g_TimerHandle==NULL)
		{
			//建立并且初始化缺省的安全描述符和属性
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
// 	p_Expires：设置定时器变为阻塞状态的时间间隔，以 100 纳秒为单位， 精度高。
// 	p_Relative： 设置是相对时间还是绝对时间， 相对时间与当前的系统有关， 绝对时间则为格林威治时间。
// 	p_BaseTime： 若为相对时间， 指明 p_Expires 的时间基准单位， 纳秒、 微秒还是毫秒。
	g_TimerExpires.QuadPart=1*p_Expires;
	if (p_Relative)
		g_TimerExpires.QuadPart=-1*p_Expires;
	if(p_BaseTime==0)//以100纳秒为单位
		return;
	g_TimerExpires.QuadPart=10*g_TimerExpires.QuadPart;
	if(p_BaseTime==1)//以微秒为单位
		return;
	g_TimerExpires.QuadPart=1000*g_TimerExpires.QuadPart;
	if(p_BaseTime==2)//以毫秒为单位
		return;
	g_TimerExpires.QuadPart=1000*g_TimerExpires.QuadPart;
	if(p_BaseTime==3)//以秒为单位
		return;
	g_TimerExpires.QuadPart=60*g_TimerExpires.QuadPart;
	if(p_BaseTime==4)//以分为单位
		return;
	g_TimerExpires.QuadPart=60*g_TimerExpires.QuadPart;//以小时为单位
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
