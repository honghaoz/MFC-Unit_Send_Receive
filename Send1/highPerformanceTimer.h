// highPerformanceTimer.h: interface for the ChighPerformanceTimer class.
//
//////////////////////////////////////////////////////////////////////

#if !defined(AFX_HIGHPERFORMANCETIMER_H__20F40B42_7529_4DFF_BDF6_40995F659E47__INCLUDED_)
#define AFX_HIGHPERFORMANCETIMER_H__20F40B42_7529_4DFF_BDF6_40995F659E47__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#define g_WaitableTimer_TickOkay 1;
#define g_WaitableTimer_NotValid 2;
#define g_WaitableTimer_TickError 3;
class ChighPerformanceTimer  
{
public:
	HANDLE TimerHandle();//获取定时器句柄（用于其他类使用定时器）
	bool Stop();//停止定时器运行
	bool Start();//定时器开始运行函数
	void Period(LONG p_Period);//修改定时器周期
	void Expires(_int64 p_Expires,bool p_Relative,int p_BaseTime);//修改定时器属性函数
	bool g_Valid;//定时器成功初始化标志
	int g_Result;//上次操作的结果
	int g_Error;
	LARGE_INTEGER g_TimerExpires;//定时器变为阻塞状态的时间间隔
	LONG g_TimerPeriod;//定时器目前的周期
	bool g_Set;//定时器运行标志
	BOOL g_ManualReset;//手动设置标志
	HANDLE g_TimerHandle;//定时器句柄
	char g_Name[MAX_PATH];//定时器名
	SECURITY_ATTRIBUTES g_SecurityAttributes;//安全属性
	SECURITY_DESCRIPTOR g_SecurityDescriptor;//安全描述符
	ChighPerformanceTimer(CString p_TimerName,bool p_Periodic,LONG p_Period);
	virtual ~ChighPerformanceTimer();

};

#endif // !defined(AFX_HIGHPERFORMANCETIMER_H__20F40B42_7529_4DFF_BDF6_40995F659E47__INCLUDED_)
