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
	HANDLE TimerHandle();//��ȡ��ʱ�����������������ʹ�ö�ʱ����
	bool Stop();//ֹͣ��ʱ������
	bool Start();//��ʱ����ʼ���к���
	void Period(LONG p_Period);//�޸Ķ�ʱ������
	void Expires(_int64 p_Expires,bool p_Relative,int p_BaseTime);//�޸Ķ�ʱ�����Ժ���
	bool g_Valid;//��ʱ���ɹ���ʼ����־
	int g_Result;//�ϴβ����Ľ��
	int g_Error;
	LARGE_INTEGER g_TimerExpires;//��ʱ����Ϊ����״̬��ʱ����
	LONG g_TimerPeriod;//��ʱ��Ŀǰ������
	bool g_Set;//��ʱ�����б�־
	BOOL g_ManualReset;//�ֶ����ñ�־
	HANDLE g_TimerHandle;//��ʱ�����
	char g_Name[MAX_PATH];//��ʱ����
	SECURITY_ATTRIBUTES g_SecurityAttributes;//��ȫ����
	SECURITY_DESCRIPTOR g_SecurityDescriptor;//��ȫ������
	ChighPerformanceTimer(CString p_TimerName,bool p_Periodic,LONG p_Period);
	virtual ~ChighPerformanceTimer();

};

#endif // !defined(AFX_HIGHPERFORMANCETIMER_H__20F40B42_7529_4DFF_BDF6_40995F659E47__INCLUDED_)
