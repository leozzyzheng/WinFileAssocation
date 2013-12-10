#ifndef _REG_HELPER_H_
#define _REG_HELPER_H_

#include <windows.h>
#include <stdio.h>
#include <Shlobj.h>

//�÷�����win8�������RegisterFileRelation��������
//win8���Լ���������HASHֵ������ֵ����ͨ�����·�ʽ��ȡ��
//�Թ���ԱȨ������һ��RegisterFileRelation������Ҫ���ԣ�
// Ȼ���ҵ�Ҫ�������ļ�ѡ��Ĭ�ϳ���
// �ٵ�ע���HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FileExts\\��ĺ�׺��\\UserChoice���ҵ�Hash�����ֵ
// ����ֵ��������HASH�궨���м���

//English version:
//usage: if you don't use win8 & win8.1 just call RegisterFileRelation,
//otherwise, you should first call RegisterFileRelation in your app as admin, 
//then find one file that has the wanted ext, used OS's methods(such as right button -> open with)to assocate this file to your app.
//now find the Hash Key value in HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FileExts\\[your ext]\\UserChoice
//change the HASH defination at follow, then you can assocate your file in any win8 PC!
#define HASH ""

#define SYS_VERSION_OTHER 0
#define SYS_VERSION_WIN_XP 1
#define SYS_VERSION_WIN_7 2
#define SYS_VERSION_WIN_8 3

// ע���ļ�����
// strExt: Ҫ������չ��(����: ".txt")
// strAppName: Ҫ������Ӧ�ó�����(����: "C:/MyApp/MyApp.exe")
// strAppFileName: Ҫ������Ӧ�ó���exe����(����: "MyApp.exe")
// strProgid: �����޸�Ĭ�ϴ򿪷�ʽ(����: "Applications/MyApp.exe")
// strAppKey: ExtName��չ����ע����еļ�ֵ(����: "txtfile")
// strDefaultIcon: ��չ��ΪstrAppName��ͼ���ļ�(����: "C:/MyApp/MyApp.exe,0")
// strDescribe: �ļ���������
BOOL  RegisterFileRelation(char *strExt, char *strAppName, char * strAppFileName, char * strProgid, char *strAppKey, char *strDefaultIcon, char *strDescribe);

/*++ 
Routine Description: This routine returns TRUE if the caller's
process is a member of the Administrators local group. Caller is NOT
expected to be impersonating anyone and is expected to be able to
open its own process and process token. 
Arguments: None. 
Return Value: 
   TRUE - Caller has Administrators local group. 
   FALSE - Caller does not have Administrators local group. --
*/ 
BOOL IsUserAdmin(VOID);

//��ȡwindowsϵͳ��
//����ֵ:winxp-1, win7-2, win8-3, ����-0
int GetSystemVersion();

//��ȡע����������Ȩ��
BOOL GaintKeyPrivilege(HKEY & hKey);

#endif /* _REG_HELPER_H_ */