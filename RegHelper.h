#ifndef _REG_HELPER_H_
#define _REG_HELPER_H_

#include <windows.h>
#include <stdio.h>
#include <Shlobj.h>

//用法：非win8仅需调用RegisterFileRelation函数即可
//win8需自己定义下面HASH值，具体值可以通过如下方式获取：
//以管理员权限运行一次RegisterFileRelation（参数要给对）
// 然后找到要关联的文件选择默认程序
// 再到注册表HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FileExts\\你的后缀名\\UserChoice中找到Hash这个键值
// 将键值填入下面HASH宏定义中即可

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

// 注册文件关联
// strExt: 要检测的扩展名(例如: ".txt")
// strAppName: 要关联的应用程序名(例如: "C:/MyApp/MyApp.exe")
// strAppFileName: 要关联的应用程序exe名称(例如: "MyApp.exe")
// strProgid: 用于修改默认打开方式(例如: "Applications/MyApp.exe")
// strAppKey: ExtName扩展名在注册表中的键值(例如: "txtfile")
// strDefaultIcon: 扩展名为strAppName的图标文件(例如: "C:/MyApp/MyApp.exe,0")
// strDescribe: 文件类型描述
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

//获取windows系统版
//返回值:winxp-1, win7-2, win8-3, 其他-0
int GetSystemVersion();

//获取注册表键的所有权限
BOOL GaintKeyPrivilege(HKEY & hKey);

#endif /* _REG_HELPER_H_ */