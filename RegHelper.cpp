#include "RegHelper.h"

BOOL  RegisterFileRelation(char *strExt, char *strAppName, char * strAppFileName, char * strProgid, char *strAppKey, char *strDefaultIcon, char *strDescribe)
{
    char strTemp[_MAX_PATH];
    HKEY hKey;
    BOOL bSuccess = FALSE;

    int sysVersion = GetSystemVersion();

    RegCreateKeyA(HKEY_CLASSES_ROOT,strExt,&hKey);
    RegSetValueExA(hKey,"",NULL,REG_SZ,(BYTE*)strAppKey,strlen(strAppKey)+1);
    RegCloseKey(hKey);

    RegCreateKeyA(HKEY_CLASSES_ROOT,strAppKey,&hKey);
    RegSetValueExA(hKey,"",NULL,REG_SZ,(BYTE*)strDescribe,strlen(strDescribe)+1);
    RegCloseKey(hKey);

    sprintf_s(strTemp,"%s\\DefaultIcon",strAppKey);
    RegCreateKeyA(HKEY_CLASSES_ROOT,strTemp,&hKey);
    RegSetValueExA(hKey,"",NULL,REG_SZ,(BYTE*)strDefaultIcon,strlen(strDefaultIcon)+1);
    RegCloseKey(hKey);

    sprintf_s(strTemp,"%s\\Shell",strAppKey);
    RegCreateKeyA(HKEY_CLASSES_ROOT,strTemp,&hKey);
    RegSetValueExA(hKey,"",NULL,REG_SZ,(BYTE*)"Open",strlen("Open")+1);
    RegCloseKey(hKey);

    sprintf_s(strTemp,"%s\\Shell\\Open\\Command",strAppKey);
    RegCreateKeyA(HKEY_CLASSES_ROOT,strTemp,&hKey);
    sprintf_s(strTemp,"%s \"%%1\"",strAppName);
    RegSetValueExA(hKey,"",NULL,REG_SZ,(BYTE*)strTemp,strlen(strTemp)+1);
    RegCloseKey(hKey);

    sprintf_s(strTemp,"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FileExts\\%s\\OpenWithList",strExt);
    RegCreateKeyA(HKEY_CURRENT_USER, strTemp, &hKey);
    RegSetValueExA(hKey, "MRUList", NULL, REG_SZ , (BYTE*)"", 0);
    RegCloseKey(hKey);

    if(sysVersion == SYS_VERSION_WIN_7)
    {
        sprintf_s(strTemp,"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FileExts\\%s\\UserChoice",strExt);
        RegCreateKeyA(HKEY_CURRENT_USER, strTemp, &hKey);
        RegSetValueExA(hKey, "Progid", NULL, REG_SZ , (BYTE*)(strProgid), strlen(strProgid)+1);

        char progidResult[_MAX_PATH];
        DWORD dwSize = sizeof(progidResult);

        RegQueryValueExA(hKey, "Progid", NULL, NULL, (LPBYTE)progidResult, &dwSize);

        if(_stricmp(progidResult,strProgid) != 0)
        {
            if(IsUserAdmin())
            {
                if(GaintKeyPrivilege(hKey))
                {
                    RegCloseKey(hKey);
                    RegCreateKeyA(HKEY_CURRENT_USER, strTemp, &hKey);
                    RegSetValueExA(hKey, "Progid", NULL, REG_SZ , (BYTE*)(strProgid), strlen(strProgid)+1);
                    RegCloseKey(hKey);
                    bSuccess = true;
                }
                else
                {   
                    //Unknow ERROR occured when gaint UserChoice key privilege!
                }
            }
            else
            {
                //Current user dosen't have admin privilege to edit special reg key value!
            }
        }
    }
    else if(sysVersion == SYS_VERSION_WIN_8 )
    {
        sprintf_s(strTemp,"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FileExts\\%s\\UserChoice",strExt);
        RegCreateKeyA(HKEY_CURRENT_USER, strTemp, &hKey);
        RegSetValueExA(hKey, "Progid", NULL, REG_SZ , (BYTE*)(strAppKey), strlen(strAppKey)+1);

        char progidResult[_MAX_PATH];
        DWORD dwSize = sizeof(progidResult);

        RegQueryValueExA(hKey, "Progid", NULL, NULL, (LPBYTE)progidResult, &dwSize);

        if(_stricmp(progidResult,strAppKey) != 0)
        {
            if(IsUserAdmin())
            {
                if(GaintKeyPrivilege(hKey))
                {
                    RegCloseKey(hKey);
                    RegCreateKeyA(HKEY_CURRENT_USER, strTemp, &hKey);
                    RegSetValueExA(hKey, "Progid", NULL, REG_SZ , (BYTE*)(strAppKey), strlen(strAppKey)+1);
                    RegCloseKey(hKey);

                    bSuccess = true;
                }
                else
                {   
                    //Unknow ERROR occured when gaint UserChoice key privilege!
                }
            }
            else
            {
                //Current user dosen't have admin privilege to edit special reg key value!
            }
        }

        RegCloseKey(hKey);
        RegCreateKeyA(HKEY_CURRENT_USER, strTemp, &hKey);
        RegSetValueExA(hKey, "Hash", NULL, REG_SZ , (BYTE*)(HASH), strlen(HASH)+1);
        RegCloseKey(hKey);
    }

    if(sysVersion == SYS_VERSION_WIN_XP)
    {
        sprintf_s(strTemp,"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FileExts\\%s",strExt);
        RegCreateKeyA(HKEY_CURRENT_USER, strTemp, &hKey);
        RegSetValueExA(hKey, "Application", NULL, REG_SZ , (BYTE*)(strAppFileName), strlen(strAppFileName)+1);
        RegCloseKey(hKey);

        bSuccess = true;
    }

    if(sysVersion == SYS_VERSION_WIN_XP || sysVersion == SYS_VERSION_WIN_8 )
    {
        sprintf_s(strTemp,"Applications\\%s\\shell\\open\\command",strAppFileName);
        RegCreateKeyA(HKEY_CLASSES_ROOT, strTemp, &hKey);
        sprintf_s(strTemp,"%s \"%%1\"",strAppName);
        RegSetValueExA(hKey,"",NULL,REG_SZ,(BYTE*)strTemp,strlen(strTemp)+1);
        RegCloseKey(hKey);
    }
    
    if(sysVersion == SYS_VERSION_OTHER)
    {
        //un support OS for register file relation!
    }

    ::SHChangeNotify(SHCNE_ASSOCCHANGED,SHCNF_IDLIST|SHCNF_FLUSH,0,0);

    return bSuccess;
}

BOOL IsUserAdmin(VOID)
{
    BOOL b;
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    PSID AdministratorsGroup; 
    b = AllocateAndInitializeSid(
        &NtAuthority,
        2,
        SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0,
        &AdministratorsGroup); 

    if(b) 
    {
        if (!CheckTokenMembership( NULL, AdministratorsGroup, &b)) 
        {
             b = FALSE;
        } 
        FreeSid(AdministratorsGroup); 
    }

    return(b);
}

int GetSystemVersion()
{
    SYSTEM_INFO info;                                   
    GetSystemInfo(&info);                              
    OSVERSIONINFOEX os; 
    os.dwOSVersionInfoSize=sizeof(OSVERSIONINFOEX);  
    if(GetVersionEx((OSVERSIONINFO *)&os))                 
    { 
        switch(os.dwMajorVersion)
        {                        
            //MajorVersion
            case 5: 
                switch(os.dwMinorVersion)
                {               
                    //MinorVersion
                case 1: 
                    return SYS_VERSION_WIN_XP;                    
                case 2: 
                    if(os.wProductType==VER_NT_WORKSTATION && 
                       info.wProcessorArchitecture==PROCESSOR_ARCHITECTURE_AMD64)
                        return SYS_VERSION_WIN_XP;
                } 
                break; 
            case 6: 
                switch(os.dwMinorVersion)
                { 
                case 1: 
                    if(os.wProductType==VER_NT_WORKSTATION) 
                        return SYS_VERSION_WIN_7;
                case 2:
                        return SYS_VERSION_WIN_8;
                } 
                break;
        } 
    } 

    return SYS_VERSION_OTHER;
}

BOOL GaintKeyPrivilege( HKEY & hKey )
{
    SID_IDENTIFIER_AUTHORITY SecIA = SECURITY_NT_AUTHORITY;
    PSID pSid = NULL;

    if (FALSE == ::AllocateAndInitializeSid(&SecIA, 1, 
        SECURITY_INTERACTIVE_RID, 0, 0, 0, 0, 0, 0, 0, &pSid))
    {
        return FALSE;
    }

    DWORD dwAclSize = sizeof(ACL) + sizeof(ACCESS_ALLOWED_ACE) + 
        ::GetLengthSid(pSid) - sizeof(DWORD);
    PACL pDacl = (PACL) new BYTE[dwAclSize];

    if (TRUE == ::InitializeAcl(pDacl, dwAclSize, ACL_REVISION))
    {
        if (TRUE == ::AddAccessAllowedAce(pDacl, ACL_REVISION, KEY_ALL_ACCESS, 
            pSid))
        {
            SECURITY_DESCRIPTOR SecDesc;
            if (TRUE == ::InitializeSecurityDescriptor(&SecDesc, 
                SECURITY_DESCRIPTOR_REVISION))
            {
                if (TRUE == ::SetSecurityDescriptorDacl(&SecDesc, TRUE, pDacl, FALSE))
                {
                    return (ERROR_SUCCESS == ::RegSetKeySecurity(hKey, 
                        (SECURITY_INFORMATION)DACL_SECURITY_INFORMATION, &SecDesc));
                }
            }
        }
    }

    return false;
}
