/* rndos2.c  -  OS/2 entropy gatherer
 * Copyright (C) 2012 KO Myung-Hun <komh@chollian.net>
 *
 * Libgcrypt is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * Libgcrypt is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include <config.h>

#define INCL_DOS
#define INCL_DOSERRORS
#include <os2.h>

#include <stdio.h>
#include <stdlib.h>

#include <sys/ioctl.h>
#include <net/if.h>

#include "types.h"
#include "g10lib.h"
#include "rand-internal.h"

#define ADD( buf, bufsize, origin, remain ) \
    do { \
        int n = ( bufsize ) < ( remain ) ? ( bufsize ) : ( remain ); \
        add( buf, n, origin ); \
        ( remain ) -= n; \
    } while( 0 )

#define BUF_SIZE_IFMIB              ( sizeof( struct ifmib ))
#define BUF_SIZE_REQUESTER          ( sizeof( unsigned long ) * 30 )
#define BUF_SIZE_SERVER             ( sizeof( unsigned long ) * 17 )
#define BUF_SIZE_CPUUTIL            ( sizeof( ULONG ) * 8 )
#define BUF_SIZE_SYS_STATE          ( 64 * 1024 )
#define BUF_SIZE_SYS_STATE_DELTA    4096
#define BUF_SIZE_SYS_STATE_MARGIN   1024

static HMODULE hmodTcpIp32;
static HMODULE hmodNetApi32;
static HMODULE hmodDosCalls;

static int _System ( *pfnsocket )( int, int, int );
static int _System ( *pfnos2_ioctl )( int, unsigned long, char *, int );
static int _System ( *pfnsoclose )( int );

static unsigned APIENTRY ( *pfnNet32StatisticsGet2 )(
                                const unsigned char *, const unsigned char *,
                                unsigned long, unsigned long, unsigned long,
                                unsigned char *, unsigned long,
                                unsigned long * );

static APIRET APIENTRY ( *pfnDosPerfSysCall )( ULONG, ULONG, ULONG, ULONG );
static APIRET APIENTRY ( *pfnDosQuerySysState )( ULONG, ULONG, PID, TID, PVOID,
                                                 ULONG );

int
_gcry_rndos2_gather_random( void ( *add )( const void *, size_t,
                                           enum random_origins ),
                            enum random_origins origin, size_t length,
                            int level )
{
    static BOOL    fInit = FALSE;
    static ULONG   ulCpuCount = 1;

    unsigned char *buf;
    ULONG          rc;

    if( !level )
        return 0;

    /* We never block, assume level 2. */

    if( !fInit )
    {
        CHAR szFail[ 260 ];

        if( !DosLoadModule( szFail, sizeof( szFail ), "tcpip32",
                            &hmodTcpIp32 ))
        {
            rc = DosQueryProcAddr( hmodTcpIp32, 16, NULL,
                                   ( PFN * )&pfnsocket );

            if( !rc )
                rc = DosQueryProcAddr( hmodTcpIp32, 17, NULL,
                                       ( PFN * )&pfnsoclose );

            if( !rc )
                rc = DosQueryProcAddr( hmodTcpIp32, 200, NULL,
                                       ( PFN * )&pfnos2_ioctl );

            if( rc )
            {
                DosFreeModule( hmodTcpIp32 );

                hmodTcpIp32 = NULLHANDLE;
            }
        }
        else
            hmodTcpIp32 = NULLHANDLE;

        if( !DosLoadModule( szFail, sizeof( szFail ), "netapi32",
                            &hmodNetApi32 ))
        {
            if( DosQueryProcAddr( hmodNetApi32, 125, NULL,
                                  ( PFN * )&pfnNet32StatisticsGet2 ))
            {
                DosFreeModule( hmodNetApi32 );

                hmodNetApi32 = NULLHANDLE;
            }
        }
        else
            hmodNetApi32 = NULLHANDLE;

        pfnDosPerfSysCall   = NULL;
        pfnDosQuerySysState = NULL;
        if( !DosLoadModule( szFail, sizeof( szFail ), "doscalls",
                            &hmodDosCalls ))
        {
            if( !DosQueryProcAddr( hmodDosCalls, 976, NULL,
                                   ( PFN * )&pfnDosPerfSysCall ))
                /* Query CPU count */
                pfnDosPerfSysCall( 0x41, 0, ( ULONG )&ulCpuCount, 0 );

            DosQueryProcAddr( hmodDosCalls, 368, NULL,
                              ( PFN * )&pfnDosQuerySysState );

            if( !pfnDosPerfSysCall && !pfnDosQuerySysState )
                DosFreeModule( hmodDosCalls );
        }

        fInit = TRUE;
    }

    while( length )
    {
        if( pfnDosPerfSysCall )
        {
            buf = gcry_xcalloc( ulCpuCount, BUF_SIZE_CPUUTIL );

            /* Query CPU utilization snapshot */
            if( !pfnDosPerfSysCall( 0x63, ( ULONG )buf, 0, 0 ))
                ADD( buf, BUF_SIZE_CPUUTIL * ulCpuCount, origin, length );

            gcry_free( buf );
        }

        if( hmodTcpIp32 )
        {
            int s;

            s = pfnsocket( PF_INET, SOCK_RAW, 0 );

            if( s != -1 )
            {
                buf = gcry_xmalloc( BUF_SIZE_IFMIB );

                if( !pfnos2_ioctl( s, SIOSTATIF, ( caddr_t )buf,
                                   BUF_SIZE_IFMIB ))
                    ADD( buf, BUF_SIZE_IFMIB, origin, length );

                gcry_free( buf );

                pfnsoclose( s );
            }
        }

        if( hmodNetApi32 )
        {
            ULONG ulAvail;

            buf = gcry_xmalloc( BUF_SIZE_REQUESTER );

            if( !pfnNet32StatisticsGet2( NULL, "REQUESTER", 0, 0, 1, buf,
                                         BUF_SIZE_REQUESTER, &ulAvail ))
                ADD( buf, BUF_SIZE_REQUESTER, origin, length );

            gcry_free( buf );

            buf = gcry_xmalloc( BUF_SIZE_SERVER );

            if( !pfnNet32StatisticsGet2( NULL, "SERVER", 0, 0, 1, buf,
                                         BUF_SIZE_SERVER, &ulAvail ))
                ADD( buf, BUF_SIZE_SERVER, origin, length );

            gcry_free( buf );
        }

        if( pfnDosQuerySysState )
        {
            size_t bufSize = BUF_SIZE_SYS_STATE;

            /* Allocate additional memory because DosQuerySysState()
               sometimes seems to overwrite to a memory boundary. */
            buf = gcry_xmalloc( bufSize + BUF_SIZE_SYS_STATE_MARGIN );

            do
            {
                /* Query all the system information supported by OS */
                rc = DosQuerySysState( QS_SUPPORTED, 0, 0, 0, ( PCHAR )buf,
                                       bufSize );
                if( rc == ERROR_BUFFER_OVERFLOW )
                {
                    bufSize += BUF_SIZE_SYS_STATE_DELTA;
                    gcry_free( buf );
                    buf = gcry_xmalloc( bufSize +
                                        BUF_SIZE_SYS_STATE_MARGIN );
                }
            } while( rc == ERROR_BUFFER_OVERFLOW );

            if( !rc )
                ADD( buf, bufSize, origin, length );

            gcry_free( buf );
        }

#define ADD_QSV( ord ) \
    do { \
        ULONG ulSV; \
        DosQuerySysInfo( ord, ord, &ulSV, sizeof( ulSV )); \
        ADD( &ulSV, sizeof( ulSV ), origin, length ); \
    } while( 0 )

        /* Fail safe */
        ADD_QSV( QSV_MS_COUNT );
        ADD_QSV( QSV_TIME_LOW );
        ADD_QSV( QSV_TIME_HIGH );
        ADD_QSV( QSV_TOTAVAILMEM );
        ADD_QSV( QSV_FOREGROUND_FS_SESSION );
        ADD_QSV( QSV_FOREGROUND_PROCESS );
    }

    return 0;
}
