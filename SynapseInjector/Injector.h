#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include <stdexcept>

struct ProcessInfo {
    DWORD id;
    std::wstring name;
};

class Injector {
public:
    static bool EnableDebugPrivilege();
    static DWORD GetProcessIdByName(const std::wstring& processName);
    static std::vector<ProcessInfo> GetAllProcesses();
    static void Inject(DWORD processId, const std::wstring& dllPath);
    static void Eject(DWORD processId, const std::wstring& dllName);
    static std::wstring GetErrorMessage(DWORD errorCode);
};