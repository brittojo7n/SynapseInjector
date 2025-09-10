#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include <stdexcept>

// A struct to hold process information
struct ProcessInfo {
    DWORD id;
    std::wstring name;
};

class Injector {
public:
    // Enables the SeDebugPrivilege required to interact with other processes.
    static bool EnableDebugPrivilege();

    // Gets the Process ID (PID) for a given process name.
    static DWORD GetProcessIdByName(const std::wstring& processName);

    // Retrieves a list of all running processes.
    static std::vector<ProcessInfo> GetAllProcesses();

    // The main injection function. Throws a runtime_error on failure.
    static void Inject(DWORD processId, const std::wstring& dllPath);
};