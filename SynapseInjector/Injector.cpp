#include "Injector.h"
#include <tlhelp32.h>
#include <algorithm>
#include <memory>

std::wstring Injector::GetErrorMessage(DWORD errorCode) {
    LPWSTR messageBuffer = nullptr;
    size_t size = FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL, errorCode, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPWSTR)&messageBuffer, 0, NULL);
    std::wstring message(messageBuffer, size);
    LocalFree(messageBuffer);
    return message;
}

bool Injector::EnableDebugPrivilege() {
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        return false;
    }

    TOKEN_PRIVILEGES tp;
    LUID luid;
    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
        CloseHandle(hToken);
        return false;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
        CloseHandle(hToken);
        return false;
    }

    CloseHandle(hToken);
    return true;
}

DWORD Injector::GetProcessIdByName(const std::wstring& processName) {
    DWORD pid = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        return 0;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnap, &pe32)) {
        std::wstring procNameLower = processName;
        std::transform(procNameLower.begin(), procNameLower.end(), procNameLower.begin(), ::tolower);

        do {
            std::wstring currentProcName = pe32.szExeFile;
            std::transform(currentProcName.begin(), currentProcName.end(), currentProcName.begin(), ::tolower);
            if (currentProcName == procNameLower) {
                pid = pe32.th32ProcessID;
                break;
            }
        } while (Process32Next(hSnap, &pe32));
    }

    CloseHandle(hSnap);
    return pid;
}

std::vector<ProcessInfo> Injector::GetAllProcesses() {
    std::vector<ProcessInfo> processes;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        return processes;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnap, &pe32)) {
        do {
            processes.push_back({ pe32.th32ProcessID, pe32.szExeFile });
        } while (Process32Next(hSnap, &pe32));
    }

    CloseHandle(hSnap);
    return processes;
}

void Injector::Inject(DWORD processId, const std::wstring& dllPath) {
    if (GetFileAttributesW(dllPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
        throw std::runtime_error("DLL file not found.");
    }

    auto processDeleter = [](HANDLE h) { if (h) CloseHandle(h); };
    std::unique_ptr<void, decltype(processDeleter)> hProcess(OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId), processDeleter);

    if (!hProcess) {
        throw std::runtime_error("Failed to open target process. Error: " + std::string(GetErrorMessage(GetLastError()).begin(), GetErrorMessage(GetLastError()).end()));
    }

    size_t dllPathSize = (dllPath.length() + 1) * sizeof(wchar_t);

    auto virtualFreeDeleter = [&](LPVOID p) { if (p) VirtualFreeEx(hProcess.get(), p, 0, MEM_RELEASE); };
    std::unique_ptr<void, decltype(virtualFreeDeleter)> pAllocatedMem(VirtualAllocEx(hProcess.get(), NULL, dllPathSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE), virtualFreeDeleter);

    if (!pAllocatedMem) {
        throw std::runtime_error("Failed to allocate memory in target process. Error: " + std::string(GetErrorMessage(GetLastError()).begin(), GetErrorMessage(GetLastError()).end()));
    }

    if (!WriteProcessMemory(hProcess.get(), pAllocatedMem.get(), dllPath.c_str(), dllPathSize, NULL)) {
        throw std::runtime_error("Failed to write to process memory. Error: " + std::string(GetErrorMessage(GetLastError()).begin(), GetErrorMessage(GetLastError()).end()));
    }

    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    FARPROC pLoadLibrary = GetProcAddress(hKernel32, "LoadLibraryW");
    if (!pLoadLibrary) {
        throw std::runtime_error("Failed to get LoadLibraryW address.");
    }

    auto threadDeleter = [](HANDLE h) { if (h) CloseHandle(h); };
    std::unique_ptr<void, decltype(threadDeleter)> hRemoteThread(CreateRemoteThread(hProcess.get(), NULL, 0, (LPTHREAD_START_ROUTINE)pLoadLibrary, pAllocatedMem.get(), 0, NULL), threadDeleter);

    if (!hRemoteThread) {
        throw std::runtime_error("Failed to create remote thread. Error: " + std::string(GetErrorMessage(GetLastError()).begin(), GetErrorMessage(GetLastError()).end()));
    }

    WaitForSingleObject(hRemoteThread.get(), 5000);
}

void Injector::Eject(DWORD processId, const std::wstring& dllName) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processId);
    if (hSnap == INVALID_HANDLE_VALUE) {
        throw std::runtime_error("Failed to create module snapshot. Error: " + std::string(GetErrorMessage(GetLastError()).begin(), GetErrorMessage(GetLastError()).end()));
    }

    MODULEENTRY32 me32;
    me32.dwSize = sizeof(MODULEENTRY32);
    HMODULE hModule = NULL;

    if (Module32First(hSnap, &me32)) {
        std::wstring dllNameLower = dllName;
        std::transform(dllNameLower.begin(), dllNameLower.end(), dllNameLower.begin(), ::tolower);
        do {
            std::wstring currentModuleName = me32.szModule;
            std::transform(currentModuleName.begin(), currentModuleName.end(), currentModuleName.begin(), ::tolower);
            if (currentModuleName == dllNameLower) {
                hModule = me32.hModule;
                break;
            }
        } while (Module32Next(hSnap, &me32));
    }

    CloseHandle(hSnap);

    if (!hModule) {
        throw std::runtime_error("Module not found in the target process.");
    }

    auto processDeleter = [](HANDLE h) { if (h) CloseHandle(h); };
    std::unique_ptr<void, decltype(processDeleter)> hProcess(OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId), processDeleter);

    if (!hProcess) {
        throw std::runtime_error("Failed to open target process. Error: " + std::string(GetErrorMessage(GetLastError()).begin(), GetErrorMessage(GetLastError()).end()));
    }

    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    FARPROC pFreeLibrary = GetProcAddress(hKernel32, "FreeLibrary");

    if (!pFreeLibrary) {
        throw std::runtime_error("Failed to get FreeLibrary address.");
    }

    auto threadDeleter = [](HANDLE h) { if (h) CloseHandle(h); };
    std::unique_ptr<void, decltype(threadDeleter)> hRemoteThread(CreateRemoteThread(hProcess.get(), NULL, 0, (LPTHREAD_START_ROUTINE)pFreeLibrary, hModule, 0, NULL), threadDeleter);

    if (!hRemoteThread) {
        throw std::runtime_error("Failed to create remote thread for ejection. Error: " + std::string(GetErrorMessage(GetLastError()).begin(), GetErrorMessage(GetLastError()).end()));
    }

    WaitForSingleObject(hRemoteThread.get(), 5000);
}