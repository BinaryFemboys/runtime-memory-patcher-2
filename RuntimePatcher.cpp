#include <vector>
#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <cwchar>
#include <sstream>
#include <string>
#include <random>
#include <thread>
#include <stdio.h>
#include <intrin.h>
#include <format>
#include <thread> 
#include <chrono>

#define RESET   "\033[0m"
#define RED     "\033[31m"
#define GREEN   "\033[32m"
#define YELLOW  "\033[33m"
#define MAGENTA "\033[35m"

void EnableANSIColors() {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hConsole == INVALID_HANDLE_VALUE) return;

    DWORD mode = 0;
    GetConsoleMode(hConsole, &mode);
    SetConsoleMode(hConsole, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
}

struct PatchAddress {
    uintptr_t Address;
    unsigned char OldByte;
    unsigned char NewByte;
};

struct Patch {
    const char* ModuleName;
    std::vector<PatchAddress> Patches;
};

Patch example_exe = { "example.exe", {
PatchAddress{ 116211, 232, 144 },
PatchAddress{ 116212, 216, 144 },
PatchAddress{ 116213, 110, 144 },
PatchAddress{ 116214, 254, 144 },
PatchAddress{ 116215, 255, 144 },
PatchAddress{ 116216, 72, 144 },
PatchAddress{ 116217, 141, 144 },
PatchAddress{ 116218, 77, 144 },
PatchAddress{ 116219, 23, 144 },
PatchAddress{ 116220, 232, 144 },
PatchAddress{ 116221, 191, 144 },
PatchAddress{ 116222, 191, 144 },
PatchAddress{ 116223, 255, 144 },
PatchAddress{ 116224, 255, 144 },
PatchAddress{ 114643, 232, 144 },
PatchAddress{ 114644, 56, 144 },
PatchAddress{ 114645, 47, 144 },
PatchAddress{ 114646, 255, 144 },
PatchAddress{ 114647, 255, 144 },
PatchAddress{ 114648, 72, 144 },
PatchAddress{ 114649, 141, 144 },
PatchAddress{ 114650, 80, 144 },
PatchAddress{ 114651, 8, 144 },
PatchAddress{ 114652, 51, 144 },
PatchAddress{ 114653, 219, 144 },
PatchAddress{ 114654, 128, 144 },
PatchAddress{ 114655, 56, 144 },
PatchAddress{ 114656, 4, 144 },
PatchAddress{ 114657, 72, 144 },
PatchAddress{ 114658, 15, 144 },
PatchAddress{ 114659, 69, 144 },
PatchAddress{ 114660, 211, 144 },
PatchAddress{ 114661, 15, 144 },
PatchAddress{ 114662, 182, 144 },
PatchAddress{ 114663, 2, 144 },
PatchAddress{ 114664, 136, 144 },
PatchAddress{ 114665, 134, 144 },
PatchAddress{ 114666, 16, 144 },
PatchAddress{ 114667, 2, 144 },
PatchAddress{ 114668, 0, 144 },
PatchAddress{ 114669, 0, 144 },
PatchAddress{ 114670, 72, 144 },
PatchAddress{ 114671, 141, 144 },
PatchAddress{ 114672, 21, 144 },
PatchAddress{ 114673, 187, 144 },
PatchAddress{ 114674, 143, 144 },
PatchAddress{ 114675, 5, 144 },
PatchAddress{ 114676, 0, 144 },
PatchAddress{ 114677, 72, 144 },
PatchAddress{ 114678, 139, 144 },
PatchAddress{ 114679, 207, 144 },
PatchAddress{ 114680, 232, 144 },
PatchAddress{ 114681, 19, 144 },
PatchAddress{ 114682, 47, 144 },
PatchAddress{ 114683, 255, 144 },
PatchAddress{ 114684, 255, 144 },
PatchAddress{ 114685, 128, 144 },
PatchAddress{ 114686, 56, 144 },
PatchAddress{ 114687, 3, 144 },
PatchAddress{ 114688, 117, 144 },
PatchAddress{ 114689, 4, 144 },
PatchAddress{ 114690, 72, 144 },
PatchAddress{ 114691, 139, 144 },
PatchAddress{ 114692, 88, 144 },
PatchAddress{ 114693, 8, 144 },
PatchAddress{ 114694, 72, 144 },
PatchAddress{ 114695, 139, 144 },
PatchAddress{ 114696, 211, 144 },
PatchAddress{ 114697, 72, 144 },
PatchAddress{ 114698, 131, 144 },
PatchAddress{ 114699, 123, 144 },
PatchAddress{ 114700, 24, 144 },
PatchAddress{ 114701, 16, 144 },
PatchAddress{ 114702, 114, 144 },
PatchAddress{ 114703, 3, 144 },
PatchAddress{ 114704, 72, 144 },
PatchAddress{ 114705, 139, 144 },
PatchAddress{ 114706, 19, 144 },
PatchAddress{ 114707, 72, 144 },
PatchAddress{ 114708, 141, 144 },
PatchAddress{ 114709, 142, 144 },
PatchAddress{ 114710, 24, 144 },
PatchAddress{ 114711, 2, 144 },
PatchAddress{ 114712, 0, 144 },
PatchAddress{ 114713, 0, 144 },
PatchAddress{ 114714, 76, 144 },
PatchAddress{ 114715, 139, 144 },
PatchAddress{ 114716, 67, 144 },
PatchAddress{ 114717, 16, 144 },
PatchAddress{ 114718, 232, 144 },
PatchAddress{ 114719, 157, 144 },
PatchAddress{ 114720, 13, 144 },
PatchAddress{ 114721, 255, 144 },
PatchAddress{ 114722, 255, 144 },
PatchAddress{ 114724, 72, 144 },
PatchAddress{ 114725, 141, 144 },
PatchAddress{ 114726, 79, 144 },
PatchAddress{ 114727, 8, 144 },
PatchAddress{ 114728, 15, 144 },
PatchAddress{ 114729, 182, 144 },
PatchAddress{ 114730, 23, 144 },
PatchAddress{ 114731, 232, 144 },
PatchAddress{ 114732, 16, 144 },
PatchAddress{ 114733, 188, 144 },
PatchAddress{ 114734, 255, 144 },
PatchAddress{ 114735, 255, 144 },
PatchAddress{ 114736, 72, 144 },
PatchAddress{ 114737, 139, 144 },
PatchAddress{ 114738, 76, 144 },
PatchAddress{ 114739, 36, 144 },
PatchAddress{ 114740, 40, 144 },
PatchAddress{ 114741, 72, 144 },
PatchAddress{ 114742, 51, 144 },
PatchAddress{ 114743, 204, 144 },
PatchAddress{ 114744, 232, 144 },
PatchAddress{ 114745, 243, 144 },
PatchAddress{ 114746, 71, 144 },
PatchAddress{ 114747, 5, 144 },
PatchAddress{ 114748, 0, 144 },
} };





void centerText(const std::string& text, int consoleWidth, int r = 255, int g = 255, int b = 255)
{
    int padding = (consoleWidth - text.length()) / 2;
    std::cout << std::string(padding, ' ');
}

void title()
{
    std::wstring loadingText = L"";
    int animationSpeedMs = 325;
    int animationPhase = 0;

    while (true)
    {
        if (animationPhase == 0) {
            loadingText += L"The BinFbs"[loadingText.length()];
            std::wstring wLoadingText = loadingText;
            SetConsoleTitleW(wLoadingText.c_str());
            std::this_thread::sleep_for(std::chrono::milliseconds(animationSpeedMs));

            if (loadingText == L"The BinFbs")
            {
                animationPhase = 1;
            }
        }
        else if (animationPhase == 1)
        {
            loadingText = loadingText.substr(0, loadingText.length() - 1);
            std::wstring wLoadingText = loadingText;
            SetConsoleTitleW(wLoadingText.c_str());
            std::this_thread::sleep_for(std::chrono::milliseconds(animationSpeedMs));

            if (loadingText.empty()) {
                animationPhase = 0;
            }
        }
    }
}

void titleAnimation(const std::string& message, int animationDuration, int frameDuration, int r = 255, int g = 255, int b = 255)
{
    const std::string symbols = "-\\|/";
    int numFrames = animationDuration / frameDuration;
    int symbolIndex = 0;

    for (int frame = 0; frame < numFrames; ++frame) {
        CONSOLE_SCREEN_BUFFER_INFO csbi;
        GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &csbi);
        int consoleWidth = csbi.srWindow.Right - csbi.srWindow.Left + 1;

        centerText(symbols.substr(symbolIndex, 1) + " " + message + "   ", consoleWidth);
        symbolIndex = (symbolIndex + 1) % symbols.length();
        std::this_thread::sleep_for(std::chrono::milliseconds(frameDuration));
        std::cout << "\r";
    }
}

std::string int_to_string(int value) {
    std::stringstream ss;
    ss << value;
    return ss.str();
}

void SetConsoleColor(WORD color) {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, color);
}

// Function to log errors in red
void LogError(const std::string& message) {
    SetConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY);  // Red text
    std::cerr << "[error] --> ";
    SetConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);  // Reset to default
    std::cerr << message << std::endl;
}

// Function to log success in green
void LogSuccess(const std::string& message) {
    SetConsoleColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY);  // Green text
    std::cout << "[success] --> ";
    SetConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);  // Reset to default
    std::cout << message << std::endl;
}

bool enable_debug_privileges() {
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        std::cerr << "OpenProcessToken failed with error " << GetLastError() << std::endl;
        return false;
    }

    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
        std::cerr << "LookupPrivilegeValue failed with error " << GetLastError() << std::endl;
        CloseHandle(hToken);
        return false;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
        std::cerr << "AdjustTokenPrivileges failed with error " << GetLastError() << std::endl;
        CloseHandle(hToken);
        return false;
    }

    CloseHandle(hToken);

    if (GetLastError() != ERROR_SUCCESS) {
        std::cerr << "AdjustTokenPrivileges failed with error " << GetLastError() << std::endl;
        return false;
    }

    return true;
}

bool Tamper_Threads(DWORD processId, int value) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS | PROCESS_QUERY_INFORMATION | PROCESS_SET_INFORMATION | PROCESS_VM_READ, FALSE, processId);
    if (hProcess == NULL) {
        return false;
    }

    std::vector<HANDLE> threads;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        CloseHandle(hProcess);
        return false;
    }

    THREADENTRY32 te;
    te.dwSize = sizeof(te);
    if (Thread32First(hSnapshot, &te)) {
        do {
            if (te.th32OwnerProcessID == processId) {
                HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
                if (hThread) {
                    threads.push_back(hThread);
                }
            }
        } while (Thread32Next(hSnapshot, &te));
    }

    CloseHandle(hSnapshot);

    bool result = true;
    for (HANDLE hThread : threads) {
        if (value == 0) {  // Suspend
            if (SuspendThread(hThread) == (DWORD)-1) {
                result = false;
            }
            CloseHandle(hThread);
        }
        else {  // Resume
            ResumeThread(hThread);
            CloseHandle(hThread);
        }
    }

    CloseHandle(hProcess);
    return result;
}


uintptr_t get_module_base_address(DWORD processID, const wchar_t* moduleName) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processID);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        DWORD error = GetLastError();
        LogError("CreateToolhelp32Snapshot failed with error " + int_to_string(error) + " for process ID " + int_to_string(processID));
        return 0;
    }

    MODULEENTRY32 me = { sizeof(me) };
    if (Module32First(hSnapshot, &me)) {
        do {
            if (_wcsicmp(me.szModule, moduleName) == 0) {
                CloseHandle(hSnapshot);
                return reinterpret_cast<uintptr_t>(me.modBaseAddr);
            }
        } while (Module32Next(hSnapshot, &me));
    }
    else {
        DWORD error = GetLastError();
        LogError("Module32First failed with error " + int_to_string(error));
    }

    CloseHandle(hSnapshot);
    LogError("Module not found");
    return 0;
}

bool patch_process_memory(HANDLE hProcess, uintptr_t baseAddress) {
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);

    bool patchSuccess = true;

    for (const PatchAddress& addr : example_exe.Patches) {
        uintptr_t targetAddress = baseAddress + addr.Address;

        if (targetAddress == 0) {
            LogError("Invalid address");
            patchSuccess = false;
            continue;
        }

        uintptr_t pageStart = targetAddress & ~(sysInfo.dwPageSize - 1);
        size_t pageSize = sysInfo.dwPageSize;

        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQueryEx(hProcess, (LPCVOID)targetAddress, &mbi, sizeof(mbi)) == 0) {
            DWORD error = GetLastError();
            LogError("VirtualQueryEx failed with error " + int_to_string(error) + " for address 0x" + int_to_string(targetAddress));
            patchSuccess = false;
            continue;
        }

        if (!(mbi.Protect & PAGE_EXECUTE_READWRITE) && !(mbi.Protect & PAGE_READWRITE)) {
            DWORD oldProtect;
            if (!VirtualProtectEx(hProcess, (LPVOID)targetAddress, pageSize, PAGE_EXECUTE_READWRITE, &oldProtect)) {
                DWORD error = GetLastError();
                LogError("VirtualProtectEx failed with error " + int_to_string(error) + " for address 0x" + int_to_string(targetAddress));
                patchSuccess = false;
                continue;
            }
        }

        SIZE_T bytesWritten;
        if (!WriteProcessMemory(hProcess, (LPVOID)targetAddress, &addr.NewByte, 1, &bytesWritten)) {
            DWORD error = GetLastError();
            LogError("WriteProcessMemory failed for address 0x" + int_to_string(targetAddress) + " with error " + int_to_string(error));
            patchSuccess = false;
            continue;
        }
        else {
            LogSuccess("Patched address 0x" + int_to_string(targetAddress) + " with new byte 0x" + int_to_string(static_cast<int>(addr.NewByte)));
        }

        DWORD temp;
        if (!VirtualProtectEx(hProcess, (LPVOID)targetAddress, pageSize, mbi.Protect, &temp)) {
            DWORD error = GetLastError();
            LogError("VirtualProtectEx (restore) failed for address 0x" + int_to_string(targetAddress) + " with error " + int_to_string(error));
            patchSuccess = false;
        }
    }

    return patchSuccess;
}

void attach_to_process_and_patch(const wchar_t* processName) {
    DWORD processID = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        LogError("CreateToolhelp32Snapshot failed with error " + int_to_string(GetLastError()));
        return;
    }

    PROCESSENTRY32 pe = { sizeof(pe) };
    if (Process32First(hSnapshot, &pe)) {
        do {
            if (wcscmp(pe.szExeFile, processName) == 0) {
                processID = pe.th32ProcessID;
                break;
            }
        } while (Process32Next(hSnapshot, &pe));
    }

    CloseHandle(hSnapshot);

    if (processID == 0) {
        LogError("Target process not found");
        return;
    }

    // Suspend target process threads
    if (!Tamper_Threads(processID, 0)) {
        LogError("Failed to suspend threads for process ID " + int_to_string(processID));
        return;
    }

    LogSuccess("Suspended the target process");
    //Sleep(2000);

    uintptr_t baseAddress = get_module_base_address(processID, L"example.exe");
    if (baseAddress == 0) {
        LogError("Module base address not found");
        return;
    }

    HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION, FALSE, processID);
    if (!hProcess) {
        LogError("OpenProcess failed with error " + int_to_string(GetLastError()));
        return;
    }

    // Patch the process memory
    bool patchSuccess = patch_process_memory(hProcess, baseAddress);

    
    if (patchSuccess) {
        LogSuccess("Successfully patched the process");
        //Sleep(2000);
        if (!Tamper_Threads(processID, 1)) {
            LogError("Failed to resume threads for process ID " + int_to_string(processID));
        }
        else {
            LogSuccess("Resumed the target process threads");
        }
    }
    else {
        LogError("Patching failed, process remains suspended");
    }

    CloseHandle(hProcess);
}

int main() {

    std::thread titleThread(title);
    int msgBoxResult = MessageBoxA(
        NULL,                            
        "Made by The BinFbs",            
        "Info",                          
        MB_OK | MB_ICONINFORMATION       
    );

    
    if (msgBoxResult == IDOK) {
        if (!enable_debug_privileges()) {
            std::cerr << "Failed to enable debug privileges." << std::endl;
            return 1;
        }

        EnableANSIColors();
        std::cout << YELLOW
            << R"(
 ____  _                           ______ ____  
|  _ \(_)                         |  ____|  _ \ 
| |_) |_ _ __   __ _ _ __ _   _   | |__  | |_) |
|  _ <| | '_ \ / _` | '__| | | |  |  __| |  _ < 
| |_) | | | | | (_| | |  | |_| |  | |    | |_) |
|____/|_|_| |_|\__,_|_|   \__, |  |_|    |____/ 
                           __/ |                
                          |___/            
)"
<< RESET << std::endl;

        std::cout << MAGENTA << "[BinaryFemboy Central]" << RESET << GREEN << " [INFO] You like femboys don't you ;3" << std::endl;
        std::this_thread::sleep_for(std::chrono::seconds(1));
        std::cout << MAGENTA << "[BinaryFemboy Central]" << RESET << GREEN << " [INFO] Currently using Binary Femboys v1.2" << std::endl;
        std::cout << MAGENTA << "[BinaryFemboy Central]" << RESET << GREEN << " [INFO] Made with love (and several lost braincells) by @deltrix and @od8m" << std::endl;
        std::this_thread::sleep_for(std::chrono::seconds(3));

        attach_to_process_and_patch(L"example.exe");

        std::cout << "Press Enter to exit...";
        std::cin.get();  
    }

    return 0;
}
