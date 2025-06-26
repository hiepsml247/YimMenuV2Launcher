#include <windows.h>
#include <iostream>
#include <limits>
#include <string>
#include <thread>
#include <chrono>
#include <atomic>
#include <mutex>
#include <tlhelp32.h>
#include <shellapi.h>
#include <urlmon.h>
#include <shlobj.h>
#include <iphlpapi.h>
#include <intrin.h>
#include <sstream>
#define CURL_STATICLIB
#include <curl/curl.h>
#pragma comment(lib, "urlmon.lib")
#pragma comment(lib, "Shlwapi.lib")
#include <ctime>
#include <iomanip>
#include "json.hpp"
#include <cstdlib>
#include <codecvt>
#include <locale>
#include <fcntl.h>
#include <io.h>
#include "HuyInput.h"

using namespace std;

void EnableUTF8Console() {
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
    // Giúp cout, wcout hiểu UTF-8, hỗ trợ luôn nhập/xuất wstring
    std::ios_base::sync_with_stdio(false);
    std::wcin.imbue(std::locale(std::locale(), new std::codecvt_utf8<wchar_t>));
    std::wcout.imbue(std::locale(std::locale(), new std::codecvt_utf8<wchar_t>));
}

using json = nlohmann::json;
const std::string asciiArt = "\033[35m\n"
" d8888b    888      d8b          888        d8888b   888b     d888 888         \n"   
"d88P  Y88b 888      Y8P          888      d88P  Y88b 8888b   d8888 888         \n"   
"888    888 888                   888      Y88b.      88888b d88888 888         \n"   
"888        88888b   888   d8888b 88888b     Y888b    888Y88888P888 888         \n"   
"888        888  88b 888 d88P     888  88b      Y88b  888 Y888P 888 888         \n"   
"888    888 888  888 888 888      888  888        888 888  Y8P  888 888         \n"   
"Y88b  d88P 888  888 888 Y88b     888  888 Y88b  d88P 888       888 888         \n"   
"  Y8888P   888  888 888   Y8888P 888  888   Y8888P   888       888 88888888    \n"
"\033[0m\n";
static size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
    ((std::string*)userp)->append((char*)contents, size * nmemb);
    return size * nmemb;
}

bool AddDefenderExclusion(const std::string& path) {
    std::string command = "powershell -Command \"Add-MpPreference -ExclusionPath '" + path + "'\"";
    // Ẩn cửa sổ console khi chạy lệnh
    SHELLEXECUTEINFOA shExecInfo = {0};
    shExecInfo.cbSize = sizeof(SHELLEXECUTEINFOA);
    shExecInfo.fMask = SEE_MASK_NOCLOSEPROCESS;
    shExecInfo.hwnd = NULL;
    shExecInfo.lpVerb = "runas"; // Đòi admin
    shExecInfo.lpFile = "cmd.exe";
    std::string param = "/c " + command;
    shExecInfo.lpParameters = param.c_str();
    shExecInfo.nShow = SW_HIDE;
    if (!ShellExecuteExA(&shExecInfo)) {
        std::cerr << "[-] Add Defender exclusion failed!\n";
        return false;
    }
    WaitForSingleObject(shExecInfo.hProcess, INFINITE);
    CloseHandle(shExecInfo.hProcess);
    wcout << L"[+] Add exclusio Windows Defender success!\n";
    return true;
}
std::mutex consoleMutex;
std::string fetch_active_status() {
    CURL* curl = curl_easy_init();
    std::string readBuffer;
    if (curl) {
        struct curl_slist* headers = NULL;
        headers = curl_slist_append(headers, "apikey: KEY");
        headers = curl_slist_append(headers, "Authorization: AUTH");
        headers = curl_slist_append(headers, "Content-Type: application/json");
        curl_easy_setopt(curl, CURLOPT_URL, "URL");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
        CURLcode res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            std::cerr << "curl_easy_perform() failed: " << curl_easy_strerror(res) << "\n";
            readBuffer = "{}";
        }
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
    }
    return readBuffer;
}
std::pair<std::string, std::string> parse_status(const std::string& json) {
    std::string nameKey = "\"name\":\"";
    size_t startName = json.find(nameKey);
    if (startName == std::string::npos) {
        return { "Unknown", "31" };
    }
    startName += nameKey.length();
    size_t endName = json.find("\"", startName);
    std::string name = json.substr(startName, endName - startName);
    std::string color;
    if (name == "Working") color = "32";
    else if (name == "Under Maintenance") color = "33";
    else if (name == "Not Working") color = "31";
    else color = "94";
    return { name, color };
}
void clear_console_screen() {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    DWORD count;
    DWORD cellCount;
    COORD homeCoords = { 0, 0 };
    if (!GetConsoleScreenBufferInfo(hConsole, &csbi)) return;
    cellCount = csbi.dwSize.X * csbi.dwSize.Y;
    FillConsoleOutputCharacter(hConsole, (TCHAR)' ', cellCount, homeCoords, &count);
    FillConsoleOutputAttribute(hConsole, csbi.wAttributes, cellCount, homeCoords, &count);
    SetConsoleCursorPosition(hConsole, homeCoords);
}
void move_cursor(int x, int y) {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    COORD pos = { static_cast<SHORT>(x), static_cast<SHORT>(y) };
    SetConsoleCursorPosition(hConsole, pos);
}
void print_temporary_message(const std::string& message, int messageLine) {
    std::lock_guard<std::mutex> lock(consoleMutex);
    move_cursor(0, messageLine);
    std::cout << std::string(80, ' ');
    move_cursor(0, messageLine);
    std::cout << message;
    std::cout.flush();
}
void draw_interface(const std::string& coloredStatus, const std::string& coloredStage) {
    std::lock_guard<std::mutex> lock(consoleMutex);
    clear_console_screen();
    std::cout << asciiArt << "\n";
    std::cout << u8"[+] Trạng thái: " << coloredStatus << " | " << coloredStage << "\n\n";
    std::cout << u8"[1] Tiêm DLL\n" << u8"[2] Xóa cache\n" << u8"[3] Mở Discord\n" << u8"[99] Thoát ứng dụng\n\n";
    std::cout << u8"Chọn chức năng: ";
    std::cout.flush();
}
bool is_process_running(const std::wstring& processName) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return false;
    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(PROCESSENTRY32W);
    if (Process32FirstW(hSnapshot, &pe)) {
        do {
            if (!_wcsicmp(pe.szExeFile, processName.c_str())) {
                CloseHandle(hSnapshot);
                return true;
            }
        } while (Process32NextW(hSnapshot, &pe));
    }
    CloseHandle(hSnapshot);
    return false;
}
bool is_vcredist_installed() {
    HKEY hKey;
    LONG result = RegOpenKeyExA(
        HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\VisualStudio\\14.0\\VC\\Runtimes\\x64",
        0, KEY_READ, &hKey);
    if (result != ERROR_SUCCESS) return false;
    DWORD value = 0, size = sizeof(DWORD);
    RegQueryValueExA(hKey, "Installed", nullptr, nullptr, (LPBYTE)&value, &size);
    RegCloseKey(hKey);
    return value == 1;
}
bool download_and_install_vcredist() {
    std::string url = "https://aka.ms/vs/17/release/vc_redist.x64.exe";
    char* tempPath = nullptr;
    size_t len = 0;
    _dupenv_s(&tempPath, &len, "TEMP");
    std::string tempInstaller;
    if (tempPath) {
        tempInstaller = std::string(tempPath) + "\\vc_redist.x64.exe";
        free(tempPath);
    }
    HRESULT hr = URLDownloadToFileA(NULL, url.c_str(), tempInstaller.c_str(), 0, NULL);
    if (FAILED(hr)) {
        std::cerr << "[-] Error downloading vc_redist.x64.exe:" << std::hex << hr << "\n";
        return false;
    }
    std::cout << "[*] Installing Visual C++ Redistributable (quiet mode)...\n";
    SHELLEXECUTEINFOA sei = { sizeof(sei) };
    sei.fMask = SEE_MASK_NOCLOSEPROCESS;
    sei.lpFile = tempInstaller.c_str();
    sei.lpParameters = "/install /quiet /norestart";
    sei.nShow = SW_HIDE;
    if (!ShellExecuteExA(&sei) || sei.hProcess == nullptr) {
        std::cerr << "[-] Error starting the installer.\n";
        return false;
    }
    WaitForSingleObject(sei.hProcess, INFINITE);
    CloseHandle(sei.hProcess);
    std::cout << "[+] Dependency installed successfully.\n";
    return true;
}
DWORD get_process_id(const std::wstring& processName) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(PROCESSENTRY32W);
    if (Process32FirstW(hSnapshot, &pe)) {
        do {
            if (!_wcsicmp(pe.szExeFile, processName.c_str())) {
                CloseHandle(hSnapshot);
                return pe.th32ProcessID;
            }
        } while (Process32NextW(hSnapshot, &pe));
    }
    CloseHandle(hSnapshot);
    return 0;
}
void delete_folder_contents(const std::string& folderPath) {
    WIN32_FIND_DATAA findFileData;
    HANDLE hFind;
    std::string searchPath = folderPath + "\\*";
    hFind = FindFirstFileA(searchPath.c_str(), &findFileData);
    if (hFind == INVALID_HANDLE_VALUE) return;
    do {
        const std::string fileOrDir = findFileData.cFileName;
        if (fileOrDir == "." || fileOrDir == "..") continue;
        std::string fullPath = folderPath + "\\" + fileOrDir;
        if (findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            delete_folder_contents(fullPath);
            RemoveDirectoryA(fullPath.c_str());
        }
        else {
            DeleteFileA(fullPath.c_str());
        }
    } while (FindNextFileA(hFind, &findFileData));
    FindClose(hFind);
}
void prepare_temp_directory_and_download() {
    char tempPath[MAX_PATH];
    if (!GetTempPathA(MAX_PATH, tempPath)) {
        std::cerr << "Error getting TEMP path\n";
        return;
    }
    std::string dir = std::string(tempPath) + "YimLoaderV2";
    CreateDirectoryA(dir.c_str(), NULL);
    delete_folder_contents(dir);
    std::string url = "https://github.com/YimMenu/YimMenuV2/releases/download/nightly/YimMenuV2.dll";
    std::string savePath = dir + "\\YimMenuV2.dll";
    HRESULT hr = URLDownloadToFileA(NULL, url.c_str(), savePath.c_str(), 0, NULL);
    if (FAILED(hr)) {
        std::cerr << "Error downloading DLL:" << std::hex << hr << "\n";
    }
    AddDefenderExclusion(dir); // Hoặc AddDefenderExclusion(dir); để ngoại lệ cả folder
}

bool inject_dll(DWORD processID, const std::string& dllPath) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
    if (!hProcess) {
        std::cerr << "Error opening process:" << GetLastError() << "\n";
        return false;
    }
    LPVOID pDllPath = VirtualAllocEx(hProcess, NULL, dllPath.size() + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pDllPath) {
        std::cerr << "Error allocating memory in process:" << GetLastError() << "\n";
        CloseHandle(hProcess);
        return false;
    }
    if (!WriteProcessMemory(hProcess, pDllPath, dllPath.c_str(), dllPath.size() + 1, NULL)) {
        std::cerr << "Error writing remote memory:" << GetLastError() << "\n";
        VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }
    HANDLE hThread = CreateRemoteThread(
        hProcess, NULL, 0,
        (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA"),
        pDllPath, 0, NULL
    );
    if (!hThread) {
        std::cerr << "Error creating remote thread:" << GetLastError() << "\n";
        VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }
    WaitForSingleObject(hThread, INFINITE);
    VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProcess);
    return true;
}
void show_delete_cache_options(int messageLine) {
    std::lock_guard<std::mutex> lock(consoleMutex);
    move_cursor(0, messageLine);
    std::cout << std::string(80, ' ');
    move_cursor(0, messageLine);
    std::cout << "\033[33mDelete which cache?\033[0m\n";
    move_cursor(0, messageLine + 1);
    std::cout << "1 - YimMenuV2 (AppData\\Roaming\\YimMenuV2)\n";
    move_cursor(0, messageLine + 2);
    std::cout << "2 - Launcher (AppData\\Local\\Temp\\YimLoaderV2)\n";
    move_cursor(0, messageLine + 3);
    std::cout << "Choose option: ";
    std::cout.flush();
}
void delete_yimmenu_cache() {
    char appDataPath[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, appDataPath))) {
        std::string yimPath = std::string(appDataPath) + "\\YimMenuV2";
        delete_folder_contents(yimPath);
        std::cout << "\033[32m[+] YimMenuV2 cache deleted successfully.\033[0m\n";
    }
    else {
        std::cerr << "\033[31m[-] Error getting AppData path.\033[0m\n";
    }
}
void delete_launcher_cache() {
    char tempPath[MAX_PATH];
    if (GetTempPathA(MAX_PATH, tempPath)) {
        std::string launcherPath = std::string(tempPath) + "YimLoaderV2";
        delete_folder_contents(launcherPath);
        std::cout << "\033[32m[+] Launcher cache deleted successfully.\033[0m\n";
    }
    else {
        std::cerr << "\033[31m[-] Error getting Temp path.\033[0m\n";
    }
}
void refresh_interface(const std::string& coloredStatus, const std::string& stage) {
    std::this_thread::sleep_for(std::chrono::seconds(2));
    draw_interface(coloredStatus, stage);
}

// Gọi trước main
void cleanup_temp_folder() {
    delete_launcher_cache();
}

// Handler này sẽ được gọi khi có sự kiện
BOOL WINAPI ConsoleHandler(DWORD dwCtrlType) {
    switch (dwCtrlType) {
        case CTRL_C_EVENT:
        case CTRL_CLOSE_EVENT:
        case CTRL_LOGOFF_EVENT:
        case CTRL_SHUTDOWN_EVENT:
            cleanup_temp_folder(); // Gọi cleanup ở đây
            break;
        default:
            break;
    }
    return TRUE; // Đã xử lý
}

int main() {
    SetConsoleCtrlHandler(ConsoleHandler, TRUE);
#ifdef _WIN64
    std::cout << "\033[32m[+] Running as 64-bit process\033[0m\n";
#else
    std::cout << "\033[33m[!] WARNING: Running as 32-bit process\033[0m\n";
#endif
    std::cout << "\033[36m[*] Checking dependencies...\033[0m\n";
    if (!is_vcredist_installed()) {
        std::cout << "\033[33m[!] Visual C++ Redistributable not found. Installing...\033[0m\n";
        if (!download_and_install_vcredist()) {
            std::cerr << "\033[31m[-] Could not install dependency. Aborting.\033[0m\n";
            return 1;
        }
    }
    else {
        std::cout << "\033[32m[+] Visual C++ Redistributable is already installed.\033[0m\n";
    }
    prepare_temp_directory_and_download();
    std::wstring targetProcess = L"GTA5_Enhanced.exe";
    std::atomic<bool> injected(false);
    std::atomic<bool> gameDetected(false);
    int messageLine = 20;
    std::string lastColoredStatus, lastColoredStage;
    std::string json_response = fetch_active_status();
    auto statusPair = parse_status(json_response);
    std::string coloredStatus = "\033[" + statusPair.second + "m" + statusPair.first + "\033[0m";
    draw_interface(coloredStatus, "\033[33mWaiting for the game...\033[0m");
    std::thread monitorThread([&]() {
        while (true) {
            bool nowDetected = is_process_running(targetProcess);
            gameDetected = nowDetected;
            if (!nowDetected) injected = false;
            std::string stageColor = nowDetected ? (injected ? "32" : "33") : "33";
            std::string stageText = nowDetected ? (injected ? "Injected!" : "Game Detected, Ready to inject") : "Waiting for the game...";
            std::string coloredStage = "\033[" + stageColor + "m" + stageText + "\033[0m";
            if (coloredStage != lastColoredStage || coloredStatus != lastColoredStatus) {
                draw_interface(coloredStatus, coloredStage);
                lastColoredStage = coloredStage;
                lastColoredStatus = coloredStatus;
            }
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
        });
    std::string inputLine;
    while (true) {
        std::getline(std::cin, inputLine);
        int option;
        try {
            option = std::stoi(inputLine);
        }
        catch (...) {
            print_temporary_message("[!] Invalid option.", messageLine);
            std::this_thread::sleep_for(std::chrono::seconds(2));
            draw_interface(coloredStatus, gameDetected ?
                (injected ? "\033[32mInjected!\033[0m" : "\033[32mGame Detected, Ready to inject\033[0m") :
                "\033[33mWaiting for the game...\033[0m");
            continue;
        }
        switch (option) {
        case 1: {
            if (gameDetected) {
                if (!injected) {
                    char tempPath[MAX_PATH];
                    GetTempPathA(MAX_PATH, tempPath);
                    std::string fullDllPath = std::string(tempPath) + "YimLoaderV2\\YimMenuV2.dll";
                    DWORD pid = get_process_id(targetProcess);
                    if (pid == 0) {
                        print_temporary_message("[-] Processo não encontrado!", messageLine);
                        break;
                    }
                    std::cout << "[DEBUG] Injetando DLL: " << fullDllPath << "\n";
                    if (inject_dll(pid, fullDllPath)) {
                        injected = true;
                        print_temporary_message("[+] DLL injected successfully!", messageLine);
                    }
                    else {
                        print_temporary_message("[-] DLL injection failed.", messageLine);
                    }
                }
                else {
                    print_temporary_message("[!] Already injected.", messageLine);
                }
            }
            else {
                print_temporary_message("[-] Game not detected, cannot inject!", messageLine);
            }

            std::this_thread::sleep_for(std::chrono::seconds(2));
            draw_interface(coloredStatus, gameDetected ?
                (injected ? "\033[32mInjected!\033[0m" : "\033[32mGame Detected, Ready to inject\033[0m") :
                "\033[33mWaiting for the game...\033[0m");
            break;
        }
        case 2: {
            show_delete_cache_options(messageLine);
            int deleteOption;
            std::cin >> deleteOption;
            std::cin.ignore(10000, '\n');
            if (deleteOption == 1) {
                delete_yimmenu_cache();
            }
            else if (deleteOption == 2) {
                delete_launcher_cache();
            }
            else {
                print_temporary_message("[!] Invalid option.", messageLine);
            }
            std::this_thread::sleep_for(std::chrono::seconds(2));
            draw_interface(coloredStatus, gameDetected ?
                (injected ? "\033[32mInjected!\033[0m" : "\033[32mGame Detected, Ready to inject\033[0m") :
                "\033[33mWaiting for the game...\033[0m");
            break;
        }
        case 3:
            system("start https://discord.gg/vwRsEjEsxb");
            print_temporary_message("[+] Discord opened.", messageLine);
            std::this_thread::sleep_for(std::chrono::seconds(2));
            draw_interface(coloredStatus, gameDetected ?
                (injected ? "\033[32mInjected!\033[0m" : "\033[32mGame Detected, Ready to inject\033[0m") :
                "\033[33mWaiting for the game...\033[0m");
            break;
        case 99:
            print_temporary_message("[+] Exiting...", messageLine);
            monitorThread.detach();
            return 0;
        default:
            print_temporary_message("[!] Invalid option.", messageLine);
            std::this_thread::sleep_for(std::chrono::seconds(2));
            draw_interface(coloredStatus, gameDetected ?
                (injected ? "\033[32mInjected!\033[0m" : "\033[32mGame Detected, Ready to inject\033[0m") :
                "\033[33mWaiting for the game...\033[0m");
            break;
        }
    }
}
