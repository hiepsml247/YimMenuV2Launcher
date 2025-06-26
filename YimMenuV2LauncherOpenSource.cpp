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

bool AddDefenderExclusion(const std::wstring& path) {
    std::wstring command = L"powershell -Command \"Add-MpPreference -ExclusionPath '" + path + L"'\"";
    SHELLEXECUTEINFOW shExecInfo = { 0 };
    shExecInfo.cbSize = sizeof(SHELLEXECUTEINFOW);
    shExecInfo.fMask = SEE_MASK_NOCLOSEPROCESS;
    shExecInfo.hwnd = NULL;
    shExecInfo.lpVerb = L"runas";
    shExecInfo.lpFile = L"cmd.exe";
    std::wstring param = L"/c " + command;
    shExecInfo.lpParameters = param.c_str();
    shExecInfo.nShow = SW_HIDE;
    if (!ShellExecuteExW(&shExecInfo)) {
        std::wcerr << L"[-] Thêm ngoại lệ thất bại!\n";
        return false;
    }
    WaitForSingleObject(shExecInfo.hProcess, INFINITE);
    CloseHandle(shExecInfo.hProcess);
    std::wcout << L"[+] Đã thêm vào danh sách ngoại lệ của Windows Defender!\n";
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
void print_temporary_message(const std::wstring& message, int messageLine) {
    std::lock_guard<std::mutex> lock(consoleMutex);
    move_cursor(0, messageLine);
    std::wcout << std::wstring(80, L' ');
    move_cursor(0, messageLine);
    std::wcout << message;
    std::wcout.flush();
}
void draw_interface(const std::wstring& coloredStatus, const std::wstring& coloredStage) {
    std::lock_guard<std::mutex> lock(consoleMutex);
    clear_console_screen();
    std::wcout << asciiArt << L"\n";
    std::wcout << L"[+] Trạng thái: " << coloredStatus << L" | " << coloredStage << L"\n\n";
    std::wcout << L"[1] Tiêm DLL\n" << L"[2] Xóa cache\n" << L"[3] Mở Discord\n" << L"[99] Thoát ứng dụng\n\n";
    std::wcout << L"Chọn chức năng: ";
    std::wcout.flush();
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
     _setmode(_fileno(stdout), _O_U16TEXT);
     _setmode(_fileno(stdin), _O_U16TEXT);
     SetConsoleCtrlHandler(ConsoleHandler, TRUE);
#ifdef _WIN64
    std::wcout << L"\033[32m[+] Đang chạy tiến trình 64-bit\033[0m\n";
#else
    std::wcout << L"\033[33m[!] Cảnh báo: Đang chạy tiến trình 32-bit\033[0m\n";
#endif
    std::wcout << L"\033[36m[*] Kiểm tra thư viện phụ thuộc...\033[0m\n";
    if (!is_vcredist_installed()) {
        std::wcout << L"\033[33m[!] Chưa có Visual C++ Redistributable. Đang cài đặt...\033[0m\n";
        if (!download_and_install_vcredist()) {
            std::wcerr << L"\033[31m[-] Không cài được thư viện. Thoát.\033[0m\n";
            return 1;
        }
    }
    else {
        std::wcout << L"\033[32m[+] Đã có Visual C++ Redistributable.\033[0m\n";
    }
    prepare_temp_directory_and_download();
    std::wstring targetProcess = L"GTA5_Enhanced.exe";
    std::atomic<bool> injected(false);
    std::atomic<bool> gameDetected(false);
    int messageLine = 20;
    std::string lastColoredStatus, lastColoredStage;
    std::string json_response = fetch_active_status();
    auto statusPair = parse_status(json_response);
    std::wstring coloredStatus = L"\033[31mKhông xác định\033[0m";
    draw_interface(coloredStatus, L"\033[33mĐang chờ game...\033[0m");
    std::thread monitorThread([&]() {
        while (true) {
            bool nowDetected = is_process_running(targetProcess);
            gameDetected = nowDetected;
            if (!nowDetected) injected = false;
            std::wstring stageColor = nowDetected ? (injected ? L"32" : L"33") : L"33";
            std::wstring stageText = nowDetected ? (injected ? L"Đã inject!" : L"Đã nhận diện game, sẵn sàng inject") : L"Đang chờ game...";
            std::wstring coloredStage = L"\033[" + stageColor + L"m" + stageText + L"\033[0m";
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
            print_temporary_message(L"[!] Tuỳ chọn không hợp lệ.", messageLine);
            std::this_thread::sleep_for(std::chrono::seconds(2));
            draw_interface(coloredStatus, gameDetected ?
                (injected ? L"\033[32mĐã inject!\033[0m" : L"\033[32mĐã nhận diện game, sẵn sàng inject\033[0m") :
                L"\033[33mĐang chờ game...\033[0m");
            continue;
        }
        switch (option) {
        case 1: {
            if (gameDetected) {
                if (!injected) {
                    wchar_t tempPath[MAX_PATH];
                    GetTempPathW(MAX_PATH, tempPath);
                    std::wstring fullDllPath = std::wstring(tempPath) + L"YimLoaderV2\\YimMenuV2.dll";
                    DWORD pid = get_process_id(targetProcess);
                    if (pid == 0) {
                        print_temporary_message(L"[-] Không tìm thấy tiến trình!", messageLine);
                        break;
                    }
                    std::wcout << L"[DEBUG] Đang inject DLL: " << fullDllPath << L"\n";
                    if (inject_dll(pid, std::string(fullDllPath.begin(), fullDllPath.end()))) {
                        injected = true;
                        print_temporary_message(L"[+] Đã inject DLL thành công!", messageLine);
                    } else {
                        print_temporary_message(L"[-] Inject DLL thất bại.", messageLine);
                    }
                }
                else {
                    print_temporary_message(L"[!] Đã inject rồi.", messageLine);
                }
            } else {
                print_temporary_message(L"[-] Chưa mở game!", messageLine);
            }
            std::this_thread::sleep_for(std::chrono::seconds(2));
            draw_interface(coloredStatus, gameDetected ?
                (injected ? L"\033[32mĐã inject!\033[0m" : L"\033[32mĐã nhận diện game, sẵn sàng inject\033[0m") :
                L"\033[33mĐang chờ game...\033[0m");
            break;
        }
        case 2: {
            show_delete_cache_options(messageLine);
            int deleteOption;
            std::wcin >> deleteOption;
            std::wcin.ignore(10000, L'\n');
            if (deleteOption == 1) {
                delete_yimmenu_cache();
            }
            else if (deleteOption == 2) {
                delete_launcher_cache();
            }
            else {
                print_temporary_message(L"[!] Tuỳ chọn không hợp lệ.", messageLine);
            }
            std::this_thread::sleep_for(std::chrono::seconds(2));
            draw_interface(coloredStatus, ...);
            break;
        }
        case 3:
            system("start https://discord.gg/vwRsEjEsxb");
            print_temporary_message("[+] Discord opened.", messageLine);
            std::this_thread::sleep_for(std::chrono::seconds(2));
            draw_interface(coloredStatus, gameDetected ?
                (injected ? L"\033[32mĐã inject!\033[0m" : L"\033[32mĐã nhận diện game, sẵn sàng inject\033[0m") :
                L"\033[33mĐang chờ game...\033[0m");
            break;
        case 99:
            print_temporary_message(L"[+] Thoát...", messageLine);
            monitorThread.detach();
            return 0;
        default:
            print_temporary_message(L"[!] Tuỳ chọn không hợp lệ.", messageLine);
            std::this_thread::sleep_for(std::chrono::seconds(2));
            draw_interface(coloredStatus, gameDetected ?
                (injected ? L"\033[32mĐã inject!\033[0m" : L"\033[32mĐã nhận diện game, sẵn sàng inject\033[0m") :
                L"\033[33mĐang chờ game...\033[0m");
            break;
        }
    }
}
