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


std::mutex consoleMutex;
std::string fetch_active_status() {
    CURL* curl = curl_easy_init();
    std::string readBuffer;
    if (curl) {
        struct curl_slist* headers = NULL;
        headers = curl_slist_append(headers, "apikey: KEY");
        headers = curl_slist_append(headers, "Authorization: AUTH");
        headers = curl_slist_append(headers, "Content-Type: application/json");
        curl_easy_setopt(curl, CURLOPT_URL, "http://basic3.asaka.asia:27053/status");
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
    if (name == "Working" || name == u8"Hoạt động") color = "32";
    else if (name == "Under Maintenance" || name == u8"Bảo trì") color = "33";
    else if (name == "Not Working" || name == u8"Không hoạt động") color = "31";
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
    std::cout << u8"[1] Tiêm DLL\n" << u8"[3] Mở Discord\n" << u8"[99] Thoát ứng dụng\n\n";
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
        std::cerr << u8"[-] Lỗi khởi động trình cài đặt.\n";
        return false;
    }
    WaitForSingleObject(sei.hProcess, INFINITE);
    CloseHandle(sei.hProcess);
    std::cout << u8"[+] Đã cài đặt phụ thuộc thành công.\n";
    return true;
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
        std::cerr << u8"[-] Thêm danh sách ngoại lệ của Windows Defender thất bại!\n";
        return false;
    }
    WaitForSingleObject(shExecInfo.hProcess, INFINITE);
    CloseHandle(shExecInfo.hProcess);
    std::cout << u8"[+] Đã thêm vào danh sách ngoại lệ của Windows Defender!\n";
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
        std::cerr << u8"Lỗi khi nhận đường dẫn TEMP\n";
        return;
    }
    std::string dir = std::string(tempPath) + "ChichSML";
    CreateDirectoryA(dir.c_str(), NULL);
    delete_folder_contents(dir);
    std::string url = "https://github.com/hiepsml247/chichsml/releases/download/hoho/ChichSML.dll";
    std::string savePath = dir + "\\ChichSML.dll";
    HRESULT hr = URLDownloadToFileA(NULL, url.c_str(), savePath.c_str(), 0, NULL);
    if (FAILED(hr)) {
        std::cerr << u8"Lỗi tải xuống DLL:" << std::hex << hr << "\n";
    }
    AddDefenderExclusion(dir); //để ngoại lệ cả folder
}

bool inject_dll(DWORD processID, const std::string& dllPath) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
    if (!hProcess) {
        std::cerr << u8"Lỗi quá trình mở:" << GetLastError() << "\n";
        return false;
    }
    LPVOID pDllPath = VirtualAllocEx(hProcess, NULL, dllPath.size() + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pDllPath) {
        std::cerr << u8"Lỗi phân bổ bộ nhớ trong tiến trình:" << GetLastError() << "\n";
        CloseHandle(hProcess);
        return false;
    }
    if (!WriteProcessMemory(hProcess, pDllPath, dllPath.c_str(), dllPath.size() + 1, NULL)) {
        std::cerr << u8"Lỗi ghi bộ nhớ từ xa:" << GetLastError() << "\n";
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
        std::cerr << u8"Lỗi tạo chủ đề từ xa:" << GetLastError() << "\n";
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
    std::cout << u8"\033[33mXóa bộ đệm nào?\033[0m\n";
    move_cursor(0, messageLine + 1);
    std::cout << u8"1 - ChichSML (AppData\\Roaming\\ChichSML)\n";
    move_cursor(0, messageLine + 2);
    std::cout << u8"2 - Launcher (AppData\\Local\\Temp\\ChichSML)\n";
    move_cursor(0, messageLine + 3);
    std::cout << u8"Chọn đi: ";
    std::cout.flush();
}
void delete_yimmenu_cache() {
    char appDataPath[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, appDataPath))) {
        std::string yimPath = std::string(appDataPath) + "\\ChichSML";
        delete_folder_contents(yimPath);
        std::cout << u8"\033[32m[+] Đã xóa bộ nhớ đệm ChichSML thành công.\033[0m\n";
    }
    else {
        std::cerr << u8"\033[31m[-] Lỗi khi nhận đường dẫn AppData.\033[0m\n";
    }
}
void delete_launcher_cache() {
    char tempPath[MAX_PATH];
    if (GetTempPathA(MAX_PATH, tempPath)) {
        std::string launcherPath = std::string(tempPath) + "ChichSML";
        delete_folder_contents(launcherPath);
        std::cout << u8"\033[32m[+] Đã xóa thành công bộ đệm của trình khởi chạy.\033[0m\n";
    }
    else {
        std::cerr << u8"\033[31m[-] Lỗi nhận đường dẫn tạm thời.\033[0m\n";
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
    SetConsoleOutputCP(65001);
    SetConsoleCtrlHandler(ConsoleHandler, TRUE);

    std::string json_response = fetch_active_status();
    auto statusPair = parse_status(json_response);
    
    if (statusPair.first == "Unknown") {
        std::cerr << u8"\033[31m[!] Không thể kết nối đến server! Tool sẽ thoát.\033[0m\n";
        std::this_thread::sleep_for(std::chrono::seconds(5));
        return 1;
    }

    if (statusPair.first != "Working" && statusPair.first != u8"Hoạt động") {
        std::cerr << u8"\033[31m[!] Tool đang bảo trì hoặc bị chặn bởi server! Vui lòng thử lại sau.\033[0m\n";
        std::cerr << u8"\033[33mTrạng thái server: " << statusPair.first << "\033[0m\n";
        std::this_thread::sleep_for(std::chrono::seconds(5));
        return 1;
    }
#ifdef _WIN64
    std::cout << u8"\033[32m[+] Chạy tiến trình 64-bit\033[0m\n";
#else
    std::cout << u8"\033[33m[!] CẢNH BÁO: Chạy tiến trình 32 bit\033[0m\n";
#endif
    std::cout << u8"\033[36m[*] Đang kiểm tra sự phụ thuộc...\033[0m\n";
    if (!is_vcredist_installed()) {
        std::cout << u8"\033[33m[!] Không tìm thấy Visual C++ Redistributable. Đang cài đặt...\033[0m\n";
        if (!download_and_install_vcredist()) {
            std::cerr << u8"\033[31m[-] Không thể cài đặt phụ thuộc. Đang hủy bỏ.\033[0m\n";
            return 1;
        }
    }
    else {
        std::cout << u8"\033[32m[+] Visual C++ Redistributable đã được cài đặt.\033[0m\n";
    }
    prepare_temp_directory_and_download();
    std::wstring targetProcess = L"GTA5_Enhanced.exe";
    std::atomic<bool> injected(false);
    std::atomic<bool> gameDetected(false);
    int messageLine = 20;
    std::string lastColoredStatus, lastColoredStage;

    std::string coloredStatus = "\033[" + statusPair.second + "m" + statusPair.first + "\033[0m";
    draw_interface(coloredStatus, u8"\033[33mĐang chờ vào game...\033[0m");
    std::thread monitorThread([&]() {
        while (true) {
            bool nowDetected = is_process_running(targetProcess);
            gameDetected = nowDetected;
            if (!nowDetected) injected = false;
            std::string stageColor = nowDetected ? (injected ? "32" : "33") : "33";
            std::string stageText = nowDetected ? (injected ? u8"Đã tiêm!" : u8"Đã nhận diện game, sẵn sàng tiêm") : u8"Đang chờ vào game...";
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
            print_temporary_message(u8"[!] Tuỳ chọn không hợp lệ.", messageLine);
            std::this_thread::sleep_for(std::chrono::seconds(2));
            draw_interface(coloredStatus, gameDetected ?
                (injected ? u8"\033[32mĐã tiêm!\033[0m" : u8"\033[32mĐã phát hiện trò chơi, Sẵn sàng để tiêm\033[0m") :
                u8"\033[33mĐang chờ vào game...\033[0m");
            continue;
        }
        switch (option) {
        case 1: {
            if (gameDetected) {
                if (!injected) {
                    char tempPath[MAX_PATH];
                    GetTempPathA(MAX_PATH, tempPath);
                    std::string fullDllPath = std::string(tempPath) + "ChichSML\\ChichSML.dll";
                    DWORD pid = get_process_id(targetProcess);
                    if (pid == 0) {
                        print_temporary_message(u8"[-] Không tìm thấy tiến trình!", messageLine);
                        break;
                    }
                    std::cout << u8"[DEBUG] Đang tiêm DLL: " << fullDllPath << "\n";
                    if (inject_dll(pid, fullDllPath)) {
                        injected = true;
                        print_temporary_message(u8"[+] Đã tiêm DLL thành công!", messageLine);
                    }
                    else {
                        print_temporary_message(u8"[-] Tiêm DLL thất bại.", messageLine);
                    }
                }
                else {
                    print_temporary_message(u8"[!] Đã tiêm rồi.", messageLine);
                }
            }
            else {
                print_temporary_message(u8"[-] Chưa mở game!", messageLine);
            }

            std::this_thread::sleep_for(std::chrono::seconds(2));
            draw_interface(coloredStatus, gameDetected ?
                (injected ? u8"\033[32mĐã tiêm!\033[0m" : u8"\033[32mĐã phát hiện trò chơi, Sẵn sàng để tiêm\033[0m") :
                u8"\033[33mĐang chờ vào game...\033[0m");
            break;
        }
        // case 2: {
        //     show_delete_cache_options(messageLine);
        //     int deleteOption;
        //     std::cin >> deleteOption;
        //     std::cin.ignore(10000, '\n');
        //     if (deleteOption == 1) {
        //         delete_yimmenu_cache();
        //     }
        //     else if (deleteOption == 2) {
        //         delete_launcher_cache();
        //     }
        //     else {
        //         print_temporary_message(u8"[!] Tuỳ chọn không hợp lệ.", messageLine);
        //     }
        //     std::this_thread::sleep_for(std::chrono::seconds(2));
        //     draw_interface(coloredStatus, gameDetected ?
        //         (injected ? u8"\033[32mĐã tiêm!\033[0m" : u8"\033[32mĐã phát hiện trò chơi, Sẵn sàng để tiêm\033[0m") :
        //         u8"\033[33mĐang chờ vào game...\033[0m");
        //     break;
        // }
        case 3:
            system("start https://discord.com/users/537520518744637461");
            print_temporary_message("[+] Discord opened.", messageLine);
            std::this_thread::sleep_for(std::chrono::seconds(2));
            draw_interface(coloredStatus, gameDetected ?
                (injected ? u8"\033[32mĐã tiêm!\033[0m" : u8"\033[32mĐã phát hiện trò chơi, Sẵn sàng để tiêm\033[0m") :
                u8"\033[33mĐang chờ vào game...\033[0m");
            break;
        case 99:
            print_temporary_message(u8"[+] Thoát...", messageLine);
            monitorThread.detach();
            return 0;
        default:
            print_temporary_message(u8"[!] Tuỳ chọn không hợp lệ.", messageLine);
            std::this_thread::sleep_for(std::chrono::seconds(2));
            draw_interface(coloredStatus, gameDetected ?
                (injected ? u8"\033[32mĐã tiêm!\033[0m" : u8"\033[32mĐã phát hiện trò chơi, Sẵn sàng để tiêm\033[0m") :
                u8"\033[33mĐang chờ vào game...\033[0m");
            break;
        }
    }
}
