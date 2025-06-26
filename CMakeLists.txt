cmake_minimum_required(VERSION 3.14)
project(YimMenuV2Launcher)

set(CMAKE_CXX_STANDARD 17)

# Tích hợp vcpkg (GitHub Actions tự nhận)
find_package(CURL REQUIRED)

add_executable(YimMenuV2Launcher
    YimMenuV2LauncherOpenSource.cpp
    json.hpp
)

target_link_libraries(YimMenuV2Launcher PRIVATE CURL::libcurl)
