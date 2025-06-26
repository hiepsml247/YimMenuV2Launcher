cmake_minimum_required(VERSION 3.14)
project(YimMenuV2Launcher)

set(CMAKE_CXX_STANDARD 17)

find_package(CURL CONFIG REQUIRED)

add_executable(YimMenuV2Launcher
    YimMenuV2LauncherOpenSource.cpp
    json.hpp
    appicon.rc
)
target_link_libraries(YimMenuV2Launcher PRIVATE CURL::libcurl)
