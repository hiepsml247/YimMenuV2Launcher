cmake_minimum_required(VERSION 3.14)
project(YimMenuV2Launcher)

set(CMAKE_CXX_STANDARD 17)
find_package(CURL CONFIG REQUIRED)

add_executable(YimMenuV2Launcher
    YimMenuV2LauncherOpenSource.cpp
    json.hpp
    appicon.rc
    runasadmin.manifest
)

set_target_properties(YimMenuV2Launcher PROPERTIES
  VS_GLOBAL_EnableManifest true
  VS_GLOBAL_ApplicationManifest "runasadmin.manifest"
)
