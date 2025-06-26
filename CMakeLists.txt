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
if (MSVC)
    set_target_properties(YimMenuV2Launcher PROPERTIES
        VS_DEBUGGER_ENVIRONMENT "PATH=%PATH%;$<TARGET_FILE_DIR:YimMenuV2Launcher>"
        LINK_FLAGS "/MANIFEST /MANIFESTINPUT:runasadmin.manifest"
    )
endif()

target_link_libraries(YimMenuV2Launcher PRIVATE CURL::libcurl)
