cmake_minimum_required(VERSION 3.15)
project(hyprkey_sdk C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

include_directories(include)

# Platform-specific library linking for PC/SC
if(WIN32)
    set(PCSC_LIB winscard)
    add_definitions(-D_WIN32_WINNT=0x0600)
else()
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(PCSC REQUIRED libpcsclite)
    include_directories(${PCSC_INCLUDE_DIRS})
    set(PCSC_LIB ${PCSC_LIBRARIES})
endif()

# Static and Shared Library
add_library(hyprkey_static STATIC
    libhyprkey/transport_pcsc.c
    libhyprkey/satochip.c
)
target_link_libraries(hyprkey_static PRIVATE ${PCSC_LIB})
target_include_directories(hyprkey_static PUBLIC include)

add_library(hyprkey SHARED
    libhyprkey/transport_pcsc.c
    libhyprkey/satochip.c
)
target_compile_definitions(hyprkey PRIVATE HYPRKEY_BUILD_DLL)
target_link_libraries(hyprkey PRIVATE ${PCSC_LIB})
target_include_directories(hyprkey PUBLIC include)

# CLI Tool
add_executable(hyprkey-cli
    cli/main.c
)
target_link_libraries(hyprkey-cli PRIVATE hyprkey_static ${PCSC_LIB})
target_include_directories(hyprkey-cli PRIVATE include)
