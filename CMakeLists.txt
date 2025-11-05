cmake_minimum_required(VERSION 3.22.1)

project(pairipcore)


add_library(pairipcore SHARED
        src/library.cpp
        src/armhook.c
        src/inlinehook.c
        src/mem.c
        src/memscan.c
        src/proc.c
)

target_link_libraries(pairipcore
        android
        log
)

# Only build for ARM architectures (remove x86)
set(CMAKE_ANDROID_ARCH_ABI arm64-v8a armeabi-v7a)
