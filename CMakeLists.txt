cmake_minimum_required(VERSION 3.8)
project(Secure_Cloud_Storage)

set(CMAKE_CXX_STANDARD 14)
set(GCC_ENABLE_WARNINGS "-O1 -Wall -Werror -Wno-unused-result")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${GCC_ENABLE_WARNINGS}")
include_directories(Source/Client)
include_directories(Source/Server)

add_executable(Secure_Cloud_Storage
        Source/Server/server_main.cpp
        )
