cmake_minimum_required(VERSION 3.22)
project(Secure_Cloud_Storage)

set(CMAKE_CXX_STANDARD 14)

include_directories(Source/Client)
include_directories(Source/Server)

add_executable(Secure_Cloud_Storage
        Source/Server/server_main.cpp
        )
