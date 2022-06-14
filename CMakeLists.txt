cmake_minimum_required(VERSION 3.8)
project(Secure_Cloud_Storage)

set(CMAKE_CXX_STANDARD 14)
set(GCC_ENABLE_WARNINGS "-O1 -Wall -Werror -Wno-unused-result")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${GCC_ENABLE_WARNINGS}")
include_directories(Source/Client)

#add_executable(Secure_Cloud_Storage ${SOURCE_FILES})

add_executable(Server Source/Server/server_main.cpp)
include_directories(Source/Server)
add_executable(Client Source/Client/client_main.cpp)
