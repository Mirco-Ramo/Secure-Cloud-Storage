cmake_minimum_required(VERSION 3.8)
project(Secure_Cloud_Storage)

set(CMAKE_CXX_STANDARD 14)
link_libraries(crypto)
set(GCC_ENABLE_WARNINGS "-O1 -Wall -Werror -Wno-unused-result")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${GCC_ENABLE_WARNINGS}")
SET(CMAKE_CXX_FLAGS -pthread)
include_directories(Source/Client)
include_directories(Source/Server)
#add_executable(Secure_Cloud_Storage ${SOURCE_FILES})

add_executable(Server Source/Server/server_main.cpp
        Source/Server/server_include.h
        Source/Server/worker.h
        Source/Server/server_functions.h
        Source/Server/worker_logic_functions.cpp
        Source/Server/worker_protocol_functions.cpp
        Source/Server/server_conn_functions.cpp
        Source/Server/struct_message.h
        Source/Server/worker_message_exchange.cpp)

add_executable(Client Source/Client/client_main.cpp
        Source/Client/struct_message.h)
