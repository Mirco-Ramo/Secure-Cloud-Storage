cmake_minimum_required(VERSION 3.8)
project(Secure_Cloud_Storage)

set(CMAKE_CXX_STANDARD 14)
link_libraries(crypto)
set(GCC_ENABLE_WARNINGS "-O1 -Wall -Werror -Wno-unused-result")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${GCC_ENABLE_WARNINGS}")
SET(CMAKE_CXX_FLAGS -pthread)
include_directories(Source/Client)
include_directories(Source/Server)
include_directories(Source/Common_Libs)
include_directories(Keys/Server)

add_executable(Server Source/Server/server_main.cpp
        Source/Common_Libs/common_parameters.h
        Source/Common_Libs/common_functions.h
        Source/Common_Libs/struct_message.h
        Source/Server/server_include.h
        Source/Server/worker.h
        Source/Server/server_functions.h
        Source/Common_Libs/communication_utilities.cpp
        Source/Common_Libs/crypto_utilities.cpp
        Source/Server/worker_logic_functions.cpp
        Source/Server/worker_protocol_functions.cpp
        Source/Server/server_conn_functions.cpp
        Source/Common_Libs/buffers.h)

add_executable(Client Source/Client/client_main.cpp
        Source/Common_Libs/common_parameters.h
        Source/Common_Libs/common_functions.h
        Source/Common_Libs/struct_message.h
        Source/Client/client_functions.h
        Source/Common_Libs/communication_utilities.cpp
        Source/Common_Libs/crypto_utilities.cpp
        Source/Client/client_conn_functions.cpp
        Source/Client/client_logic_functions.cpp
        Source/Client/client_protocol_functions.cpp Source/Common_Libs/buffers.h)
