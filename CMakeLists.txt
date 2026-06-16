cmake_minimum_required(VERSION 3.15)

project(aestool LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_executable(aestool
    src/main.cpp
)

target_include_directories(aestool PRIVATE
    C:/msys64/mingw64/include
)

target_link_directories(aestool PRIVATE
    C:/msys64/mingw64/lib
)

target_link_libraries(aestool PRIVATE
    cryptopp
    ws2_32
)