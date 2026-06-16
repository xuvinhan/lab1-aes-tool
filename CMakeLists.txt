cmake_minimum_required(VERSION 3.20)

project(AESTool LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_path(CRYPTOPP_INCLUDE_DIR
    NAMES cryptopp/aes.h
    PATHS /mingw64/include
)

find_library(CRYPTOPP_LIBRARY
    NAMES cryptopp
    PATHS /mingw64/lib
)

if (NOT CRYPTOPP_INCLUDE_DIR)
    message(FATAL_ERROR "Crypto++ headers not found. Install mingw-w64-x86_64-crypto++")
endif()

if (NOT CRYPTOPP_LIBRARY)
    message(FATAL_ERROR "Crypto++ library not found. Install mingw-w64-x86_64-crypto++")
endif()

message(STATUS "Crypto++ include dir: ${CRYPTOPP_INCLUDE_DIR}")
message(STATUS "Crypto++ library    : ${CRYPTOPP_LIBRARY}")

add_executable(aestool
    src/main.cpp
)

target_include_directories(aestool PRIVATE
    ${CRYPTOPP_INCLUDE_DIR}
)

target_link_libraries(aestool PRIVATE
    ${CRYPTOPP_LIBRARY}
)

add_executable(aesbench
    src/benchmark.cpp
)

target_include_directories(aesbench PRIVATE
    ${CRYPTOPP_INCLUDE_DIR}
)

target_link_libraries(aesbench PRIVATE
    ${CRYPTOPP_LIBRARY}
)
