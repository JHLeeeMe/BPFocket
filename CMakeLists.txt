### CMakeLists.txt
###

# FetchContent requires at least 3.14
cmake_minimum_required(VERSION 3.14)
project(BPFocket)

# GoogleTest requires at least C++14
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Debug" CACHE STRING "Choose the type of build." FORCE)
endif()

set(CMAKE_DEBUG_POSTFIX "_d")
set(CMAKE_RELWITHDEBINFO_POSTFIX "_rd")

# Add sub dir
if(UNIX AND NOT APPLE)
    add_subdirectory(test/)
    add_subdirectory(sample/)
endif()

message("\n###################################################################")
message(STATUS "CMake Version:          ${CMAKE_VERSION}")
message(STATUS "Project:                ${PROJECT_NAME}")
message(STATUS "Generator:              ${CMAKE_GENERATOR}")
message(STATUS "Bulid for OS type:      ${CMAKE_SYSTEM_NAME}")
message(STATUS "Build for OS version:   ${CMAKE_SYSTEM_VERSION}")
message(STATUS "Build for CPU type:     ${CMAKE_SYSTEM_PROCESSOR}")
message(STATUS "Build type:             ${CMAKE_BUILD_TYPE}")

string(TOUPPER ${CMAKE_BUILD_TYPE} BUILD_TYPE)
message(STATUS "C flags:                ${CMAKE_C_FLAGS_${BUILD_TYPE}} ${CMAKE_C_FLAGS}")
message(STATUS "CXX flags:              ${CMAKE_CXX_FLAGS_${BUILD_TYPE}} ${CMAKE_CXX_FLAGS}")
message(STATUS "Build output path:      ${CMAKE_BINARY_DIR}")
message(STATUS "Install path:           ${CMAKE_INSTALL_PREFIX}")
message("###################################################################\n")
