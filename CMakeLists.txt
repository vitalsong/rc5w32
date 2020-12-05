cmake_minimum_required(VERSION 3.1)
project(rc5w32 LANGUAGES C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

add_compile_options(-Wall -Wextra)
#add_definitions(-DRC5_EMBEDDED)

add_library(${PROJECT_NAME} src/rc5w32.c)
target_include_directories(${PROJECT_NAME} PUBLIC src)

if (CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    add_subdirectory(tests)
endif()
