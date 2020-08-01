cmake_minimum_required(VERSION 3.4)
project(rc5w32 LANGUAGES C)

set(CMAKE_C_STANDARD 90)
add_compile_options(-Wall -Wextra)

add_library(${PROJECT_NAME} src/rc5w32.c)
target_include_directories(${PROJECT_NAME} PUBLIC src)

if (CMAKE_TESTING_ENABLED)
    add_subdirectory(tests)
endif ()
