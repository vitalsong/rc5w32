cmake_minimum_required(VERSION 3.4)
project(rc5w32-tests LANGUAGES CXX)

add_executable(${PROJECT_NAME} main.cpp)
target_link_libraries(${PROJECT_NAME} rc5w32)
add_test(NAME ${PROJECT_NAME} COMMAND rc5w32-tests)
