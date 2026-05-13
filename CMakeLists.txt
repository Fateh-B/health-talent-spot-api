cmake_minimum_required(VERSION 3.16)

project(health_talent_spot_api)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(health-api src/main.cpp)

target_include_directories(health-api PRIVATE include)

target_link_libraries(health-api PRIVATE pthread)
