cmake_minimum_required(VERSION 3.16)

project(health_talent_spot_api)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(mongocxx REQUIRED)
find_package(bsoncxx REQUIRED)

add_executable(health-api src/main.cpp)

target_include_directories(health-api PRIVATE include)

target_link_libraries(health-api PRIVATE pthread)
target_link_libraries(health-api PRIVATE mongo::mongocxx_shared mongo::bsoncxx_shared)
