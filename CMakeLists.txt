cmake_minimum_required(VERSION 3.20)
project(jwt_webserver)

set(CMAKE_CXX_STANDARD 17)
find_package(Threads REQUIRED)

add_executable(jwt_webserver main.cpp)
target_link_libraries(jwt_webserver Threads::Threads)
