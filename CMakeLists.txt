cmake_minimum_required(VERSION 3.20)
project(jwt_webserver)

set(CMAKE_CXX_STANDARD 17)
find_package(Threads REQUIRED)

add_subdirectory(lib/jwt-cpp)
add_subdirectory(lib/cpp-httplib)

add_executable(${PROJECT_NAME} main.cpp)
target_link_libraries(${PROJECT_NAME} Threads::Threads jwt-cpp httplib::httplib)
