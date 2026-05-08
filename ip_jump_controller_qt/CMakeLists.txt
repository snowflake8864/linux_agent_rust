cmake_minimum_required(VERSION 3.16)
project(ip_jump_controller_qt VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

# Cross-compilation: set Qt6_DIR and CMAKE_TOOLCHAIN_FILE externally
# e.g. cmake -DCMAKE_TOOLCHAIN_FILE=loongarch64.cmake -DQt6_DIR=/path/to/qt6/lib/cmake/Qt6

find_package(Qt6 REQUIRED COMPONENTS Widgets Network Core)

add_executable(ip_jump_controller_qt
    src/main.cpp
    src/mainwindow.cpp
    src/mockserver.cpp
)

target_link_libraries(ip_jump_controller_qt PRIVATE
    Qt6::Widgets
    Qt6::Network
    Qt6::Core
)
