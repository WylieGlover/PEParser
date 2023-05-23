cmake_minimum_required(VERSION 3.23)
project(PeParser64)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_INCLUDE_CURRENT_DIR ON)
set(CMAKE_PREFIX_PATH "C:\\Qt\\6.5.0\\mingw_64\\lib\\cmake\\")

find_package(Qt6Widgets REQUIRED)

set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)
set(AUTOGEN_BUILD_DIR ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(${PROJECT_NAME}
        src/main.cpp
        src/GuiPE.cpp
        headers/GuiPE.hpp)
target_link_libraries(PeParser64 Qt6::Core Qt6::Widgets)
