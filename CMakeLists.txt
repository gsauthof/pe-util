cmake_minimum_required(VERSION 2.8.8)
project(mingw_util CXX)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -Wall")

find_package(Boost 1.54
  COMPONENTS
    system # needed by filesystem, log
    filesystem)

add_subdirectory(pe-parse/parser-library)

add_executable(peldd
  peldd.cc)
set_property(TARGET peldd PROPERTY INCLUDE_DIRECTORIES
    ${CMAKE_CURRENT_SOURCE_DIR}/pe-parse)
target_link_libraries(peldd pe-parser-library ${Boost_LIBRARIES})
