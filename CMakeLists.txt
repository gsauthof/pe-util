cmake_minimum_required(VERSION 3.1...3.22.1)
project(mingw_util CXX)

set(CMAKE_CXX_STANDARD 17)
add_compile_options("-Wall")

add_executable(peldd
  peldd.cc
  pe-parse/pe-parser-library/src/parse.cpp
  pe-parse/pe-parser-library/src/buffer.cpp
  )
set_property(TARGET peldd PROPERTY INCLUDE_DIRECTORIES
    ${CMAKE_CURRENT_SOURCE_DIR}/pe-parse/pe-parser-library/include)

install(TARGETS peldd
        RUNTIME DESTINATION bin)
