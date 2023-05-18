cmake_minimum_required(VERSION 3.1...3.22.1)
project(mingw_util CXX)

set(CMAKE_CXX_STANDARD 17)
add_compile_options("-Wall")

# List all files explicitly; this will make IDEs happy (i.e. QtCreator, CLion, ...)
list(APPEND PEPARSERLIB_SOURCEFILES
  pe-parse/pe-parser-library/include/pe-parse/parse.h
  pe-parse/pe-parser-library/include/pe-parse/nt-headers.h
  pe-parse/pe-parser-library/include/pe-parse/to_string.h

  pe-parse/pe-parser-library/src/buffer.cpp
  pe-parse/pe-parser-library/src/parse.cpp
)

# NOTE(ww): On Windows we use the Win32 API's built-in UTF16 conversion
# routines; on other platforms we use codecvt. codecvt is nominally deprecated
# in C++17 and onwards, but will probably be available for quite some time.
# Previous versions of pe-parse used ICU when available, but this caused
# DLL hell on Windows and wasn't worth the additional dependency.
if(MSVC)
  list(APPEND PEPARSERLIB_SOURCEFILES pe-parse/pe-parser-library/src/unicode_winapi.cpp)
else()
  list(APPEND PEPARSERLIB_SOURCEFILES pe-parse/pe-parser-library/src/unicode_codecvt.cpp)
endif()

add_executable(peldd
  peldd.cc
  ${PEPARSERLIB_SOURCEFILES}
  )
set_property(TARGET peldd PROPERTY INCLUDE_DIRECTORIES
    ${CMAKE_CURRENT_SOURCE_DIR}/pe-parse/pe-parser-library/include)

install(TARGETS peldd
        RUNTIME DESTINATION bin)
