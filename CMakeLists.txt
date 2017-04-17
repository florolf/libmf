project(libmf C)

cmake_minimum_required(VERSION 2.8)

set(CMAKE_MODULE_PATH ${libmf_SOURCE_DIR}/cmake)

include_directories(include)

add_subdirectory(include)
add_subdirectory(src)
add_subdirectory(example)
