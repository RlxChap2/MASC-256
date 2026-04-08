cmake_minimum_required(VERSION 3.10)

project(ACC_CRYPTO VERSION 1.0 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

set(CMAKE_BUILD_TYPE Release)

include_directories(include)

set(SOURCES
    src/main.c
    src/acc_crypto.c
    src/memory_mix.c
)

add_executable(acc_crypto ${SOURCES})

if(MSVC)
    target_compile_options(acc_crypto PRIVATE
        /W4
        $<$<CONFIG:Release>:/O2>
    )
else()
    target_compile_options(acc_crypto PRIVATE
        -Wall
        -Wextra
        -Wpedantic
        $<$<CONFIG:Release>:-O3;-march=native;-funroll-loops>
    )
endif()