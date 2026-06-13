cmake_minimum_required(VERSION 3.10)

project(MASC_256 VERSION 2.0 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})

add_library(masc256
    src/acc_crypto.c
    src/memory_mix.c
)

target_include_directories(masc256 PUBLIC include)

add_executable(acc_crypto src/main.c)
target_link_libraries(acc_crypto PRIVATE masc256)

include(CTest)
if(BUILD_TESTING)
    add_executable(masc256_tests tests/test_masc256.c)
    target_link_libraries(masc256_tests PRIVATE masc256)
    add_test(NAME masc256_roundtrip COMMAND masc256_tests)
endif()

if(MSVC)
    target_compile_options(masc256 PRIVATE
        /W4
        $<$<CONFIG:Release>:/O2>
    )
    target_compile_options(acc_crypto PRIVATE /W4)
    if(BUILD_TESTING)
        target_compile_options(masc256_tests PRIVATE /W4)
    endif()
else()
    target_compile_options(masc256 PRIVATE
        -Wall
        -Wextra
        -Wpedantic
        $<$<CONFIG:Release>:-O3;-march=native;-funroll-loops>
    )
    target_compile_options(acc_crypto PRIVATE -Wall -Wextra -Wpedantic)
    if(BUILD_TESTING)
        target_compile_options(masc256_tests PRIVATE -Wall -Wextra -Wpedantic)
    endif()
endif()

if(WIN32)
    target_link_libraries(masc256 PUBLIC bcrypt)
endif()
