cmake_minimum_required(VERSION 3.20)
project(sim_verify_recorder LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_library(sim_verify_recorder STATIC
    src/boundary_walk.cpp
    src/boundary_writer.cpp
    src/boundary_session.cpp
)

target_include_directories(sim_verify_recorder
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

if(MSVC)
    target_compile_options(sim_verify_recorder PRIVATE /W4 /EHsc)
    target_compile_definitions(sim_verify_recorder PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
endif()

add_executable(sim_verify_recorder_test
    tests/test_native_recorder.cpp
)

target_link_libraries(sim_verify_recorder_test PRIVATE sim_verify_recorder)

if(MSVC)
    target_compile_options(sim_verify_recorder_test PRIVATE /W4 /EHsc)
    target_compile_definitions(sim_verify_recorder_test PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
endif()

enable_testing()
add_test(NAME sim_verify_recorder_test COMMAND sim_verify_recorder_test)
