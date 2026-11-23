cmake_minimum_required(VERSION 3.16)

if(NOT PROJECT_NAME)
    project(spuemu LANGUAGES CXX)
    enable_testing()
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(SPUEMU_CORE_SOURCES
    src/cpu.cpp
    src/debugger.cpp
    src/disasm.cpp
    src/log.cpp
    src/machine.cpp
    src/memory.cpp
    src/module_path.cpp
    src/spu_channels.cpp
)

add_library(spuemu_core STATIC ${SPUEMU_CORE_SOURCES})

target_include_directories(spuemu_core
    PUBLIC
        "${CMAKE_CURRENT_SOURCE_DIR}/src"
)

if(WIN32)
    target_compile_definitions(spuemu_core PUBLIC _CRT_SECURE_NO_WARNINGS NOMINMAX)
    target_link_libraries(spuemu_core PUBLIC ws2_32)
else()
    find_package(Threads REQUIRED)
    target_link_libraries(spuemu_core PUBLIC Threads::Threads ${CMAKE_DL_LIBS})
endif()

get_filename_component(SPUEMU_REPO_ROOT_ABS "${CMAKE_CURRENT_SOURCE_DIR}/../.." ABSOLUTE)
if(MSVC)
    file(TO_NATIVE_PATH "${CMAKE_CURRENT_SOURCE_DIR}" SPUEMU_SRC_PREFIX_NATIVE)
    file(TO_NATIVE_PATH "${SPUEMU_REPO_ROOT_ABS}" SPUEMU_REPO_ROOT_NATIVE)
    target_compile_options(spuemu_core PUBLIC "/d1trimfile:${SPUEMU_SRC_PREFIX_NATIVE}")
    target_compile_options(spuemu_core PUBLIC "/d1trimfile:${SPUEMU_REPO_ROOT_NATIVE}")
else()
    target_compile_options(spuemu_core PUBLIC
        "-ffile-prefix-map=${CMAKE_CURRENT_SOURCE_DIR}/="
    )
endif()

add_executable(spuemu src/main.cpp)
target_link_libraries(spuemu PRIVATE spuemu_core)

add_executable(spuemu_tests tests/spuemu_tests.cpp)
target_link_libraries(spuemu_tests PRIVATE spuemu_core)
add_test(NAME spuemu_tests COMMAND spuemu_tests)

if(MSVC)
    target_link_options(spuemu PRIVATE $<$<CONFIG:Release>:/PDBALTPATH:%_PDB%>)
    target_link_options(spuemu_tests PRIVATE $<$<CONFIG:Release>:/PDBALTPATH:%_PDB%>)
endif()

# Resolve IDA SDK root from IDASDK, IDA_SDK_DIR, or integrated ida-sdk tree
set(_DEFAULT_IDA_SDK_DIR "")
if(DEFINED IDASDK AND EXISTS "${IDASDK}/include/idd.hpp")
    set(_DEFAULT_IDA_SDK_DIR "${IDASDK}")
elseif(DEFINED ENV{IDASDK} AND EXISTS "$ENV{IDASDK}/include/idd.hpp")
    set(_DEFAULT_IDA_SDK_DIR "$ENV{IDASDK}")
elseif(DEFINED ENV{IDA_SDK_DIR} AND EXISTS "$ENV{IDA_SDK_DIR}/include/idd.hpp")
    set(_DEFAULT_IDA_SDK_DIR "$ENV{IDA_SDK_DIR}")
elseif(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/../../../../include/idd.hpp")
    set(_DEFAULT_IDA_SDK_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../../..")
elseif(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/../../include/idd.hpp")
    set(_DEFAULT_IDA_SDK_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../..")
endif()
set(IDA_SDK_DIR "${_DEFAULT_IDA_SDK_DIR}" CACHE PATH "Path to IDA SDK src directory")

set(_IDA_LIB_PATH "")
if(EXISTS "${IDA_SDK_DIR}/lib/x64_win_64/ida.lib")
    set(_IDA_LIB_PATH "${IDA_SDK_DIR}/lib/x64_win_64/ida.lib")
elseif(EXISTS "${IDA_SDK_DIR}/lib/x64_win_vc_64/ida.lib")
    set(_IDA_LIB_PATH "${IDA_SDK_DIR}/lib/x64_win_vc_64/ida.lib")
endif()

if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/src/ida_dbg_plugin.cpp" AND
   (TARGET idasdk::plugin OR (EXISTS "${IDA_SDK_DIR}/include/idd.hpp" AND _IDA_LIB_PATH)))
    if(COMMAND ida_add_plugin)
        ida_add_plugin(spudbg
            SOURCES
                src/ida_dbg_plugin.cpp
            LIBRARIES
                spuemu_core
        )
    else()
        add_library(spudbg SHARED src/ida_dbg_plugin.cpp)
        set_target_properties(spudbg PROPERTIES
            PREFIX ""
            OUTPUT_NAME "spudbg"
        )
        if(TARGET idasdk::plugin)
            target_link_libraries(spudbg PRIVATE spuemu_core idasdk::plugin)
        else()
            target_include_directories(spudbg PRIVATE "${IDA_SDK_DIR}/include")
            target_compile_definitions(spudbg PRIVATE
                __NT__ __EA64__ __X64__ _CRT_SECURE_NO_WARNINGS NOMINMAX
            )
            target_link_libraries(spudbg PRIVATE spuemu_core "${_IDA_LIB_PATH}")
        endif()
    endif()

    if(MSVC)
        if(EXISTS "${IDA_SDK_DIR}/include/idd.hpp")
            get_filename_component(_IDA_SDK_DIR_ABS "${IDA_SDK_DIR}" ABSOLUTE)
            file(TO_NATIVE_PATH "${_IDA_SDK_DIR_ABS}" _IDA_SDK_DIR_NATIVE)
            target_compile_options(spudbg PRIVATE "/d1trimfile:${_IDA_SDK_DIR_NATIVE}")
        endif()
        target_link_options(spudbg PRIVATE $<$<CONFIG:Release>:/PDBALTPATH:%_PDB%>)
    endif()

    if(DEFINED ENV{APPDATA})
        set(_SPU_IDA_USER_DIR "$ENV{APPDATA}/Hex-Rays/IDA Pro")
        add_custom_command(TARGET spudbg POST_BUILD
            COMMAND "${CMAKE_COMMAND}" -E make_directory "${_SPU_IDA_USER_DIR}/plugins"
            COMMAND "${CMAKE_COMMAND}" -E copy_if_different
                "$<TARGET_FILE:spudbg>"
                "${_SPU_IDA_USER_DIR}/plugins/$<TARGET_FILE_NAME:spudbg>"
            COMMENT "Deploying spudbg plugin to IDA Pro user directory"
        )
    endif()
endif()
