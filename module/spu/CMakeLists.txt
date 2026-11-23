# Processor Module: spu (Cell Broadband Engine Synergistic Processor Unit)
if(NOT COMMAND ida_add_procmod)
    cmake_minimum_required(VERSION 3.25)

    if(DEFINED ENV{IDASDK} AND NOT "$ENV{IDASDK}" STREQUAL "")
        set(_SPU_IDASDK_HINT "$ENV{IDASDK}")
    elseif(DEFINED IDASDK AND NOT "${IDASDK}" STREQUAL "")
        set(_SPU_IDASDK_HINT "${IDASDK}")
    elseif(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/../../../../include/pro.h")
        get_filename_component(_SPU_IDASDK_HINT "${CMAKE_CURRENT_SOURCE_DIR}/../../../.." ABSOLUTE)
        set(ENV{IDASDK} "${_SPU_IDASDK_HINT}")
    endif()

    if(_SPU_IDASDK_HINT AND EXISTS "${_SPU_IDASDK_HINT}/cmake/idasdk_standalone.cmake")
        include("${_SPU_IDASDK_HINT}/cmake/idasdk_standalone.cmake")
    endif()

    project(spu_procmod LANGUAGES CXX)
    set(CMAKE_CXX_STANDARD 17)
    set(CMAKE_CXX_STANDARD_REQUIRED ON)

    if(_SPU_IDASDK_HINT AND EXISTS "${_SPU_IDASDK_HINT}/cmake/idasdk_init.cmake")
        include("${_SPU_IDASDK_HINT}/cmake/idasdk_init.cmake")
    endif()
    find_package(idasdk REQUIRED HINTS "${_SPU_IDASDK_HINT}/cmake")
endif()

ida_add_procmod(spu
    SOURCES
        ana.cpp
        emu.cpp
        ins.cpp
        merge.cpp
        out.cpp
        reg.cpp
        spu.hpp
        ins.hpp
)

target_include_directories(spu PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

if(MSVC)
    get_filename_component(SPU_REPO_ROOT_ABS "${CMAKE_CURRENT_SOURCE_DIR}/../.." ABSOLUTE)
    file(TO_NATIVE_PATH "${SPU_REPO_ROOT_ABS}" SPU_REPO_ROOT_NATIVE)
    file(TO_NATIVE_PATH "${CMAKE_CURRENT_SOURCE_DIR}" SPU_SRC_PREFIX_NATIVE)
    target_compile_options(spu PRIVATE "/d1trimfile:${SPU_SRC_PREFIX_NATIVE}")
    target_compile_options(spu PRIVATE "/d1trimfile:${SPU_REPO_ROOT_NATIVE}")
    if(DEFINED IDASDK AND EXISTS "${IDASDK}")
        get_filename_component(SPU_IDASDK_ABS "${IDASDK}" ABSOLUTE)
        file(TO_NATIVE_PATH "${SPU_IDASDK_ABS}" SPU_IDASDK_NATIVE)
        target_compile_options(spu PRIVATE "/d1trimfile:${SPU_IDASDK_NATIVE}")
    endif()
    target_link_options(spu PRIVATE $<$<CONFIG:Release>:/PDBALTPATH:%_PDB%>)
else()
    target_compile_options(spu PRIVATE
        "-ffile-prefix-map=${CMAKE_CURRENT_SOURCE_DIR}/="
    )
endif()

if(DEFINED ENV{APPDATA})
    set(IDA_USER_DIR "$ENV{APPDATA}/Hex-Rays/IDA Pro")

    add_custom_command(TARGET spu POST_BUILD
        COMMAND "${CMAKE_COMMAND}" -E make_directory "${IDA_USER_DIR}/procs"
        COMMAND "${CMAKE_COMMAND}" -E copy_if_different "$<TARGET_FILE:spu>" "${IDA_USER_DIR}/procs/$<TARGET_FILE_NAME:spu>"
        COMMAND "${CMAKE_COMMAND}" -E copy_if_different "${CMAKE_CURRENT_SOURCE_DIR}/spu_shadow.py" "${IDA_USER_DIR}/procs/spu.py"
        COMMENT "Deploying spu procmod and spu.py shadow stub to IDA Pro user directory"
    )

    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/cfg/SPU.cfg")
        add_custom_command(TARGET spu POST_BUILD
            COMMAND "${CMAKE_COMMAND}" -E make_directory "${IDA_USER_DIR}/cfg"
            COMMAND "${CMAKE_COMMAND}" -E copy_if_different "${CMAKE_CURRENT_SOURCE_DIR}/cfg/SPU.cfg" "${IDA_USER_DIR}/cfg/SPU.cfg"
            COMMENT "Deploying SPU.cfg to IDA Pro user directory"
        )
    endif()

    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/til/spu_cbea.til")
        add_custom_command(TARGET spu POST_BUILD
            COMMAND "${CMAKE_COMMAND}" -E make_directory "${IDA_USER_DIR}/til/spu"
            COMMAND "${CMAKE_COMMAND}" -E copy_if_different "${CMAKE_CURRENT_SOURCE_DIR}/til/spu_cbea.til" "${IDA_USER_DIR}/til/spu/spu_cbea.til"
            COMMAND "${CMAKE_COMMAND}" -E copy_if_different "${CMAKE_CURRENT_SOURCE_DIR}/til/spu_cbea.til" "${IDA_USER_DIR}/til/spu_cbea.til"
            COMMENT "Deploying spu_cbea.til to IDA Pro user directory"
        )
    endif()
endif()
