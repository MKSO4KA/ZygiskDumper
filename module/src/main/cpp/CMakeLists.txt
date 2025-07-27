cmake_minimum_required(VERSION 3.18.1)

if (NOT DEFINED MODULE_NAME)
    message(FATAL_ERROR "MODULE_NAME is not set")
else ()
    project(${MODULE_NAME})
endif ()

message("Build type: ${CMAKE_BUILD_TYPE}")

set(CMAKE_CXX_STANDARD 20)

set(LINKER_FLAGS "-ffixed-x18 -Wl,--hash-style=both")
set(C_FLAGS "-Werror=format -fdata-sections -ffunction-sections")
set(CXX_FLAGS "${CXX_FLAGS} -fno-exceptions -fno-rtti")

if (NOT CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(C_FLAGS "${C_FLAGS} -O2 -fvisibility=hidden -fvisibility-inlines-hidden")
    set(LINKER_FLAGS "${LINKER_FLAGS} -Wl,-exclude-libs,ALL -Wl,--gc-sections -Wl,--strip-all")
else ()
    set(C_FLAGS "${C_FLAGS} -O0")
endif ()

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${C_FLAGS}")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${C_FLAGS} ${CXX_FLAGS}")

set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} ${LINKER_FLAGS}")
set(CMAKE_MODULE_LINKER_FLAGS "${CMAKE_MODULE_LINKER_FLAGS} ${LINKER_FLAGS}")

# --- ИЗМЕНЕНИЯ ЗДЕСЬ ---

# 1. Указываем, где лежат наши заголовочные файлы (включая dobby.h)
include_directories(
        xdl/include
        ${CMAKE_CURRENT_SOURCE_DIR}/include # <-- ДОБАВЛЕНО
)

# 2. Создаем "цель" для нашей пред-собранной библиотеки Dobby
add_library(dobby STATIC IMPORTED)
set_target_properties(dobby PROPERTIES IMPORTED_LOCATION
        ${CMAKE_CURRENT_SOURCE_DIR}/libs/${ANDROID_ABI}/libdobby.a)

aux_source_directory(xdl xdl-src)

add_library(${MODULE_NAME} SHARED
        main.cpp
        hack.cpp
        il2cpp_dump.cpp
        ${xdl-src})

# 3. Указываем нашему модулю, что он должен "линковаться" с Dobby
target_link_libraries(${MODULE_NAME} log dobby) # <-- ДОБАВЛЕНО dobby

# --- КОНЕЦ ИЗМЕНЕНИЙ ---

if (NOT CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_custom_command(TARGET ${MODULE_NAME} POST_BUILD
            COMMAND ${CMAKE_STRIP} --strip-all --remove-section=.comment "${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/lib${MODULE_NAME}.so")
endif ()