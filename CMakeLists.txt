cmake_minimum_required(VERSION 3.15)
project(SandBoxieUnlocker LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 仅支持 MSVC（依赖 cl.exe 的 /utf-8 源码与 Windows SDK）
if(NOT MSVC)
    message(FATAL_ERROR "本项目需使用 MSVC (cl.exe) 工具链编译（如 Visual Studio 2022 或 Build Tools）")
endif()

# 仅支持 64 位：代码里有 uint64 指针/CR3/物理地址运算，x86 会被截断
if(NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
    message(FATAL_ERROR "本项目仅支持 x64 构建：VS 生成器请加 -A x64，命令行请用 x64 开发者环境")
endif()

# GUI 主程序（WIN32 自动设置 /SUBSYSTEM:WINDOWS，即无控制台窗口）
add_executable(SandBoxieUnlocker WIN32
    src/main.cpp
    src/core.cpp
    src/windows_security_check.cpp
)

target_include_directories(SandBoxieUnlocker PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party
)

target_compile_definitions(SandBoxieUnlocker PRIVATE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
    _CRT_SECURE_NO_WARNINGS
    UNICODE
    _UNICODE
)

target_compile_options(SandBoxieUnlocker PRIVATE
    /utf-8   # 源码按 UTF-8 处理（含中文字面量）
    /O2      # 优化
)

target_link_libraries(SandBoxieUnlocker PRIVATE
    psapi
    advapi32
    shell32
    bcrypt
    user32
    gdi32
)

# 若源码树中存在 RTCore64.sys，构建后自动拷到输出目录，
# 这样工具运行时可直接从自身目录加载驱动。
set(RTCORE64_SYS "${CMAKE_CURRENT_SOURCE_DIR}/third_party/RTCore64.sys")
if(EXISTS "${RTCORE64_SYS}")
    add_custom_command(TARGET SandBoxieUnlocker POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "${RTCORE64_SYS}" "$<TARGET_FILE_DIR:SandBoxieUnlocker>/RTCore64.sys"
        COMMENT "已复制 RTCore64.sys 到输出目录")
endif()
