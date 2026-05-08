# CMake toolchain file for loongarch64-linux-musl cross-compilation
# Usage: cmake -DCMAKE_TOOLCHAIN_FILE=this_file -B build_loong64 ...

set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR loongarch64)

set(TOOLCHAIN_PREFIX /opt/loongarch64-linux-musl)
set(SYSROOT ${TOOLCHAIN_PREFIX}/sysroot)
set(CMAKE_SYSROOT ${SYSROOT})

set(CMAKE_C_COMPILER ${TOOLCHAIN_PREFIX}/bin/loongarch64-linux-musl-gcc)
set(CMAKE_CXX_COMPILER ${TOOLCHAIN_PREFIX}/bin/loongarch64-linux-musl-g++)
set(CMAKE_AR ${TOOLCHAIN_PREFIX}/bin/loongarch64-linux-musl-ar)
set(CMAKE_RANLIB ${TOOLCHAIN_PREFIX}/bin/loongarch64-linux-musl-ranlib)
set(CMAKE_STRIP ${TOOLCHAIN_PREFIX}/bin/loongarch64-linux-musl-strip)
set(CMAKE_OBJCOPY ${TOOLCHAIN_PREFIX}/bin/loongarch64-linux-musl-objcopy)
set(CMAKE_OBJDUMP ${TOOLCHAIN_PREFIX}/bin/loongarch64-linux-musl-objdump)

set(CMAKE_FIND_ROOT_PATH ${SYSROOT})
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY BOTH)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE BOTH)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE BOTH)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} --sysroot=${SYSROOT}" CACHE STRING "")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} --sysroot=${SYSROOT}" CACHE STRING "")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} --sysroot=${SYSROOT}" CACHE STRING "")
