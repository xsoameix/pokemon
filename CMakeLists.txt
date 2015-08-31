cmake_minimum_required(VERSION 2.8.12.2)

# Unix / Linux

add_executable(main main.c lib.c)

# Windows

SET(CMAKE_SYSTEM_NAME Windows)
set(COMPILER_PREFIX i686-w64-mingw32)
set(CMAKE_C_COMPILER ${COMPILER_PREFIX}-gcc)
set(CMAKE_SHARED_LIBRARY_LINK_C_FLAGS "")

# here is the target environment located
set(CMAKE_FIND_ROOT_PATH /usr/${COMPILER_PREFIX})

# adjust the default behaviour of the FIND_XXX() commands:
# search headers and libraries in the target environment, search 
# programs in the host environment
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)

add_executable(win.exe win.c lib.c)
