cmake_minimum_required(VERSION 2.8.12.2)
project(POKE)

add_executable(main main.c lib.c)
add_executable(win win.c lib.c)
