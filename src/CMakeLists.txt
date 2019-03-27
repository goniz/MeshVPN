
#set(SOURCE_FILES meshvpn.c)
file(GLOB_RECURSE SOURCE_FILES *.c)
add_executable(meshvpn ${SOURCE_FILES})
target_link_libraries(meshvpn crypto ssl z)