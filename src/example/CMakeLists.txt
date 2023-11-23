find_package(Tcmalloc)

add_executable(server main.cpp)
set_property(TARGET server PROPERTY CXX_STANDARD 20)
target_compile_options(server PRIVATE "-Wall")
target_link_libraries(server uis)
if (${Tcmalloc_FOUND})
    target_link_libraries(server ${Tcmalloc_LIBRARY})
endif()
