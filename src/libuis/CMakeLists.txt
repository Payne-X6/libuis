add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/kern)

add_library(uis SHARED
    uis.cpp global_ctx.cpp link.cpp)

get_target_property(USER_BINARY_DIR bpf.serialize BINARY_DIR)
set_property(TARGET uis PROPERTY CXX_STANDARD 20)

add_dependencies(uis bpf.serialize)
target_compile_options(uis PRIVATE "-Wall")
target_include_directories(uis PRIVATE ${USER_BINARY_DIR} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(uis xdp bpf)
