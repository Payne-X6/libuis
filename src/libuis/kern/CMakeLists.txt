add_custom_target(bpf.compile
    clang -O3 -g -Wall -target bpf -c ${CMAKE_CURRENT_SOURCE_DIR}/bpf.c -o ${CMAKE_CURRENT_BINARY_DIR}/bpf.o
    SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/bpf.c
    BYPRODUCTS ${CMAKE_CURRENT_BINARY_DIR}/bpf.o
)

add_custom_target(bpf.serialize
    bpftool gen skeleton ${CMAKE_CURRENT_BINARY_DIR}/bpf.o > ${CMAKE_CURRENT_BINARY_DIR}/bpf.h
    SOURCES ${CMAKE_CURRENT_BINARY_DIR}/bpf.o
    BYPRODUCTS ${CMAKE_CURRENT_BINARY_DIR}/bpf.h
)