add_library(
        thpool STATIC
        thpool.c
        thpool.h
)

# add_compile_definitions(LIBRARY_EXPORTS)
target_include_directories(thpool PUBLIC "${PROJECT_SOURCE_DIR}")