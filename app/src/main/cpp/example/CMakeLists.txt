add_executable(
        camflowexample

        # Source files
        write.c
)

# Find the android log library and store the path as log-lib
find_library(
        log-lib
        log)

# Partially link the executable with shared libraries at compile time
target_link_libraries(
        camflowexample
        PUBLIC
        provenance
        ${log-lib})