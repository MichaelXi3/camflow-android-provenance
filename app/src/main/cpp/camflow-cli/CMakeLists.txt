add_executable(
        camflow-cli

        # Source files
        camflow.c
)

# Find the android log library and store the path as log-lib
find_library(
        log-lib
        log)

# Partially link the executable with shared libraries at compile time
target_link_libraries(
        camflow-cli
        PUBLIC
        provenance
        ${log-lib})