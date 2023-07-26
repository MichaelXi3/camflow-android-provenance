add_executable(
        camflowd

        # Source files
        main.c
        ini/ini.c

        # Header files
        ini/ini.h
        camflowd-include/service-log.h
        camflowd-include/service-config.h
    )

# Find the android log library and store the path as log-lib
find_library(
        log-lib
        log)

# Partially link the executable with shared libraries at compile time
target_link_libraries(
        camflowd
        PUBLIC
        provenance
        ${log-lib})