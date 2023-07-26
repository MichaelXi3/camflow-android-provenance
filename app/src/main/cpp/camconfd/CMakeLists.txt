add_executable(
        camconfd

        # Source files
        config.c
        ini/ini.c

        # Header files
        ini/ini.h
        camconf.h
)

# Find the android log library and store the path as log-lib
find_library(
        log-lib
        log)

# Partially link the executable with shared libraries at compile time
target_link_libraries(
        camconfd
        PUBLIC
        provenance
        ${log-lib})