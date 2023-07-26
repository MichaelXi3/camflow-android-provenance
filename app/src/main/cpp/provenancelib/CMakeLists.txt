
add_subdirectory(threadpool)

include_directories(camflow-dev-include)
include_directories(libprovenance-include)
include_directories(threadpool)

add_library(
        provenance SHARED
        relay.c
        libprovenance.c
        provenancefilter.c
        provenanceSPADEJSON.c
        provenanceW3CJSON.c
        provenanceutils.c

        # directory level header files
        provenanceJSONcommon.h
        uthash.h

        # libprovenance-include header files
        libprovenance-include/provenance.h
        libprovenance-include/provenance_utils.h
        libprovenance-include/provenancefilter.h
        libprovenance-include/provenanceSPADEJSON.h
        libprovenance-include/provenanceW3CJSON.h

        # camflow-dev-include header files
        camflow-dev-include/provenanceh.h
        camflow-dev-include/provenance_fs.h
        camflow-dev-include/provenance_types.h
)

#add_compile_definitions(LIBRARY_EXPORTS)
target_include_directories(provenance PUBLIC "${PROJECT_SOURCE_DIR}")

find_library(
        log-lib
        log)

target_link_libraries(
        provenance
        PUBLIC
        thpool
        ${log-lib})
