#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <netdb.h>

#include "camflow-dev-include/provenance_types.h"

#include "libprovenance-include/provenance.h"
#include "libprovenance-include/provenancefilter.h"

static inline int __provenance_change_filter( bool add, const char* file, uint64_t filter, uint64_t mask ){
    struct prov_filter f;
    int fd = open(file, O_WRONLY);
    int rc;

    if(fd<0)
    {
        return fd;
    }
    f.filter=filter;
    f.mask=mask;
    if(add){
        f.add=1;
    }else{
        f.add=0;
    }

    rc = write(fd, &f, sizeof(struct prov_filter));
    close(fd);
    if(rc<0){
        return rc;
    }
    return 0;
}

static inline int __provenance_get_filter( const char* file, uint64_t* filter ){
    int fd = open(file, O_RDONLY);
    int rc;
    if(fd<0)
    {
        return fd;
    }

    rc = read(fd, filter, sizeof(uint64_t));
    close(fd);
    if(rc<0){
        return rc;
    }
    return 0;
}

#define declare_change_filter_fcn(fcn_name, add, file, mask) int fcn_name ( uint64_t filter ){return __provenance_change_filter(add, file, filter, mask);}
#define declare_get_filter_fcn(fcn_name, file) int fcn_name ( uint64_t* filter ){ return __provenance_get_filter( file, filter );}
#define declare_reset_filter_fcn(fcn_name, file) int fcn_name ( void ){return __provenance_change_filter(false, file, 0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL);}


// node filter
declare_change_filter_fcn(provenance_add_node_filter, true, PROV_NODE_FILTER_FILE, SUBTYPE_MASK);
declare_change_filter_fcn(provenance_remove_node_filter, false, PROV_NODE_FILTER_FILE, SUBTYPE_MASK);
declare_get_filter_fcn(provenance_get_node_filter, PROV_NODE_FILTER_FILE);
declare_reset_filter_fcn(provenance_reset_node_filter, PROV_NODE_FILTER_FILE);

// propagate node filter
declare_change_filter_fcn(provenance_add_propagate_node_filter, true, PROV_PROPAGATE_NODE_FILTER_FILE, SUBTYPE_MASK);
declare_change_filter_fcn(provenance_remove_propagate_node_filter, false, PROV_PROPAGATE_NODE_FILTER_FILE, SUBTYPE_MASK);
declare_get_filter_fcn(provenance_get_propagate_node_filter, PROV_PROPAGATE_NODE_FILTER_FILE);
declare_reset_filter_fcn(provenance_reset_propagate_node_filter, PROV_PROPAGATE_NODE_FILTER_FILE);

// relation filter
declare_change_filter_fcn(provenance_add_derived_filter, true, PROV_DERIVED_FILTER_FILE, SUBTYPE_MASK);
declare_change_filter_fcn(provenance_remove_derived_filter, false, PROV_DERIVED_FILTER_FILE, SUBTYPE_MASK);
declare_get_filter_fcn(provenance_get_derived_filter, PROV_DERIVED_FILTER_FILE);
declare_reset_filter_fcn(provenance_reset_derived_filter, PROV_DERIVED_FILTER_FILE);

// relation filter
declare_change_filter_fcn(provenance_add_generated_filter, true, PROV_GENERATED_FILTER_FILE, SUBTYPE_MASK);
declare_change_filter_fcn(provenance_remove_generated_filter, false, PROV_GENERATED_FILTER_FILE, SUBTYPE_MASK);
declare_get_filter_fcn(provenance_get_generated_filter, PROV_GENERATED_FILTER_FILE);
declare_reset_filter_fcn(provenance_reset_generated_filter, PROV_GENERATED_FILTER_FILE);

// relation filter
declare_change_filter_fcn(provenance_add_used_filter, true, PROV_USED_FILTER_FILE, SUBTYPE_MASK);
declare_change_filter_fcn(provenance_remove_used_filter, false, PROV_USED_FILTER_FILE, SUBTYPE_MASK);
declare_get_filter_fcn(provenance_get_used_filter, PROV_USED_FILTER_FILE);
declare_reset_filter_fcn(provenance_reset_used_filter, PROV_USED_FILTER_FILE);

// relation filter
declare_change_filter_fcn(provenance_add_informed_filter, true, PROV_INFORMED_FILTER_FILE, SUBTYPE_MASK);
declare_change_filter_fcn(provenance_remove_informed_filter, false, PROV_INFORMED_FILTER_FILE, SUBTYPE_MASK);
declare_get_filter_fcn(provenance_get_informed_filter, PROV_INFORMED_FILTER_FILE);
declare_reset_filter_fcn(provenance_reset_informed_filter, PROV_INFORMED_FILTER_FILE);

// propagate relation filter
declare_change_filter_fcn(provenance_add_propagate_derived_filter, true, PROV_PROPAGATE_DERIVED_FILTER_FILE, SUBTYPE_MASK);
declare_change_filter_fcn(provenance_remove_propagate_derived_filter, false, PROV_PROPAGATE_DERIVED_FILTER_FILE, SUBTYPE_MASK);
declare_get_filter_fcn(provenance_get_propagate_derived_filter, PROV_PROPAGATE_DERIVED_FILTER_FILE);
declare_reset_filter_fcn(provenance_reset_propagate_derived_filter, PROV_PROPAGATE_DERIVED_FILTER_FILE);

// relation filter
declare_change_filter_fcn(provenance_add_propagate_generated_filter, true, PROV_PROPAGATE_GENERATED_FILTER_FILE, SUBTYPE_MASK);
declare_change_filter_fcn(provenance_remove_propagate_generated_filter, false, PROV_PROPAGATE_GENERATED_FILTER_FILE, SUBTYPE_MASK);
declare_get_filter_fcn(provenance_get_propagate_generated_filter, PROV_PROPAGATE_GENERATED_FILTER_FILE);
declare_reset_filter_fcn(provenance_reset_propagate_generated_filter, PROV_PROPAGATE_GENERATED_FILTER_FILE);

// relation filter
declare_change_filter_fcn(provenance_add_propagate_used_filter, true, PROV_PROPAGATE_USED_FILTER_FILE, SUBTYPE_MASK);
declare_change_filter_fcn(provenance_remove_propagate_used_filter, false, PROV_PROPAGATE_USED_FILTER_FILE, SUBTYPE_MASK);
declare_get_filter_fcn(provenance_get_propagate_used_filter, PROV_PROPAGATE_USED_FILTER_FILE);
declare_reset_filter_fcn(provenance_reset_propagate_used_filter, PROV_PROPAGATE_USED_FILTER_FILE);

// relation filter
declare_change_filter_fcn(provenance_add_propagate_informed_filter, true, PROV_PROPAGATE_INFORMED_FILTER_FILE, SUBTYPE_MASK);
declare_change_filter_fcn(provenance_remove_propagate_informed_filter, false, PROV_PROPAGATE_INFORMED_FILTER_FILE, SUBTYPE_MASK);
declare_get_filter_fcn(provenance_get_propagate_informed_filter, PROV_PROPAGATE_INFORMED_FILTER_FILE);
declare_reset_filter_fcn(provenance_reset_propagate_informed_filter, PROV_PROPAGATE_INFORMED_FILTER_FILE);