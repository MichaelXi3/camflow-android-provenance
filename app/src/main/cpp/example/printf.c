#include <stdio.h>
#include <errno.h>
#include "../provenancelib/libprovenance-include/provenance.h"


int main() {
    if(provenance_set_tracked(true)){
        printf("Failed Tracking, error %d\n", errno);
        printf("%s\n\n",strerror(errno));
    }
    if(provenance_set_propagate(true)){
        printf("Failed propagate, error %d\n", errno);
        printf("%s\n\n",strerror(errno));
    }
    printf("Hello World \n");
}
