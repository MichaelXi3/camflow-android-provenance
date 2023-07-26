#include <stdio.h>
#include <errno.h>
#include "../provenancelib/libprovenance-include/provenance.h"

void create_file(const char* path) {
    FILE* file = fopen(path, "w");
    if (file == NULL) {
        printf("error opening file\n");
        return;
    }

    const char* message = "Hello from C written by Michael Xi!";
    fprintf(file, "%s \n", message);
    fclose(file);
}

int main() {
    if(provenance_set_tracked(true)){
        printf("Failed Tracking, error %d\n", errno);
        printf("%s\n\n",strerror(errno));
    }
//    if(provenance_set_propagate(true)){
//        printf("Failed propagate, error %d\n", errno);
//        printf("%s\n\n",strerror(errno));
//    }
    const char* path = "/data/local/tmp/HelloFromC.txt";
    create_file(path);
    return 0;
}

