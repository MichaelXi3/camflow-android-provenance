#define _XOPEN_SOURCE 500
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>

#include "provenancelib/libprovenance-include/provenance.h"
#include "provenancelib/libprovenance-include/provenancefilter.h"
#include "provenancelib/libprovenance-include/provenance_utils.h"

#define ARG_HELP                        "-h"
#define ARG_VERSION                     "-v"
#define ARG_STATE                       "-s"
#define ARG_ENABLE                      "-e"
#define ARG_ALL                         "-a"
#define ARG_POLICY                      "-p"
#define ARG_CONFIG                      "-c"
#define ARG_COMPRESS_NODE               "--compress-node"
#define ARG_COMPRESS_EDGE               "--compress-edge"
#define ARG_DUPLICATE                   "--duplicate"
#define ARG_FILE                        "--file"
#define ARG_TRACK_FILE                  "--track-file"
#define ARG_TAINT_FILE                  "--taint-file"
#define ARG_OPAQUE_FILE                 "--opaque-file"
#define ARG_PROCESS                     "--process"
#define ARG_TRACK_PROCESS               "--track-process"
#define ARG_TAINT_PROCESS               "--taint-process"
#define ARG_OPAQUE_PROCESS              "--opaque-process"
#define ARG_TRACK_IPV4_INGRESS          "--track-ipv4-ingress"
#define ARG_TRACK_IPV4_EGRESS           "--track-ipv4-egress"
#define ARG_FILTER_NODE                 "--node-filter"
#define ARG_FILTER_EDGE                 "--edge-filter"
#define ARG_PROPAGATE_FILTER_NODE       "--node-propagate-filter"
#define ARG_PROPAGATE_FILTER_EDGE       "--edge-propagate-filter"
#define ARG_FILTER_RESET                "--reset-filter"
#define ARG_SECCTX_FILTER               "--track-secctx"
#define ARG_CGROUP_FILTER               "--track-cgroup"
#define ARG_USER_FILTER                 "--track-user"
#define ARG_GROUP_FILTER                "--track-group"
#define ARG_EPOCH                       "--change-epoch"
#define ARG_DROPPED                     "--drop"

#define ANSI_COLOR_RED     "\x1b[31m"
#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_YELLOW  "\x1b[33m"
#define ANSI_COLOR_BLUE    "\x1b[34m"
#define ANSI_COLOR_MAGENTA "\x1b[35m"
#define ANSI_COLOR_CYAN    "\x1b[36m"
#define ANSI_COLOR_RESET   "\x1b[0m"

#define CMD_COLORED ANSI_COLOR_GREEN "%s" ANSI_COLOR_RESET
#define CMD_PARAMETER(str) " " ANSI_COLOR_YELLOW "<" str ">" ANSI_COLOR_RESET
#define CMD_WARNING(str) ANSI_COLOR_RED str ANSI_COLOR_RESET

void usage( void ){
    printf(CMD_COLORED "\n usage.\n\n", ARG_HELP);
    printf(CMD_COLORED "\n version.\n\n", ARG_VERSION);
    printf(CMD_COLORED "\n print provenance capture state.\n\n", ARG_STATE);
    printf(CMD_COLORED "\n print out current configuration (can copy content in /etc/camflow.ini).\n\n", ARG_CONFIG);
    printf(CMD_COLORED CMD_PARAMETER("bool") "\n enable/disable provenance capture.\n\n", ARG_ENABLE);
    printf(CMD_COLORED CMD_PARAMETER("bool") "\n activate/deactivate whole-system provenance capture.\n\n", ARG_ALL);
    printf(CMD_COLORED CMD_PARAMETER("bool") "\n activate/deactivate node compression.\n\n", ARG_COMPRESS_NODE);
    printf(CMD_COLORED CMD_PARAMETER("bool") "\n activate/deactivate edge compression.\n\n", ARG_COMPRESS_EDGE);
    printf(CMD_COLORED CMD_PARAMETER("bool") "\n activate/deactivate duplication.\n\n", ARG_DUPLICATE);
    printf(CMD_COLORED CMD_PARAMETER("filename") "\n display provenance info of a file.\n\n", ARG_FILE);
    printf(CMD_COLORED CMD_PARAMETER("filename") CMD_PARAMETER("false/true/propagate") "\n set tracking.\n\n", ARG_TRACK_FILE);
    printf(CMD_COLORED CMD_PARAMETER("filename") CMD_PARAMETER("int [0-63]") "\n applies taint to the file.\n\n", ARG_TAINT_FILE);
    printf(CMD_COLORED CMD_PARAMETER("filename") CMD_PARAMETER("bool") "\n mark/unmark the file as opaque.\n\n", ARG_OPAQUE_FILE);
    printf(CMD_COLORED CMD_PARAMETER("pid") "\n display provenance info of a process.\n\n", ARG_PROCESS);
    printf(CMD_COLORED CMD_PARAMETER("pid") CMD_PARAMETER("false/true/propagate") "\n set tracking.\n\n", ARG_TRACK_PROCESS);
    printf(CMD_COLORED CMD_PARAMETER("pid") CMD_PARAMETER("int [0-63]") "\n applies taint to the process.\n\n", ARG_TAINT_PROCESS);
    printf(CMD_COLORED CMD_PARAMETER("pid") CMD_PARAMETER("bool") "\n mark/unmark the process as opaque.\n\n", ARG_OPAQUE_PROCESS);
    printf(CMD_COLORED CMD_PARAMETER("ip/mask:port") CMD_PARAMETER("track/propagate/record/delete") "\n track/propagate on bind.\n\n", ARG_TRACK_IPV4_INGRESS);
    printf(CMD_COLORED CMD_PARAMETER("ip/mask:port") CMD_PARAMETER("track/propagate/record/delete") "\n track/propagate on connect.\n\n", ARG_TRACK_IPV4_EGRESS);
    printf(CMD_COLORED CMD_PARAMETER("security context") CMD_PARAMETER("track/propagate/opaque/delete") "\n track/propagate based on security context.\n\n", ARG_SECCTX_FILTER);
    printf(CMD_COLORED CMD_PARAMETER("cgroup ino") CMD_PARAMETER("track/propagate/delete") "\n track/propagate based on cgroup.\n\n", ARG_CGROUP_FILTER);
    printf(CMD_COLORED CMD_PARAMETER("user name") CMD_PARAMETER("track/propagate/opaque/delete") "\n track/propagate based on user.\n\n", ARG_USER_FILTER);
    printf(CMD_COLORED CMD_PARAMETER("group name") CMD_PARAMETER("track/propagate/opaque/delete") "\n track/propagate based on group.\n\n", ARG_GROUP_FILTER);
    printf(CMD_COLORED CMD_PARAMETER("type") CMD_PARAMETER("bool") "\n set node filter.\n\n", ARG_FILTER_NODE);
    printf(CMD_COLORED CMD_PARAMETER("type") CMD_PARAMETER("bool") "\n set edge filter.\n\n", ARG_FILTER_EDGE);
    printf(CMD_COLORED CMD_PARAMETER("type") CMD_PARAMETER("bool") "\n set propagate node filter.\n\n", ARG_PROPAGATE_FILTER_NODE);
    printf(CMD_COLORED CMD_PARAMETER("type") CMD_PARAMETER("bool") "\n set propagate edge filter.\n\n", ARG_PROPAGATE_FILTER_EDGE);
    printf(CMD_COLORED "\n reset filters.\n\n", ARG_FILTER_RESET);
    printf(CMD_COLORED "\n change epoch.\n\n", ARG_EPOCH);
    printf(CMD_COLORED "\n display information about dropped graph elements.\n\n", ARG_DROPPED);
}

#define is_str_track(str) ( strcmp (str, "track") == 0)
#define is_str_delete(str) ( strcmp (str, "delete") == 0)
#define is_str_propagate(str) ( strcmp (str, "propagate") == 0)
#define is_str_opaque(str) ( strcmp (str, "opaque") == 0)
#define is_str_record(str) ( strcmp (str, "record") == 0)
#define is_str_true(str) ( strcmp (str, "true") == 0)
#define is_str_false(str) ( strcmp (str, "false") == 0)

void enable( const char* str ){
    if(!is_str_true(str) && !is_str_false(str)){
        printf("Excepted a boolean, got %s.\n", str);
        return;
    }

    if(provenance_set_enable(is_str_true(str))<0)
        perror("Could not enable/disable provenance capture");
}

void all( const char* str ){
    if(!is_str_true(str) && !is_str_false(str)){
        printf("Excepted a boolean, got %s.\n", str);
        return;
    }

    if(provenance_set_all(is_str_true(str))<0)
        perror("Could not activate/deactivate whole-system provenance capture");
}

void should_compress_node( const char* str ){
    if(!is_str_true(str) && !is_str_false(str)){
        printf("Excepted a boolean, got %s.\n", str);
        return;
    }

    if(provenance_should_compress_node(is_str_true(str))<0)
        perror("Could not activate/deactivate node compression.");
}

void should_compress_edge( const char* str ){
    if(!is_str_true(str) && !is_str_false(str)){
        printf("Excepted a boolean, got %s.\n", str);
        return;
    }

    if(provenance_should_compress_edge(is_str_true(str))<0)
        perror("Could not activate/deactivate edge compression.");
}

void should_duplicate( const char* str ){
    if(!is_str_true(str) && !is_str_false(str)){
        printf("Excepted a boolean, got %s.\n", str);
        return;
    }

    if(provenance_should_duplicate(is_str_true(str))<0)
        perror("Could not activate/deactivate duplication.");
}

void print_policy_hash( void ){
    int size;
    int i;
    uint8_t buffer[256];

    size = provenance_policy_hash(buffer, 256);
    for(i=0; i<size; i++)
        printf("%0X", buffer[i]);
    printf("\n");
}

void state( void ){
    uint64_t filter=0;
    struct prov_ipv4_filter filters[100];
    struct secinfo sec_filters[100];
    struct nsinfo ns_filters[100];
    struct userinfo user_filters[100];
    struct passwd* pwd;
    struct groupinfo group_filters[100];
    struct group* grp;
    uint32_t machine_id;
    char *buf;
    uint64_t id;
    int size;
    int i;

    provenance_get_machine_id(&machine_id);
    printf("Machine id: %u\n", machine_id);

    printf("Policy hash: ");
    print_policy_hash();

    printf("Provenance capture:\n");
    if(provenance_get_enable())
        printf("- capture enabled;\n");
    else
        printf("- capture disabled;\n");

    if( provenance_get_all() )
        printf("- all enabled;\n");
    else
        printf("- all disabled;\n");

    if( provenance_was_written() )
        printf("- provenance has been captured;\n");
    else
        printf("- provenance was not captured;\n");

    if( provenance_does_compress_node() )
        printf("- node compression enabled;\n");
    else
        printf("- node compression disabled;\n");

    if( provenance_does_compress_edge() )
        printf("- edge compression enabled;\n");
    else
        printf("- edge compression disabled;\n");

    if( provenance_does_duplicate() )
        printf("- duplication enabled;\n");
    else
        printf("- duplication disabled;\n");

    provenance_get_node_filter(&filter);
    printf("\nNode filter (%0lx):\n", filter);
    for (i = 0; i < 32; i++){
        id = 1 << i;
        if ((id & filter) != 0){
            buf = node_id_to_str(DM_ACTIVITY|id);
            if (strcmp("unknown", buf)!=0) {
                printf("%s\n", buf);
                continue;
            }
            buf = node_id_to_str(DM_AGENT|id);
            if (strcmp("unknown", buf)!=0) {
                printf("%s\n", buf);
                continue;
            }
            buf = node_id_to_str(DM_ENTITY|id);
            if (strcmp("unknown", buf)!=0) {
                printf("%s\n", buf);
                continue;
            }
        }
    }

    provenance_get_derived_filter(&filter);
    printf("Derived filter (%0lx):\n", filter);
    for (i = 0; i < 32; i++){
        id = 1 << i;
        if ((id & filter) != 0){
            buf = relation_id_to_str(RL_DERIVED|id);
            if (strcmp("unknown", buf)!=0) {
                printf("%s\n", buf);
                continue;
            }
        }
    }

    provenance_get_generated_filter(&filter);
    printf("Generated filter (%0lx):\n", filter);
    for (i = 0; i < 32; i++){
        id = 1 << i;
        if ((id & filter) != 0){
            buf = relation_id_to_str(RL_GENERATED|id);
            if (strcmp("unknown", buf)!=0) {
                printf("%s\n", buf);
                continue;
            }
        }
    }

    provenance_get_used_filter(&filter);
    printf("Used filter (%0lx):\n", filter);
    for (i = 0; i < 32; i++){
        id = 1 << i;
        if ((id & filter) != 0){
            buf = relation_id_to_str(RL_USED|id);
            if (strcmp("unknown", buf)!=0) {
                printf("%s\n", buf);
                continue;
            }
        }
    }

    provenance_get_informed_filter(&filter);
    printf("Informed filter (%0lx):\n", filter);
    for (i = 0; i < 32; i++){
        id = 1 << i;
        if ((id & filter) != 0){
            buf = relation_id_to_str(RL_INFORMED|id);
            if (strcmp("unknown", buf)!=0) {
                printf("%s\n", buf);
                continue;
            }
        }
    }
    printf("\n");

    provenance_get_propagate_node_filter(&filter);
    printf("Propagate node filter (%0lx):\n", filter);
    for (i = 0; i < 32; i++){
        id = 1 << i;
        if ((id & filter) != 0){
            buf = node_id_to_str(DM_ACTIVITY|id);
            if (strcmp("unknown", buf)!=0) {
                printf("%s\n", buf);
                continue;
            }
            buf = node_id_to_str(DM_AGENT|id);
            if (strcmp("unknown", buf)!=0) {
                printf("%s\n", buf);
                continue;
            }
            buf = node_id_to_str(DM_ENTITY|id);
            if (strcmp("unknown", buf)!=0) {
                printf("%s\n", buf);
                continue;
            }
        }
    }

    provenance_get_propagate_derived_filter(&filter);
    printf("Propagate derived filter (%0lx):\n", filter);
    for (i = 0; i < 32; i++){
        id = 1 << i;
        if ((id & filter) != 0){
            buf = relation_id_to_str(RL_DERIVED|id);
            if (strcmp("unknown", buf)!=0) {
                printf("%s\n", buf);
                continue;
            }
        }
    }

    provenance_get_propagate_generated_filter(&filter);
    printf("Propagate generated filter (%0lx):\n", filter);
    for (i = 0; i < 32; i++){
        id = 1 << i;
        if ((id & filter) != 0){
            buf = relation_id_to_str(RL_GENERATED|id);
            if (strcmp("unknown", buf)!=0) {
                printf("%s\n", buf);
                continue;
            }
        }
    }

    provenance_get_propagate_used_filter(&filter);
    printf("Propagate used filter (%0lx):\n", filter);
    for (i = 0; i < 32; i++){
        id = 1 << i;
        if ((id & filter) != 0){
            buf = relation_id_to_str(RL_USED|id);
            if (strcmp("unknown", buf)!=0) {
                printf("%s\n", buf);
                continue;
            }
        }
    }

    provenance_get_propagate_informed_filter(&filter);
    printf("Propagate informed filter (%0lx):\n", filter);
    for (i = 0; i < 32; i++){
        id = 1 << i;
        if ((id & filter) != 0){
            buf = relation_id_to_str(RL_INFORMED|id);
            if (strcmp("unknown", buf)!=0) {
                printf("%s\n", buf);
                continue;
            }
        }
    }
    printf("\n");

    size = provenance_ingress_ipv4(filters, 100*sizeof(struct prov_ipv4_filter));
    printf("IPv4 ingress filter (%ld).\n", size/sizeof(struct prov_ipv4_filter));
    for(i = 0; i < size/sizeof(struct prov_ipv4_filter); i++){
        printf("%s", uint32_to_ipv4str(filters[i].ip));
        printf("/%d", count_set_bits(filters[i].mask));
        printf(":%d ", ntohs(filters[i].port));

        if((filters[i].op&PROV_SET_PROPAGATE) == PROV_SET_PROPAGATE)
            printf("propagate");
        else if((filters[i].op&PROV_SET_TRACKED) == PROV_SET_TRACKED)
            printf("track");

        if((filters[i].op&PROV_SET_RECORD) == PROV_SET_RECORD)
            printf(" record");
        printf("\n");
    }

    size = provenance_egress_ipv4(filters, 100*sizeof(struct prov_ipv4_filter));
    printf("IPv4 egress filter (%ld).\n", size/sizeof(struct prov_ipv4_filter));
    for(i = 0; i < size/sizeof(struct prov_ipv4_filter); i++){
        printf("%s", uint32_to_ipv4str(filters[i].ip));
        printf("/%d", count_set_bits(filters[i].mask));
        printf(":%d ", ntohs(filters[i].port));

        if((filters[i].op&PROV_SET_PROPAGATE) == PROV_SET_PROPAGATE)
            printf("propagate");
        else if((filters[i].op&PROV_SET_TRACKED) == PROV_SET_TRACKED)
            printf("track");

        if((filters[i].op&PROV_SET_RECORD) == PROV_SET_RECORD)
            printf(" record");
        printf("\n");
    }

    size = provenance_secctx(sec_filters, 100*sizeof(struct secinfo));
    printf("Security context filter (%ld).\n", size/sizeof(struct secinfo));
    for(i = 0; i < size/sizeof(struct secinfo); i++){
        printf("%s ", sec_filters[i].secctx);
        if((sec_filters[i].op&PROV_SET_PROPAGATE) == PROV_SET_PROPAGATE)
            printf("propagate");
        else if((sec_filters[i].op&PROV_SET_TRACKED) == PROV_SET_TRACKED)
            printf("track");
        printf("\n");
    }

    size = provenance_ns(ns_filters, 100*sizeof(struct nsinfo));
    printf("Namespace filter (%ld).\n", size/sizeof(struct nsinfo));
    for(i = 0; i < size/sizeof(struct nsinfo); i++){
        printf("%u ", ns_filters[i].cgroupns);
        if((ns_filters[i].op&PROV_SET_PROPAGATE) == PROV_SET_PROPAGATE)
            printf("propagate");
        else if((ns_filters[i].op&PROV_SET_TRACKED) == PROV_SET_TRACKED)
            printf("track");
        printf("\n");
    }

    size = provenance_user(user_filters, 100*sizeof(struct userinfo));
    printf("User filter (%ld).\n", size/sizeof(struct userinfo));
    for(i = 0; i < size/sizeof(struct userinfo); i++){
        pwd = getpwuid(user_filters[i].uid);
        printf("%s ", pwd->pw_name);
        if((user_filters[i].op&PROV_SET_PROPAGATE) == PROV_SET_PROPAGATE)
            printf("propagate");
        else if((user_filters[i].op&PROV_SET_TRACKED) == PROV_SET_TRACKED)
            printf("track");
        else if((user_filters[i].op&PROV_SET_OPAQUE) == PROV_SET_OPAQUE)
            printf("opaque");
        printf("\n");
    }

    size = provenance_group(group_filters, 100*sizeof(struct groupinfo));
    printf("Group filter (%ld).\n", size/sizeof(struct groupinfo));
    for(i = 0; i < size/sizeof(struct groupinfo); i++){
        grp = getgrgid(group_filters[i].gid);
        printf("%s ", grp->gr_name);
        if((group_filters[i].op&PROV_SET_PROPAGATE) == PROV_SET_PROPAGATE)
            printf("propagate");
        else if((group_filters[i].op&PROV_SET_TRACKED) == PROV_SET_TRACKED)
            printf("track");
        else if((group_filters[i].op&PROV_SET_OPAQUE) == PROV_SET_OPAQUE)
            printf("opaque");
        printf("\n");
    }
}

void print_config(void) {
    int size;
    int i;
    struct prov_ipv4_filter filters[100];
    struct secinfo sec_filters[100];
    struct userinfo user_filters[100];
    struct passwd* pwd;
    struct groupinfo group_filters[100];
    struct group* grp;
    char *buf;
    uint64_t filter=0;
    uint64_t id;

    printf(";Auto-generated configuration\n");
    printf("[provenance]\n");
    printf("machine_id=0\n");
    printf("enabled=");
    if(provenance_get_enable())
        printf("true\n");
    else
        printf("false\n");
    printf("all=");
    if( provenance_get_all() )
        printf("true\n");
    else
        printf("false\n");
    provenance_get_node_filter(&filter);
    for (i = 0; i < 32; i++){
        id = 1 << i;
        if ((id & filter) != 0){
            buf = node_id_to_str(DM_ACTIVITY|id);
            if (strcmp("unknown", buf)!=0) {
                printf("node_filter=%s\n", buf);
                continue;
            }
            buf = node_id_to_str(DM_AGENT|id);
            if (strcmp("unknown", buf)!=0) {
                printf("node_filter=%s\n", buf);
                continue;
            }
            buf = node_id_to_str(DM_ENTITY|id);
            if (strcmp("unknown", buf)!=0) {
                printf("node_filter=%s\n", buf);
                continue;
            }
        }
    }
    provenance_get_propagate_node_filter(&filter);
    for (i = 0; i < 32; i++){
        id = 1 << i;
        if ((id & filter) != 0){
            buf = node_id_to_str(DM_ACTIVITY|id);
            if (strcmp("unknown", buf)!=0) {
                printf("propagate_node_filter=%s\n", buf);
                continue;
            }
            buf = node_id_to_str(DM_AGENT|id);
            if (strcmp("unknown", buf)!=0) {
                printf("propagate_node_filter=%s\n", buf);
                continue;
            }
            buf = node_id_to_str(DM_ENTITY|id);
            if (strcmp("unknown", buf)!=0) {
                printf("propagate_node_filter=%s\n", buf);
                continue;
            }
        }
    }
    provenance_get_derived_filter(&filter);
    for (i = 0; i < 32; i++){
        id = 1 << i;
        if ((id & filter) != 0){
            buf = relation_id_to_str(RL_DERIVED|id);
            if (strcmp("unknown", buf)!=0) {
                printf("relation_filter=%s\n", buf);
                continue;
            }
        }
    }
    provenance_get_generated_filter(&filter);
    for (i = 0; i < 32; i++){
        id = 1 << i;
        if ((id & filter) != 0){
            buf = relation_id_to_str(RL_GENERATED|id);
            if (strcmp("unknown", buf)!=0) {
                printf("relation_filter=%s\n", buf);
                continue;
            }
        }
    }
    provenance_get_used_filter(&filter);
    for (i = 0; i < 32; i++){
        id = 1 << i;
        if ((id & filter) != 0){
            buf = relation_id_to_str(RL_USED|id);
            if (strcmp("unknown", buf)!=0) {
                printf("relation_filter=%s\n", buf);
                continue;
            }
        }
    }
    provenance_get_informed_filter(&filter);
    for (i = 0; i < 32; i++){
        id = 1 << i;
        if ((id & filter) != 0){
            buf = relation_id_to_str(RL_INFORMED|id);
            if (strcmp("unknown", buf)!=0) {
                printf("relation_filter=%s\n", buf);
                continue;
            }
        }
    }
    provenance_get_propagate_node_filter(&filter);
    for (i = 0; i < 32; i++){
        id = 1 << i;
        if ((id & filter) != 0){
            buf = node_id_to_str(DM_ACTIVITY|id);
            if (strcmp("unknown", buf)!=0) {
                printf("propagate_node_filter=%s\n", buf);
                continue;
            }
            buf = node_id_to_str(DM_AGENT|id);
            if (strcmp("unknown", buf)!=0) {
                printf("propagate_node_filter=%s\n", buf);
                continue;
            }
            buf = node_id_to_str(DM_ENTITY|id);
            if (strcmp("unknown", buf)!=0) {
                printf("propagate_node_filter=%s\n", buf);
                continue;
            }
        }
    }

    provenance_get_propagate_derived_filter(&filter);
    for (i = 0; i < 32; i++){
        id = 1 << i;
        if ((id & filter) != 0){
            buf = relation_id_to_str(RL_DERIVED|id);
            if (strcmp("unknown", buf)!=0) {
                printf("propagate_relation_filter=%s\n", buf);
                continue;
            }
        }
    }

    provenance_get_propagate_generated_filter(&filter);
    for (i = 0; i < 32; i++){
        id = 1 << i;
        if ((id & filter) != 0){
            buf = relation_id_to_str(RL_GENERATED|id);
            if (strcmp("unknown", buf)!=0) {
                printf("propagate_relation_filter=%s\n", buf);
                continue;
            }
        }
    }

    provenance_get_propagate_used_filter(&filter);
    for (i = 0; i < 32; i++){
        id = 1 << i;
        if ((id & filter) != 0){
            buf = relation_id_to_str(RL_USED|id);
            if (strcmp("unknown", buf)!=0) {
                printf("propagate_relation_filter=%s\n", buf);
                continue;
            }
        }
    }

    provenance_get_propagate_informed_filter(&filter);
    for (i = 0; i < 32; i++){
        id = 1 << i;
        if ((id & filter) != 0){
            buf = relation_id_to_str(RL_INFORMED|id);
            if (strcmp("unknown", buf)!=0) {
                printf("propagate_relation_filter=%s\n", buf);
                continue;
            }
        }
    }

    /* compression configuration */
    printf("\n");
    printf("[compression]\n");
    printf("node=");
    if( provenance_does_compress_node() )
        printf("true\n");
    else
        printf("false\n");
    printf("edge=");
    if( provenance_does_compress_edge() )
        printf("true\n");
    else
        printf("false\n");
    printf("duplicate=");
    if( provenance_does_duplicate() )
        printf("true;\n");
    else
        printf("false\n");

    /* IPV4 ingress */
    printf("\n");
    printf("[ipv4-ingress]\n");
    size = provenance_ingress_ipv4(filters, 100*sizeof(struct prov_ipv4_filter));
    for(i = 0; i < size/sizeof(struct prov_ipv4_filter); i++){
        if((filters[i].op&PROV_SET_PROPAGATE) == PROV_SET_PROPAGATE) {
            printf("propagate=");
            printf("%s", uint32_to_ipv4str(filters[i].ip));
            printf("/%d", count_set_bits(filters[i].mask));
            printf(":%d\n", ntohs(filters[i].port));
        } else if((filters[i].op&PROV_SET_TRACKED) == PROV_SET_TRACKED) {
            printf("track=");
            printf("%s", uint32_to_ipv4str(filters[i].ip));
            printf("/%d", count_set_bits(filters[i].mask));
            printf(":%d\n", ntohs(filters[i].port));
        }
        if((filters[i].op&PROV_SET_RECORD) == PROV_SET_RECORD){
            printf("record=");
            printf("%s", uint32_to_ipv4str(filters[i].ip));
            printf("/%d", count_set_bits(filters[i].mask));
            printf(":%d\n", ntohs(filters[i].port));
        }
    }

    /* IPV4 ingress */
    printf("\n");
    printf("[ipv4-egress]\n");
    size = provenance_egress_ipv4(filters, 100*sizeof(struct prov_ipv4_filter));
    for(i = 0; i < size/sizeof(struct prov_ipv4_filter); i++){
        if((filters[i].op&PROV_SET_PROPAGATE) == PROV_SET_PROPAGATE) {
            printf("propagate=");
            printf("%s", uint32_to_ipv4str(filters[i].ip));
            printf("/%d", count_set_bits(filters[i].mask));
            printf(":%d\n", ntohs(filters[i].port));
        } else if((filters[i].op&PROV_SET_TRACKED) == PROV_SET_TRACKED) {
            printf("track=");
            printf("%s", uint32_to_ipv4str(filters[i].ip));
            printf("/%d", count_set_bits(filters[i].mask));
            printf(":%d\n", ntohs(filters[i].port));
        }
        if((filters[i].op&PROV_SET_RECORD) == PROV_SET_RECORD){
            printf("record=");
            printf("%s", uint32_to_ipv4str(filters[i].ip));
            printf("/%d", count_set_bits(filters[i].mask));
            printf(":%d\n", ntohs(filters[i].port));
        }
    }

    /* user */
    printf("\n");
    printf("[user]\n");
    size = provenance_user(user_filters, 100*sizeof(struct userinfo));
    for(i = 0; i < size/sizeof(struct userinfo); i++){
        if((user_filters[i].op&PROV_SET_PROPAGATE) == PROV_SET_PROPAGATE)
            printf("propagate=");
        else if((user_filters[i].op&PROV_SET_TRACKED) == PROV_SET_TRACKED)
            printf("track=");
        else if((user_filters[i].op&PROV_SET_OPAQUE) == PROV_SET_OPAQUE)
            printf("opaque=");
        pwd = getpwuid(user_filters[i].uid);
        printf("%s\n", pwd->pw_name);
    }

    /* user */
    printf("\n");
    printf("[group]\n");
    size = provenance_group(group_filters, 100*sizeof(struct groupinfo));
    for(i = 0; i < size/sizeof(struct groupinfo); i++){
        grp = getgrgid(group_filters[i].gid);
        if((group_filters[i].op&PROV_SET_PROPAGATE) == PROV_SET_PROPAGATE)
            printf("propagate=");
        else if((group_filters[i].op&PROV_SET_TRACKED) == PROV_SET_TRACKED)
            printf("track=");
        else if((group_filters[i].op&PROV_SET_OPAQUE) == PROV_SET_OPAQUE)
            printf("opaque=");
        printf("%s\n", grp->gr_name);
    }

    /* secctx */
    printf("\n");
    printf("[secctx]\n");
    size = provenance_secctx(sec_filters, 100*sizeof(struct secinfo));
    for(i = 0; i < size/sizeof(struct secinfo); i++){
        if((sec_filters[i].op&PROV_SET_PROPAGATE) == PROV_SET_PROPAGATE)
            printf("propagate=");
        else if((sec_filters[i].op&PROV_SET_TRACKED) == PROV_SET_TRACKED)
            printf("track=");
        printf("%s\n", sec_filters[i].secctx);
    }
}

void print_version(){
    char buffer[256];
    provenance_version(buffer, 256);
    printf("CamFlow %s\n", buffer);
    provenance_commit(buffer, 256);
    printf("https://github.com/camflow/camflow-dev/commit/%s\n\n", buffer);
    provenance_lib_version(buffer, 256);
    printf("libprovenance %s\n", buffer);
    provenance_lib_commit(buffer, 256);
    printf("https://github.com/camflow/libprovenance/commit/%s\n\n", buffer);
}

void file( const char* path){
    union prov_elt inode_info;
    char id[PROV_ID_STR_LEN];
    int err;

    err = provenance_read_file(path, &inode_info);
    if(err < 0){
        perror("Could not read file provenance information.\n");
        exit(-1);
    }

    ID_ENCODE(prov_id_buffer(&inode_info), PROV_IDENTIFIER_BUFFER_LENGTH, id, PROV_ID_STR_LEN);
    printf("Identifier: %s\n", id);
    printf("Type: %s\n", node_id_to_str(node_identifier(&inode_info).type));
    printf("ID: %lu\n", node_identifier(&inode_info).id);
    printf("Boot ID: %u\n", node_identifier(&inode_info).boot_id);
    printf("Machine ID: %u\n", node_identifier(&inode_info).machine_id);
    printf("Version: %u\n", node_identifier(&inode_info).version);
    printf("Taint: %0X\n", prov_taint(&inode_info));
    printf("\n");
    if( provenance_is_tracked(&inode_info) )
        printf("File is tracked.\n");
    else
        printf("File is not tracked.\n");

    if( provenance_is_opaque(&inode_info) )
        printf("File is opaque.\n");
    else
        printf("File is not opaque.\n");

    if( provenance_does_propagate(&inode_info) )
        printf("File propagates tracking.\n");
    else
        printf("File is not propagating tracking.\n");
}

void process(uint32_t pid){
    union prov_elt process_info;
    char id[PROV_ID_STR_LEN];
    int err;

    err = provenance_read_process(pid, &process_info);
    if(err < 0){
        perror("Could not read process provenance information.\n");
        exit(-1);
    }

    ID_ENCODE(prov_id_buffer(&process_info), PROV_IDENTIFIER_BUFFER_LENGTH, id, PROV_ID_STR_LEN);
    printf("Identifier: %s\n", id);
    printf("Type: %lu\n", node_identifier(&process_info).type);
    printf("ID: %lu\n", node_identifier(&process_info).id);
    printf("Boot ID: %u\n", node_identifier(&process_info).boot_id);
    printf("Machine ID: %u\n", node_identifier(&process_info).machine_id);
    printf("Taint: %0X\n", prov_taint(&process_info));
    printf("\n");
    if( provenance_is_tracked(&process_info) )
        printf("Process is tracked.\n");
    else
        printf("Process is not tracked.\n");

    if( provenance_is_opaque(&process_info) )
        printf("Process is opaque.\n");
    else
        printf("Process is not opaque.\n");

    if( provenance_does_propagate(&process_info) )
        printf("Process propagates tracking.\n");
    else
        printf("Process is not propagating tracking.\n");
}

void print_dropped_info (void) {
    struct dropped drop;
    provenance_dropped(&drop);
    printf("Graph elements dropped: \t\t%lu\n", drop.s);
}

#define CHECK_ATTR_NB(argc, min) if(argc < min){ usage();exit(-1);}
#define MATCH_ARGS(str1, str2) if(strcmp(str1, str2 )==0)

int main(int argc, char *argv[]){
    int err=0;
    int taint_bit = 0;
    uint64_t id, taint;

    if(!provenance_is_present()){
        printf(ANSI_COLOR_RED"It appears CamFlow has not been installed on your machine.\n");
        printf("Please verify you are booted under the correct kernel version\n"ANSI_COLOR_RESET);
        exit(-1);
    }

    CHECK_ATTR_NB(argc, 2);
    // do it properly, but that will do for now

    MATCH_ARGS(argv[1], ARG_HELP){
        usage();
        return 0;
    }
    MATCH_ARGS(argv[1], ARG_CONFIG){
        print_config();
        return 0;
    }
    MATCH_ARGS(argv[1], ARG_VERSION){
        print_version();
        return 0;
    }
    MATCH_ARGS(argv[1], ARG_STATE){
        state();
        return 0;
    }
    MATCH_ARGS(argv[1], ARG_ENABLE){
        CHECK_ATTR_NB(argc, 3);
        enable(argv[2]);
        return 0;
    }
    MATCH_ARGS(argv[1], ARG_ALL){
        CHECK_ATTR_NB(argc, 3);
        all(argv[2]);
        return 0;
    }
    MATCH_ARGS(argv[1], ARG_POLICY){
        CHECK_ATTR_NB(argc, 2);
        print_policy_hash();
        return 0;
    }
    MATCH_ARGS(argv[1], ARG_COMPRESS_NODE){
        CHECK_ATTR_NB(argc, 3);
        should_compress_node(argv[2]);
        return 0;
    }
    MATCH_ARGS(argv[1], ARG_COMPRESS_EDGE){
        CHECK_ATTR_NB(argc, 3);
        should_compress_edge(argv[2]);
        return 0;
    }
    MATCH_ARGS(argv[1], ARG_DUPLICATE){
        CHECK_ATTR_NB(argc, 3);
        should_duplicate(argv[2]);
        return 0;
    }
    MATCH_ARGS(argv[1], ARG_EPOCH){
        CHECK_ATTR_NB(argc, 2);
        provenance_change_epoch();
        return 0;
    }
    MATCH_ARGS(argv[1], ARG_DROPPED){
        CHECK_ATTR_NB(argc, 2);
        print_dropped_info();
        return 0;
    }
    MATCH_ARGS(argv[1], ARG_FILE){
        CHECK_ATTR_NB(argc, 3);
        file(argv[2]);
        return 0;
    }
    MATCH_ARGS(argv[1], ARG_TRACK_FILE){
        CHECK_ATTR_NB(argc, 4);
        if( is_str_propagate(argv[3]) ){
            err = provenance_propagate_file(argv[2], true);
        }else {
            err = provenance_track_file(argv[2], is_str_true(argv[3]));
            if(err < 0)
                perror("Could not change tracking settings for this file.\n");
            if(!is_str_true(argv[3]))
                err = provenance_propagate_file(argv[2], false);
        }
        if(err < 0)
            perror("Could not change tracking settings for this file.\n");
        return 0;
    }
    MATCH_ARGS(argv[1], ARG_TAINT_FILE){
        CHECK_ATTR_NB(argc, 4);
        taint_bit = atoi(argv[3]);
        if(taint_bit > 63 || taint_bit < 0)
            perror("Tag bit must be set between 0 and 63.\n");
        taint = 1 << taint_bit;
        err = provenance_taint_file(argv[2], taint);
        if(err < 0)
            perror("Could not change taint settings for this file.\n");
        return 0;
    }
    MATCH_ARGS(argv[1], ARG_OPAQUE_FILE){
        CHECK_ATTR_NB(argc, 4);
        err = provenance_opaque_file(argv[2], is_str_true(argv[3]));
        if(err < 0)
            perror("Could not change opacity settings for this file.\n");
        return 0;
    }
    MATCH_ARGS(argv[1], ARG_PROCESS){
        CHECK_ATTR_NB(argc, 3);
        process(atoi(argv[2]));
        return 0;
    }
    MATCH_ARGS(argv[1], ARG_TRACK_PROCESS){
        CHECK_ATTR_NB(argc, 4);
        if( is_str_propagate(argv[3]) ){
            err = provenance_propagate_process(atoi(argv[2]), true);
        }else {
            err = provenance_track_process(atoi(argv[2]), is_str_true(argv[3]));
            if(err < 0)
                perror("Could not change tracking settings for this process.\n");
            if(!is_str_true(argv[3]))
                err = provenance_propagate_process(atoi(argv[2]), false);
        }
        if(err < 0)
            perror("Could not change tracking settings for this process.\n");
        return 0;
    }
    MATCH_ARGS(argv[1], ARG_TAINT_PROCESS){
        CHECK_ATTR_NB(argc, 4);
        taint_bit = atoi(argv[3]);
        if(taint_bit > 63 || taint_bit < 0)
            perror("Tag bit must be set between 0 and 63.\n");
        taint = 1 << taint_bit;
        err = provenance_taint_process(atoi(argv[2]), taint);
        if(err < 0)
            perror("Could not change taint settings for this process.\n");
        return 0;
    }
    MATCH_ARGS(argv[1], ARG_OPAQUE_PROCESS){
        CHECK_ATTR_NB(argc, 4);
        err = provenance_opaque_process(atoi(argv[2]), is_str_true(argv[3]));
        if(err < 0)
            perror("Could not change opacity settings for this process.\n");
        return 0;
    }
    MATCH_ARGS(argv[1], ARG_TRACK_IPV4_INGRESS){
        CHECK_ATTR_NB(argc, 4);
        if( is_str_propagate( argv[3]) )
            err = provenance_ingress_ipv4_propagate(argv[2]);
        else if( is_str_record( argv[3]) )
            err = provenance_ingress_ipv4_record(argv[2]);
        else if( is_str_track(argv[3]))
            err = provenance_ingress_ipv4_track(argv[2]);
        else if( is_str_delete(argv[3]))
            err = provenance_ingress_ipv4_delete(argv[2]);

        if(err < 0)
            perror("Could not change ipv4 ingress.\n");
        else
            printf(CMD_WARNING("Only apply to newly created connection.\n"));
        return 0;
    }
    MATCH_ARGS(argv[1], ARG_TRACK_IPV4_EGRESS){
        CHECK_ATTR_NB(argc, 4);
        if( is_str_propagate( argv[3]) )
            err = provenance_egress_ipv4_propagate(argv[2]);
        else if( is_str_record(argv[3]) )
            err = provenance_egress_ipv4_record(argv[2]);
        else if( is_str_track(argv[3]))
            err = provenance_egress_ipv4_track(argv[2]);
        else if( is_str_delete(argv[3]))
            err = provenance_egress_ipv4_delete(argv[2]);

        if(err < 0)
            perror("Could not change ipv4 egress.\n");
        else
            printf(CMD_WARNING("Only apply to newly created connection.\n"));

        return 0;
    }
    MATCH_ARGS(argv[1], ARG_SECCTX_FILTER){
        CHECK_ATTR_NB(argc, 4);
        if( is_str_propagate( argv[3]) )
            err = provenance_secctx_propagate(argv[2]);
        else if( is_str_track(argv[3]))
            err = provenance_secctx_track(argv[2]);
        else if( is_str_opaque(argv[3]))
            err = provenance_secctx_opaque(argv[2]);
        else if( is_str_delete(argv[3]))
            err = provenance_secctx_delete(argv[2]);

        if(err < 0)
            perror("Could not change security context filter.\n");
        return 0;
    }
    MATCH_ARGS(argv[1], ARG_CGROUP_FILTER){
        CHECK_ATTR_NB(argc, 4);
        if( is_str_propagate( argv[3]) )
            err = provenance_cgroup_propagate(strtoul(argv[2], NULL, 0));
        else if( is_str_track(argv[3]))
            err = provenance_cgroup_track(strtoul(argv[2], NULL, 0));
        else if( is_str_delete(argv[3]))
            err = provenance_cgroup_delete(strtoul(argv[2], NULL, 0));

        if(err < 0)
            perror("Could not change CGroup filter.\n");
        return 0;
    }
    MATCH_ARGS(argv[1], ARG_USER_FILTER){
        CHECK_ATTR_NB(argc, 4);
        if( is_str_propagate( argv[3]) )
            err = provenance_user_propagate(argv[2]);
        else if( is_str_track(argv[3]))
            err = provenance_user_track(argv[2]);
        else if( is_str_opaque(argv[3]))
            err = provenance_user_opaque(argv[2]);
        else if( is_str_delete(argv[3]))
            err = provenance_user_delete(argv[2]);

        if(err < 0)
            perror("Could not change user filter.\n");
        return 0;
    }
    MATCH_ARGS(argv[1], ARG_GROUP_FILTER){
        CHECK_ATTR_NB(argc, 4);
        if( is_str_propagate( argv[3]) )
            err = provenance_group_propagate(argv[2]);
        else if( is_str_track(argv[3]))
            err = provenance_group_track(argv[2]);
        else if( is_str_opaque(argv[3]))
            err = provenance_group_opaque(argv[2]);
        else if( is_str_delete(argv[3]))
            err = provenance_group_delete(argv[2]);

        if(err < 0)
            perror("Could not change group filter.\n");
        return 0;
    }
    MATCH_ARGS(argv[1], ARG_FILTER_NODE){
        CHECK_ATTR_NB(argc, 4);
        id = node_str_to_id(argv[2], 256);
        if(id == 0){
            printf("Error invalid node type\n");
            exit(-1);
        }
        if(is_str_true(argv[3]))
            err = provenance_add_node_filter(id);
        else
            err = provenance_remove_node_filter(id);

        if(err < 0)
            perror("Could not change filter settings for this file.\n");
        return 0;
    }
    MATCH_ARGS(argv[1], ARG_FILTER_EDGE){
        CHECK_ATTR_NB(argc, 4);
        id = relation_str_to_id(argv[2], 256);
        if(id == 0){
            printf("Error invalid relation type\n");
            exit(-1);
        }
        if(is_str_true(argv[3]))
            err = provenance_add_relation_filter(id);
        else
            err = provenance_remove_relation_filter(id);

        if(err < 0)
            perror("Could not change filter settings for this file.\n");
        return 0;
    }
    MATCH_ARGS(argv[1], ARG_PROPAGATE_FILTER_NODE){
        CHECK_ATTR_NB(argc, 4);
        id = node_str_to_id(argv[2], 256);
        if(id == 0){
            printf("Error invalid node type\n");
            exit(-1);
        }
        if(is_str_true(argv[3]))
            err = provenance_add_propagate_node_filter(id);
        else
            err = provenance_remove_propagate_node_filter(id);

        if(err < 0)
            perror("Could not change propagation settings for this file.\n");
        return 0;
    }
    MATCH_ARGS(argv[1], ARG_PROPAGATE_FILTER_EDGE){
        CHECK_ATTR_NB(argc, 4);
        id = relation_str_to_id(argv[2], 256);
        if(id == 0){
            printf("Error invalid relation type\n");
            exit(-1);
        }
        if(is_str_true(argv[3]))
            err = provenance_add_propagate_relation_filter(id);
        else
            err = provenance_remove_propagate_relation_filter(id);

        if(err < 0)
            perror("Could not change propagation settings for this file.\n");
        return 0;
    }
    MATCH_ARGS(argv[1], ARG_FILTER_RESET){
        err = provenance_reset_node_filter();
        if(err < 0)
            perror("Could not reset the filters.\n");
        err = provenance_reset_propagate_node_filter();
        if(err < 0)
            perror("Could not reset the filters.\n");
        err = provenance_reset_relation_filter();
        if(err < 0)
            perror("Could not reset the filters.\n");
        err = provenance_reset_propagate_relation_filter();
        if(err < 0)
            perror("Could not reset the filters.\n");
        return 0;
    }
    usage();
    return 0;
}