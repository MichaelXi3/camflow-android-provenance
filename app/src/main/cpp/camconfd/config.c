/*
*
* Author: Thomas Pasquier <thomas.pasquier@bristol.ac.uk>
*
* Copyright (C) 2015-2016 University of Cambridge
* Copyright (C) 2016-2017 Harvard University
* Copyright (C) 2017-2018 University of Cambridge
* Copyright (C) 2018-2019 University of Bristol
*
* This program is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License version 2, as
* published by the Free Software Foundation.
*
*/
#include "camconf.h"

struct configuration{
    uint32_t machine_id;
    uint32_t boot_id;
    bool enabled;
    bool all;
    bool node_compress;
    bool edge_compress;
    bool duplicate;
    declare_filter(opaque, PATH_MAX);
    declare_filter(tracked, PATH_MAX);
    declare_filter(propagate, PATH_MAX);
    declare_filter(node_filter, MAX_NAME);
    declare_filter(relation_filter, MAX_NAME);
    declare_filter(propagate_node_filter, MAX_NAME);
    declare_filter(propagate_relation_filter, MAX_NAME);
    declare_filter(track_user_filter, MAX_NAME);
    declare_filter(propagate_user_filter, MAX_NAME);
    declare_filter(opaque_user_filter, MAX_NAME);
    declare_filter(track_group_filter, MAX_NAME);
    declare_filter(propagate_group_filter, MAX_NAME);
    declare_filter(opaque_group_filter, MAX_NAME);
    declare_filter(track_ipv4_ingress_filter, MAX_IP_SIZE);
    declare_filter(propagate_ipv4_ingress_filter, MAX_IP_SIZE);
    declare_filter(record_ipv4_ingress_filter, MAX_IP_SIZE);
    declare_filter(track_ipv4_egress_filter, MAX_IP_SIZE);
    declare_filter(propagate_ipv4_egress_filter, MAX_IP_SIZE);
    declare_filter(record_ipv4_egress_filter, MAX_IP_SIZE);
    declare_filter(track_secctx_filter, MAX_NAME);
    declare_filter(propagate_secctx_filter, MAX_NAME);
    declare_filter(opaque_secctx_filter, MAX_NAME);
};

static int handler(void* user, const char* section, const char* name,
                   const char* value)
{
    struct configuration* pconfig = (struct configuration*)user;

    if(MATCH("provenance", "machine_id")) {
        pconfig->machine_id = atoi(value);
    } else if (MATCH("provenance", "enabled")) {
        if(TRUE(value))
            pconfig->enabled = true;
        else
            pconfig->enabled = false;
    } else if(MATCH("provenance", "all")) {
        if(TRUE(value))
            pconfig->all = true;
        else
            pconfig->all = false;
    } else if(MATCH("compression", "node")) {
        if(TRUE(value))
            pconfig->node_compress = true;
        else
            pconfig->node_compress = false;
    } else if(MATCH("compression", "edge")) {
        if(TRUE(value))
            pconfig->edge_compress = true;
        else
            pconfig->edge_compress = false;
    } else if(MATCH("compression", "duplicate")) {
        if(TRUE(value))
            pconfig->duplicate = true;
        else
            pconfig->duplicate = false;
    } else if(MATCH("file", "opaque")){
        ADD_TO_LIST(opaque);
    } else if(MATCH("file", "track")){
        ADD_TO_LIST(tracked);
    } else if(MATCH("file", "propagate")){
        ADD_TO_LIST(propagate);
    } else if(MATCH("provenance", "node_filter")){
        ADD_TO_LIST(node_filter);
    } else if(MATCH("provenance", "relation_filter")){
        ADD_TO_LIST(relation_filter);
    } else if(MATCH("provenance", "propagate_node_filter")){
        ADD_TO_LIST(propagate_node_filter);
    } else if(MATCH("provenance", "propagate_relation_filter")){
        ADD_TO_LIST(propagate_relation_filter);
    } else if(MATCH("user", "track")){
        ADD_TO_LIST(track_user_filter);
    } else if(MATCH("user", "propagate")){
        ADD_TO_LIST(propagate_user_filter);
    } else if(MATCH("user", "opaque")){
        ADD_TO_LIST(opaque_user_filter);
    } else if(MATCH("group", "track")){
        ADD_TO_LIST(track_group_filter);
    } else if(MATCH("group", "propagate")){
        ADD_TO_LIST(propagate_group_filter);
    } else if(MATCH("group", "opaque")){
        ADD_TO_LIST(opaque_group_filter);
    } else if(MATCH("ipv4−ingress", "track")){
        ADD_TO_LIST(track_ipv4_ingress_filter);
    } else if(MATCH("ipv4−ingress", "propagate")){
        ADD_TO_LIST(propagate_ipv4_ingress_filter);
    } else if(MATCH("ipv4−ingress", "record")){
        ADD_TO_LIST(record_ipv4_ingress_filter);
    } else if(MATCH("ipv4−egress", "track")){
        ADD_TO_LIST(track_ipv4_egress_filter);
    } else if(MATCH("ipv4−egress", "propagate")){
        ADD_TO_LIST(propagate_ipv4_egress_filter);
    } else if(MATCH("ipv4−egress", "record")){
        ADD_TO_LIST(record_ipv4_egress_filter);
    } else if(MATCH("secctx", "track")){
        ADD_TO_LIST(track_secctx_filter);
    } else if(MATCH("secctx", "propagate")){
        ADD_TO_LIST(propagate_secctx_filter);
    } else if(MATCH("secctx", "opaque")){
        ADD_TO_LIST(opaque_secctx_filter);
    } else {
        return 0;  /* unknown section/name, error */
    }
    return 1;
}

void print_config(struct configuration* pconfig){
    int i;

    /*
    * PRINT PROVENANCE CONFIGURATION
    */
    if(provenance_is_present()){
        syslog(LOG_INFO, "Config loaded from '%s'", CONFIG_PATH);
        syslog(LOG_INFO, "Provenance machine_id=%u", pconfig->machine_id);
        syslog(LOG_INFO, "Provenance boot_id=%u", pconfig->boot_id);
        syslog(LOG_INFO, "Provenance enabled=%u", pconfig->enabled);
        syslog(LOG_INFO, "Provenance all=%u", pconfig->all);
        syslog(LOG_INFO, "Provenance node_compress=%u", pconfig->node_compress);
        syslog(LOG_INFO, "Provenance edge_compress=%u", pconfig->edge_compress);
        syslog(LOG_INFO, "Provenance duplicate=%u", pconfig->duplicate);
        LOG_LIST(opaque);
        LOG_LIST(tracked);
        LOG_LIST(propagate);
        LOG_LIST(node_filter);
        LOG_LIST(relation_filter);
        LOG_LIST(propagate_node_filter);
        LOG_LIST(propagate_relation_filter);
        LOG_LIST(track_user_filter);
        LOG_LIST(propagate_user_filter);
        LOG_LIST(opaque_user_filter);
        LOG_LIST(track_group_filter);
        LOG_LIST(propagate_group_filter);
        LOG_LIST(opaque_group_filter);
        LOG_LIST(track_ipv4_ingress_filter);
        LOG_LIST(propagate_ipv4_ingress_filter);
        LOG_LIST(record_ipv4_ingress_filter);
        LOG_LIST(track_ipv4_egress_filter);
        LOG_LIST(propagate_ipv4_egress_filter);
        LOG_LIST(record_ipv4_egress_filter);
        LOG_LIST(track_secctx_filter);
        LOG_LIST(propagate_secctx_filter);
        LOG_LIST(opaque_secctx_filter);
    }
}

uint32_t get_machine_id(void){
    FILE *fptr;
    uint32_t machine_id;
    int rc;

    fptr = fopen(CAMFLOW_MACHINE_ID_FILE, "rb+");
    if(!fptr) //if file does not exist, create it
    {
        fptr = fopen(CAMFLOW_MACHINE_ID_FILE, "wb");
        if(!fptr){
            syslog(LOG_ERR, "Failed opening machine ID file.");
            exit(-1);
        }
        srand(time(NULL)+rand());
        do {
            machine_id = rand();
        }while(machine_id==0);
        fwrite(&machine_id, sizeof(uint32_t), 1, fptr);
    }else{
        rc = fread(&machine_id, sizeof(uint32_t), 1, fptr);
        if(rc<0 && ferror(fptr))
            exit(rc);
    }
    if(fptr)
        fclose(fptr);
    return machine_id;
}

uint32_t get_boot_id(void){
    FILE *fptr;
    uint32_t boot_id=1;
    int rc;

    fptr = fopen(CAMFLOW_BOOT_ID_FILE, "rb+");
    if(!fptr) //if file does not exist, create it
    {
        fptr = fopen(CAMFLOW_BOOT_ID_FILE, "wb");
        if(!fptr){
            syslog(LOG_ERR, "Failed opening machine ID file.");
            exit(-1);
        }
        fwrite(&boot_id, sizeof(uint32_t), 1, fptr);
    }else{
        rc = fread(&boot_id, sizeof(uint32_t), 1, fptr);
        if(rc<0 && ferror(fptr))
            exit(rc);
        boot_id+=1;
        fseek(fptr, 0, SEEK_SET);
        fwrite(&boot_id, sizeof(uint32_t), 1, fptr);
    }
    if(fptr)
        fclose(fptr);
    return boot_id;
}

void apply_config(struct configuration* pconfig){
    int err;
    int i;
    syslog(LOG_INFO, "Applying configuration...");

    /*
    * APPLY PROVENANCE CONFIGURATION
    */
    if(provenance_is_present()){
        syslog(LOG_INFO, "Provenance module presence detected.");
        if(pconfig->machine_id==0)
            pconfig->machine_id=get_machine_id();
        if(err = provenance_set_machine_id(pconfig->machine_id)){
            syslog(LOG_ERR, "Error setting machine ID %d", err);
            exit(-1);
        }
        pconfig->boot_id=get_boot_id();
        if(err = provenance_set_boot_id(pconfig->boot_id)){
            syslog(LOG_ERR, "Error setting boot ID %d", err);
            exit(-1);
        }

        APPLY_LIST_WARNING(opaque, provenance_opaque_file(pconfig->opaque[i], true));

        APPLY_LIST_WARNING(tracked, provenance_track_file(pconfig->tracked[i], true));

        APPLY_LIST_WARNING(propagate, provenance_propagate_file(pconfig->propagate[i], true));

        APPLY_LIST(node_filter, provenance_add_node_filter(node_str_to_id(pconfig->node_filter[i], 256)));

        APPLY_LIST(relation_filter, provenance_add_relation_filter(relation_str_to_id(pconfig->relation_filter[i], 256)));

        APPLY_LIST(propagate_node_filter, provenance_add_propagate_node_filter(node_str_to_id(pconfig->propagate_node_filter[i], 256)));

        APPLY_LIST(propagate_relation_filter, provenance_add_propagate_relation_filter(relation_str_to_id(pconfig->propagate_relation_filter[i], 256)));

        APPLY_LIST(track_user_filter, provenance_user_track(pconfig->track_user_filter[i]));

        APPLY_LIST(propagate_user_filter, provenance_user_propagate(pconfig->propagate_user_filter[i]));

        APPLY_LIST(opaque_user_filter, provenance_user_opaque(pconfig->opaque_user_filter[i]));

        APPLY_LIST(track_group_filter, provenance_group_track(pconfig->track_group_filter[i]));

        APPLY_LIST(propagate_group_filter, provenance_group_propagate(pconfig->propagate_group_filter[i]));

        APPLY_LIST(opaque_group_filter, provenance_group_opaque(pconfig->opaque_group_filter[i]));

        APPLY_LIST(track_ipv4_ingress_filter, provenance_ingress_ipv4_track(pconfig->track_ipv4_ingress_filter[i]));

        APPLY_LIST(propagate_ipv4_ingress_filter, provenance_ingress_ipv4_propagate(pconfig->propagate_ipv4_ingress_filter[i]));

        APPLY_LIST(record_ipv4_ingress_filter, provenance_ingress_ipv4_record(pconfig->record_ipv4_ingress_filter[i]));

        APPLY_LIST(track_ipv4_egress_filter, provenance_egress_ipv4_track(pconfig->track_ipv4_egress_filter[i]));

        APPLY_LIST(propagate_ipv4_egress_filter, provenance_egress_ipv4_propagate(pconfig->propagate_ipv4_egress_filter[i]));

        APPLY_LIST(record_ipv4_egress_filter, provenance_egress_ipv4_record(pconfig->record_ipv4_egress_filter[i]));

        APPLY_LIST(track_secctx_filter, provenance_secctx_track(pconfig->track_secctx_filter[i]));

        APPLY_LIST(propagate_secctx_filter, provenance_secctx_propagate(pconfig->propagate_secctx_filter[i]));

        APPLY_LIST(opaque_secctx_filter, provenance_secctx_opaque(pconfig->opaque_secctx_filter[i]));

        if(err = provenance_set_enable(pconfig->enabled)){
            syslog(LOG_ERR, "Error enabling provenance %d", err);
            exit(-1);
        }

        if(err = provenance_set_all(pconfig->all)){
            syslog(LOG_ERR, "Error with all provenance %d", err);
            exit(-1);
        }

        if(err = provenance_should_compress_node(pconfig->node_compress)){
            syslog(LOG_ERR, "Error with compress_node %d", err);
            exit(-1);
        }

        if(err = provenance_should_compress_edge(pconfig->edge_compress)){
            syslog(LOG_ERR, "Error with compress_edge %d", err);
            exit(-1);
        }

        if(err = provenance_should_duplicate(pconfig->duplicate)){
            syslog(LOG_ERR, "Error with duplicate %d", err);
            exit(-1);
        }
    } else {
        syslog(LOG_ERR, "CamFlow is not running in the kernel.");
    }
}

void _init_logs( void ){
    setlogmask(LOG_UPTO(LOG_INFO));
    openlog(APP_NAME, LOG_CONS | LOG_PID | LOG_NDELAY, LOG_DAEMON);
}

int main( void )
{
    struct configuration config;

    _init_logs();

    // set everything to 0
    memset(&config, 0, sizeof(struct configuration));

    if (ini_parse(CONFIG_PATH, handler, &config) < 0) {
        syslog(LOG_ERR, "Can't load '%s'", CONFIG_PATH);
        exit(-1);
    }

    apply_config(&config);
    print_config(&config);
    return 0;
}