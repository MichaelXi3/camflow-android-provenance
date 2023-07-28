#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <syslog.h>
#include <signal.h>
#include <android/log.h>

// Reference to shared library symbols by include the shared library header files
#include "provenancelib/libprovenance-include/provenance.h"
#include "provenancelib/libprovenance-include/provenance_utils.h"
#include "provenancelib/libprovenance-include/provenanceSPADEJSON.h"

#include "camflowd-include/service-config.h"
#include "camflowd-include/service-log.h"

#define APP_NAME     "camflowd"

void init( void ){
    pid_t tid = gettid();
    syslog(LOG_INFO, "Init audit thread (%d)", tid);
    __android_log_print(ANDROID_LOG_INFO, "provenance_ops_init", "Init audit thread (%d)", tid);
}

void spade_derived(struct relation_struct* relation){
    spade_json_append(derived_to_spade_json(relation));
}

void spade_generated(struct relation_struct* relation){
    spade_json_append(generated_to_spade_json(relation));
}

void spade_used(struct relation_struct* relation){
    spade_json_append(used_to_spade_json(relation));
}

void spade_informed(struct relation_struct* relation){
    spade_json_append(informed_to_spade_json(relation));
}

void spade_influenced(struct relation_struct* relation){
    spade_json_append(influenced_to_spade_json(relation));
}

void spade_associated(struct relation_struct* relation){
    spade_json_append(associated_to_spade_json(relation));
}

void spade_proc(struct proc_prov_struct* proc){
    spade_json_append(proc_to_spade_json(proc));
}

void spade_task(struct task_prov_struct* task){
    spade_json_append(task_to_spade_json(task));
}

void spade_inode(struct inode_prov_struct* inode){
    spade_json_append(inode_to_spade_json(inode));
}

void spade_act_disc(struct disc_node_struct* node){
    spade_json_append(disc_to_spade_json(node));
}

void spade_agt_disc(struct disc_node_struct* node){
    spade_json_append(disc_to_spade_json(node));
}

void spade_ent_disc(struct disc_node_struct* node){
    spade_json_append(disc_to_spade_json(node));
}

void spade_msg(struct msg_msg_struct* msg){
    spade_json_append(msg_to_spade_json(msg));
}

void spade_shm(struct shm_struct* shm){
    spade_json_append(shm_to_spade_json(shm));
}

void spade_packet(struct pck_struct* pck){
    spade_json_append(packet_to_spade_json(pck));
}

void spade_address(struct address_struct* address){
    spade_json_append(addr_to_spade_json(address));
}

void spade_file_name(struct file_name_struct* f_name){
    spade_json_append(pathname_to_spade_json(f_name));
}

void spade_iattr(struct iattr_prov_struct* iattr){
    spade_json_append(iattr_to_spade_json(iattr));
}

void spade_xattr(struct xattr_prov_struct* xattr){
    spade_json_append(xattr_to_spade_json(xattr));
}

void spade_packet_content(struct pckcnt_struct* cnt){
    spade_json_append(pckcnt_to_spade_json(cnt));
}

void spade_arg(struct arg_struct* arg){
    spade_json_append(arg_to_spade_json(arg));
}

void spade_machine(struct machine_struct* m){
    spade_json_append(machine_to_spade_json(m));
}

void log_error(char* error){
    syslog(LOG_ERR, "From library: %s", error);
    __android_log_print(ANDROID_LOG_ERROR, "provenance_ops_log_error", "From library: %s", error);
}

struct provenance_ops ops_null = {
        .init=&init,
        .log_derived=NULL,
        .log_generated=NULL,
        .log_used=NULL,
        .log_informed=NULL,
        .log_influenced=NULL,
        .log_associated=NULL,
        .log_proc=NULL,
        .log_task=NULL,
        .log_inode=NULL,
        .log_str=NULL,
        .log_act_disc=NULL,
        .log_agt_disc=NULL,
        .log_ent_disc=NULL,
        .log_msg=NULL,
        .log_shm=NULL,
        .log_packet=NULL,
        .log_address=NULL,
        .log_file_name=NULL,
        .log_iattr=NULL,
        .log_xattr=NULL,
        .log_packet_content=NULL,
        .log_arg=NULL,
        .log_machine=NULL,
        .log_error=&log_error
};

struct provenance_ops spade_json_ops = {
        .init=&init,
        .log_derived=&spade_derived,
        .log_generated=&spade_generated,
        .log_used=&spade_used,
        .log_informed=&spade_informed,
        .log_influenced=&spade_influenced,
        .log_associated=&spade_associated,
        .log_proc=&spade_proc,
        .log_task=&spade_task,
        .log_inode=&spade_inode,
        .log_str=NULL,
        .log_act_disc=&spade_act_disc,
        .log_agt_disc=&spade_agt_disc,
        .log_ent_disc=&spade_ent_disc,
        .log_msg=&spade_msg,
        .log_shm=&spade_shm,
        .log_packet=&spade_packet,
        .log_address=&spade_address,
        .log_file_name=&spade_file_name,
        .log_iattr=&spade_iattr,
        .log_xattr=&spade_xattr,
        .log_packet_content=&spade_packet_content,
        .log_arg=&spade_arg,
        .log_machine=&spade_machine,
        .log_error=&log_error
};

static inline void __init_syslog(void){
    setlogmask(LOG_UPTO(LOG_INFO));
    openlog(APP_NAME, LOG_CONS | LOG_PID | LOG_NDELAY, LOG_DAEMON);
}

volatile sig_atomic_t terminate = 0;
void term(int signum)
{
    terminate = 1;
    syslog(LOG_INFO, "Shutdown signal received.");
    provenance_relay_stop();
    syslog(LOG_INFO, "Relay stopped.");
    syslog(LOG_INFO, "Service terminated.");
    exit(0);
}

// In this android relayfs daemon, it uses SPADE_JSON format
bool is_spade = false;
int read_relayfs_buffer() {
    int rc;
    char json[4096];
    struct sigaction action;

    // Redirect the term syscalls behavior to term function
    action.sa_handler = term;
    sigaction(SIGTERM, &action, NULL);
    sigaction(SIGQUIT, &action, NULL);
    sigaction(SIGHUP, &action, NULL);

    // System log initialization
    __init_syslog();

    // Read & parse configuration file - camflowd.ini @ /data/local/tmp
    read_config();

    // Check if the format is space json
    if(IS_FORMAT_SPADE_JSON()) {
        __android_log_print(ANDROID_LOG_INFO, "camflowd configuration", "format is: %s\n", __service_config.format);
        is_spade = true;
    }

    // Check if output option is set to log
    if(IS_CONFIG_LOG()) {
        __android_log_print(ANDROID_LOG_INFO, "camflowd configuration", "output option is: %s\n", __service_config.output);
        __android_log_print(ANDROID_LOG_INFO, "camflowd configuration", "log path is: %s\n", __service_config.log);

        // init the log file to be ready for write in
        _init_logs();

        // set SPADE_JSON callback function for print JSON
        if(IS_FORMAT_SPADE_JSON()) {
            set_SPADEJSON_callback(log_print);
            __android_log_print(ANDROID_LOG_INFO, "camflowd configuration", "set_SPADEJSON_callback, done.");
        }
    }

    // Registering audit operations
    if (IS_FORMAT_SPADE_JSON()) {
        rc = provenance_relay_register(&spade_json_ops);
    }

    // Catch failed audit operation registration
    if (rc) {
        syslog(LOG_ERR, "Failed registering audit operation.");
        __android_log_print(ANDROID_LOG_ERROR, "provenance_relay_register", "Failed registering audit operation.");
        exit(rc);
    }

    // Read relayfs byte stream and constantly parsing it until manual termination
    while(!terminate){
        if(!IS_CONFIG_NULL() && IS_FORMAT_SPADE_JSON()) {
            flush_spade_json();
        }
        sleep(1);
    }

    return 0;
}

int main() {
    // camflowd main function
    int i = read_relayfs_buffer();
    return i;
}