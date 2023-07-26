#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <netdb.h>
#include <pthread.h>
#include <time.h>
#include <math.h>
#include <fcntl.h>
#include <sys/utsname.h>

#include "camflow-dev-include/provenance_types.h"

#include "libprovenance-include/provenance.h"
#include "libprovenance-include/provenanceSPADEJSON.h"
#include "libprovenance-include/provenance_utils.h"

#include "provenanceJSONcommon.h"

__thread char buffer[MAX_JSON_BUFFER_LENGTH];
#define BUFFER_LENGTH (MAX_JSON_BUFFER_LENGTH-strnlen(buffer, MAX_JSON_BUFFER_LENGTH))
static __thread char id[PROV_ID_STR_LEN];
static __thread char from[PROV_ID_STR_LEN];
static __thread char to[PROV_ID_STR_LEN];
char date[256];
pthread_rwlock_t  date_lock = PTHREAD_RWLOCK_INITIALIZER;

static inline void __init_node(char* type, char* id, const struct node_identifier* n){
    buffer[0]='\0';
    update_time();
    strncat(buffer, "{", BUFFER_LENGTH);
    __add_string_attribute("type", type, false);
    __add_string_attribute("id", id, true);
    strncat(buffer, ",\"annotations\": {", BUFFER_LENGTH);
    __add_uint64_attribute("object_id", n->id, false);
    __add_string_attribute("object_type", node_id_to_str(n->type), true);
    __add_uint32_attribute("boot_id", n->boot_id, true);
    __add_machine_id(n->machine_id, true);
    __add_uint32_attribute("version", n->version, true);
    __add_date_attribute(true);
}

static inline void __close_node( void ){
    strncat(buffer, "}}\n", BUFFER_LENGTH);
}

static inline void __init_relation(char* type,
                                   char* from,
                                   char* to,
                                   char* id,
                                   const struct relation_identifier* e
) {
    buffer[0]='\0';
    update_time();
    strncat(buffer, "{", BUFFER_LENGTH);
    __add_string_attribute("type", type, false);
    __add_string_attribute("from", from, true);
    __add_string_attribute("to", to, true);
    strncat(buffer, ",\"annotations\": {", BUFFER_LENGTH);
    __add_string_attribute("id", id, false);
    __add_uint64_attribute("relation_id", e->id, true);
    __add_string_attribute("relation_type", relation_id_to_str(e->type), true);
    __add_uint32_attribute("boot_id", e->boot_id, true);
    __add_machine_id(e->machine_id, true);
    __add_date_attribute(true);
}

#define NODE_START(type) ID_ENCODE(n->identifier.buffer, PROV_IDENTIFIER_BUFFER_LENGTH, id, PROV_ID_STR_LEN);\
                    __init_node(type, id, &(n->identifier.node_id));\
                    __add_uint64hex_attribute("cf:taint", n->taint, true);\
                    __add_uint64_attribute("cf:jiffies", n->jiffies, true);\
                    __add_uint32_attribute("cf:epoch", n->epoch, true);

#define NODE_END() __close_node()

#define RELATION_START(type)  ID_ENCODE(e->identifier.buffer, PROV_IDENTIFIER_BUFFER_LENGTH, id, PROV_ID_STR_LEN);\
                        ID_ENCODE(e->snd.buffer, PROV_IDENTIFIER_BUFFER_LENGTH, from, PROV_ID_STR_LEN);\
                        ID_ENCODE(e->rcv.buffer, PROV_IDENTIFIER_BUFFER_LENGTH, to, PROV_ID_STR_LEN);\
                        __init_relation(type, to, from, id, &(e->identifier.relation_id));\
                        __add_uint32_attribute("epoch", e->epoch, true);

#define RELATION_END() __close_node()

static inline void __relation_to_spade_json(struct relation_struct* e) {
    __add_uint64_attribute("jiffies", e->jiffies, true);
    if(e->allowed==FLOW_ALLOWED)
        __add_string_attribute("allowed", "true", true);
    else
        __add_string_attribute("allowed", "false", true);
    if(e->set==FILE_INFO_SET && e->offset>0)
        __add_int64_attribute("offset", e->offset, true); // just offset for now
    __add_uint64hex_attribute("flags", e->flags, true);
    __add_uint64_attribute("task_id", e->task_id, true);
    __add_string_attribute("from_type", node_id_to_str(e->rcv.node_id.type), true);
    __add_string_attribute("to_type", node_id_to_str(e->snd.node_id.type), true);
}

char* used_to_spade_json(struct relation_struct* e) {
    RELATION_START("Used");
    __relation_to_spade_json(e);
    RELATION_END();
    return buffer;
}

char* generated_to_spade_json(struct relation_struct* e) {
    RELATION_START("WasGeneratedBy");
    __relation_to_spade_json(e);
    RELATION_END();
    return buffer;
}

char* informed_to_spade_json(struct relation_struct* e) {
    RELATION_START("WasInformedBy");
    __relation_to_spade_json(e);
    RELATION_END();
    return buffer;
}

char* influenced_to_spade_json(struct relation_struct* e) {
    RELATION_START("WasInfluencedBy");
    __relation_to_spade_json(e);
    RELATION_END();
    return buffer;
}

char* associated_to_spade_json(struct relation_struct* e) {
    RELATION_START("WasAssociatedWith");
    __relation_to_spade_json(e);
    RELATION_END();
    return buffer;
}

char* derived_to_spade_json(struct relation_struct* e) {
    RELATION_START("WasDerivedFrom");
    __relation_to_spade_json(e);
    RELATION_END();
    return buffer;
}

char* disc_to_spade_json(struct disc_node_struct* n) {
    buffer['0'];
    return buffer;
}

static __thread  char secctx[PATH_MAX];

char* proc_to_spade_json(struct proc_prov_struct* n) {
    NODE_START("Entity");
    __add_uint32_attribute("uid", n->uid, true);
    __add_uint32_attribute("gid", n->gid, true);
    __add_uint32_attribute("tgid", n->tgid, true);
    provenance_secid_to_secctx(n->secid, secctx, PATH_MAX);
    __add_string_attribute("secctx", secctx, true);
    NODE_END();
    return buffer;
}

char* task_to_spade_json(struct task_prov_struct* n) {
    NODE_START("Activity");
    __add_uint32_attribute("pid", n->pid, true);
    __add_uint32_attribute("vpid", n->vpid, true);
    __add_uint64_attribute("utime", n->utime, true);
    __add_uint64_attribute("stime", n->stime, true);
    __add_uint64_attribute("vm", n->vm, true);
    __add_uint64_attribute("rss", n->rss, true);
    __add_uint64_attribute("hw_vm", n->hw_vm, true);
    __add_uint64_attribute("hw_rss", n->hw_rss, true);
    __add_uint64_attribute("rbytes", n->rbytes, true);
    __add_uint64_attribute("wbytes", n->wbytes, true);
    __add_uint64_attribute("cancel_wbytes", n->cancel_wbytes, true);
    __add_uint32_attribute("utsns", n->utsns, true);
    __add_uint32_attribute("ipcns", n->ipcns, true);
    __add_uint32_attribute("mntns", n->mntns, true);
    __add_uint32_attribute("pidns", n->pidns, true);
    __add_uint32_attribute("netns", n->netns, true);
    __add_uint32_attribute("cgroupns", n->cgroupns, true);
    provenance_secid_to_secctx(n->secid, secctx, PATH_MAX);
    __add_string_attribute("secctx", secctx, true);
    NODE_END();
    return buffer;
}

static __thread char uuid[UUID_STR_SIZE];

char* inode_to_spade_json(struct inode_prov_struct* n) {
    NODE_START("Entity");
    __add_uint32_attribute("uid", n->uid, true);
    __add_uint32_attribute("gid", n->gid, true);
    __add_uint32hex_attribute("mode", n->mode, true);
    provenance_secid_to_secctx(n->secid, secctx, PATH_MAX);
    __add_string_attribute("secctx", secctx, true);
    __add_uint32_attribute("ino", n->ino, true);
    __add_string_attribute("uuid", uuid_to_str(n->sb_uuid, uuid, UUID_STR_SIZE), true);
    NODE_END();
    return buffer;
}

char* sb_to_spade_json(struct sb_struct* n) {
    NODE_START("Entity");
    __add_string_attribute("cf:uuid", uuid_to_str(n->uuid, uuid, UUID_STR_SIZE), true);
    NODE_END();
    return buffer;
}

char* msg_to_spade_json(struct msg_msg_struct* n) {
    NODE_START("Entity");
    NODE_END();
    return buffer;
}

char* shm_to_spade_json(struct shm_struct* n) {
    NODE_START("Entity");
    __add_uint32hex_attribute("cf:mode", n->mode, true);
    NODE_END();
    return buffer;
}

char* packet_to_spade_json(struct pck_struct* n) {
    ID_ENCODE(n->identifier.buffer, PROV_IDENTIFIER_BUFFER_LENGTH, id, PROV_ID_STR_LEN);
    buffer[0]='\0';
    update_time();
    strncat(buffer, "{", BUFFER_LENGTH);
    __add_string_attribute("type", "Entity", false);
    __add_string_attribute("id", id, true);
    strncat(buffer, ",\"annotations\": {", BUFFER_LENGTH);
    __add_string_attribute("object_type", "packet", false);
    __add_date_attribute(true);
    __add_uint32_attribute("packet_id", n->identifier.packet_id.id, true);
    __add_uint32_attribute("seq", n->identifier.packet_id.seq, true);
    __add_ipv4_attribute("sender", n->identifier.packet_id.snd_ip, n->identifier.packet_id.snd_port, true);
    __add_ipv4_attribute("receiver", n->identifier.packet_id.rcv_ip, n->identifier.packet_id.rcv_port, true);
    __add_uint64_attribute("jiffies", n->jiffies, true);
    __add_uint32_attribute("ih_len", n->len, true);
    NODE_END();
    return buffer;
}

char* str_msg_to_spade_json(struct str_struct* n) {
    NODE_START("Entity");
    __add_string_attribute("log", n->str, true);
    NODE_END();
    return buffer;
}

char* addr_to_spade_json(struct address_struct* n) {
    char host[NI_MAXHOST];
    char serv[NI_MAXSERV];
    int err;
    struct sockaddr *ad = (struct sockaddr*)&(n->addr);

    NODE_START("Entity");
    if(ad->sa_family == AF_INET){
        err = getnameinfo(ad, sizeof(struct sockaddr_in), host, NI_MAXHOST, serv, NI_MAXSERV, NI_NUMERICHOST | NI_NUMERICSERV);
        __add_string_attribute("type", "AF_INET", true);
        if (err < 0) {
            __add_string_attribute("host", "could not resolve", true);
            __add_string_attribute("service", "could not resolve", true);
            __add_string_attribute("error", gai_strerror(err), true);
        } else {
            __add_string_attribute("host", host, true);
            __add_string_attribute("service", serv, true);
        }
    }else if(ad->sa_family == AF_INET6){
        err = getnameinfo(ad, sizeof(struct sockaddr_in6), host, NI_MAXHOST, serv, NI_MAXSERV, NI_NUMERICHOST | NI_NUMERICSERV);
        __add_string_attribute("type", "AF_INET6", true);
        if (err < 0) {
            __add_string_attribute("host", "could not resolve", true);
            __add_string_attribute("service", "could not resolve", true);
            __add_string_attribute("error", gai_strerror(err), true);
        } else {
            __add_string_attribute("host", host, true);
            __add_string_attribute("service", serv, true);
        }
    }else if(ad->sa_family == AF_UNIX){
        __add_string_attribute("type", "AF_UNIX", true);
        __add_string_attribute("path", ((struct sockaddr_un*)ad)->sun_path, true);
    }else{
        err = getnameinfo(ad, n->length, host, NI_MAXHOST, serv, NI_MAXSERV, NI_NUMERICHOST | NI_NUMERICSERV);
        __add_int32_attribute("type", ad->sa_family, true);
        if (err < 0) {
            __add_string_attribute("host", "could not resolve", true);
            __add_string_attribute("service", "could not resolve", true);
            __add_string_attribute("error", gai_strerror(err), true);
        } else {
            __add_string_attribute("host", host, true);
            __add_string_attribute("service", serv, true);
        }
    }
    NODE_END();
    return buffer;
}

char* pathname_to_spade_json(struct file_name_struct* n) {
    int i;
    NODE_START("Entity");
    // dirty fix
    for(i=0; i<n->length; i++){
        if(n->name[i]=='\\')
            n->name[i]='/';
    }
    __add_string_attribute("pathname", n->name, true);
    NODE_END();
    return buffer;
}

char* iattr_to_spade_json(struct iattr_prov_struct* n) {
    NODE_START("Entity");
    __add_uint32hex_attribute("valid", n->valid, true);
    __add_uint32hex_attribute("mode", n->mode, true);
    __add_uint32_attribute("uid", n->uid, true);
    __add_uint32_attribute("gid", n->gid, true);
    __add_int64_attribute("size", n->size, true);
    __add_int64_attribute("atime", n->atime, true);
    __add_int64_attribute("ctime", n->ctime, true);
    __add_int64_attribute("mtime", n->mtime, true);
    NODE_END();
    return buffer;
}

char* xattr_to_spade_json(struct xattr_prov_struct* n) {
    NODE_START("Entity");
    __add_string_attribute("name", n->name, true);
    if(n->size>0){
        __add_uint32_attribute("size", n->size, true);
        // TODO record value when present
    }
    NODE_END();
    return buffer;
}

char* pckcnt_to_spade_json(struct pckcnt_struct* n) {
    char* cntenc;
    NODE_START("Entity");
    cntenc = malloc( encode64Bound(n->length) );
    base64encode(n->content, n->length, cntenc, encode64Bound(n->length));
    __add_string_attribute("content", cntenc, true);
    free(cntenc);
    __add_uint32_attribute("length", n->length, true);
    if(n->truncated==PROV_TRUNCATED)
        __add_string_attribute("truncated", "true", true);
    else
        __add_string_attribute("truncated", "false", true);
    NODE_END();
    return buffer;
}

char* arg_to_spade_json(struct arg_struct* n) {
    int i;
    char* tmp;
    NODE_START("Entity");
    for(i=0; i<n->length; i++){
        if(n->value[i]=='\\')
            n->value[i]='/';
        if(n->value[i]=='\n')
            n->value[i]=' ';
        if(n->value[i]=='\t')
            n->value[i]=' ';
    }
    tmp = repl_str(n->value, "\"", "\\\"");
    if(tmp==NULL)
        tmp = n->value;
    __add_string_attribute("value", tmp, true);
    if(n->truncated==PROV_TRUNCATED)
        __add_string_attribute("truncated", "true", true);
    else
        __add_string_attribute("truncated", "false", true);
    NODE_END();
    if(tmp != n->value)
        free(tmp);
    return buffer;
}

char* machine_to_spade_json(struct machine_struct* n){
    char tmp[256];
    NODE_START("Entity");
    __add_string_attribute("u_sysname", n->utsname.sysname, true);
    __add_string_attribute("u_nodename", n->utsname.nodename, true);
    __add_string_attribute("u_release", n->utsname.release, true);
    __add_string_attribute("u_version", n->utsname.version, true);
    __add_string_attribute("u_machine", n->utsname.machine, true);
    __add_string_attribute("u_domainname", n->utsname.domainname, true);
    sprintf(tmp, "%d.%d.%d", n->cam_major, n->cam_minor, n->cam_patch);
    __add_string_attribute("k_version", tmp, true);
    __add_string_attribute("k_commit", n->commit, true);
    provenance_lib_version(tmp, 256);
    __add_string_attribute("l_version", tmp, true);
    provenance_lib_commit(tmp, 256);
    __add_string_attribute("l_commit", tmp, true);
    NODE_END();
    return buffer;
}

static char* json;
static inline void init_buffer( void ){
    json = (char*)malloc(MAX_JSON_BUFFER_LENGTH);
    memset(buffer, 0, MAX_JSON_BUFFER_LENGTH);
    memset(json, 0, MAX_JSON_BUFFER_LENGTH);
}

static void (*print_json)(char* json);

void set_SPADEJSON_callback( void (*fcn)(char* json) ){
    init_buffer();
    print_json = fcn;
}

static pthread_mutex_t l_json =  PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP;

static inline bool __append(char* buff){
    pthread_mutex_lock(&l_json);
    if (strlen(buff) + 2 > MAX_JSON_BUFFER_LENGTH - strlen(json) - 1){ // not enough space
        pthread_mutex_unlock(&l_json);
        return false;
    }
    strncat(json, buff, MAX_JSON_BUFFER_LENGTH - strlen(json) - 1); // copy up to free space
    pthread_mutex_unlock(&l_json);
    return true;
}


void spade_json_append(char* buff){
    // we cannot append buffer is full, need to print json out
    if(!__append(buff)){
        flush_spade_json();
        spade_json_append(buff);
        return;
    }
}

static bool writing_out = false;
static pthread_mutex_t l_flush =  PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP;

void flush_spade_json(){
    bool should_flush=false;
    char* tmp;

    pthread_mutex_lock(&l_flush);
    if(!writing_out){
        writing_out = true;
        should_flush = true;
        update_time(); // we update the time
    }
    pthread_mutex_unlock(&l_flush);

    if(should_flush){
        pthread_mutex_lock(&l_json);
        if (json[0]==0) {
            pthread_mutex_unlock(&l_json);
            writing_out = false;
            return;
        }
        print_json(json);
        memset(json, 0, MAX_JSON_BUFFER_LENGTH);
        pthread_mutex_unlock(&l_json);
        pthread_mutex_lock(&l_flush);
        writing_out = false;
        pthread_mutex_unlock(&l_flush);
    }
}