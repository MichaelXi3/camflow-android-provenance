#define _GNU_SOURCE
#include <sys/stat.h>
#include <sys/poll.h>
#include <sys/syscall.h>
#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sched.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdarg.h>
#include <time.h>
#include <android/log.h>

#include "camflow-dev-include/provenance_types.h"
#include "uthash.h"

#include "threadpool/thpool.h"
#include "libprovenance-include/provenance.h"

#define RUN_PID_FILE "/data/local/tmp/provenance-service.pid"
#define NUMBER_CPUS           256 /* support 256 core max */

/* internal variables */
static struct provenance_ops prov_ops;
static uint8_t ncpus;
/* per cpu variables */
static int relay_file[NUMBER_CPUS];
static int long_relay_file[NUMBER_CPUS];
/* worker pool */
static threadpool worker_thpool=NULL;
static uint8_t running = 1;

/* internal functions */
static int open_files(void);
static int close_files(void);
static int create_worker_pool(void);
static void destroy_worker_pool(void);

static void callback_job(void* data, const size_t prov_size);
static void long_callback_job(void* data, const size_t prov_size);
static void reader_job(void *data);
static void long_reader_job(void *data);

static inline void record_error(const char* fmt, ...){
    char tmp[2048];
    va_list args;

    va_start(args, fmt);
    vsnprintf(tmp, 2048, fmt, args);
    va_end(args);
    if(prov_ops.log_error!=NULL)
        prov_ops.log_error(tmp);
}

int provenance_record_pid( void ){
    int err;
    pid_t pid = getpid();
    FILE *f = fopen(RUN_PID_FILE, "w");
    if(f==NULL)
        return -1;
    err = fprintf(f, "%d", pid);
    fclose(f);
    return err;
}

int provenance_relay_register(struct provenance_ops* ops)
{
    int err;

    /* the provenance usher will not appear in trace */
    err = provenance_set_opaque(true);
    if(err)
        return err;

    /* copy ops function pointers */
    memcpy(&prov_ops, ops, sizeof(struct provenance_ops));

    /* count how many CPU */
    ncpus = sysconf(_SC_NPROCESSORS_ONLN);
    if(ncpus>NUMBER_CPUS)
        return -1;

    /* open relay files */
    if(open_files())
        return -1;

    /* create callback threads */
    if(create_worker_pool()){
        close_files();
        return -1;
    }

    if(provenance_record_pid() < 0)
        return -1;
    return 0;
}

void provenance_relay_stop()
{
    running = 0; // worker thread will stop
    sleep(1); // give them a bit of times
    close_files();
    destroy_worker_pool();
}

static int open_files(void)
{
    int i;
    char tmp[PATH_MAX]; // to store file name
    char *path;
    char *long_path;

    path = PROV_RELAY_NAME;
    long_path = PROV_LONG_RELAY_NAME;

    tmp[0]='\0';
    for(i=0; i<ncpus; i++){
        snprintf(tmp, PATH_MAX, "%s%d", path, i);
        relay_file[i] = open(tmp, O_RDONLY | O_NONBLOCK);
        if(relay_file[i]<0){
            record_error("Could not open files %s (%d)\n", tmp, relay_file[i]);
            return -1;
        }
        snprintf(tmp, PATH_MAX, "%s%d", PROV_LONG_RELAY_NAME, i);
        long_relay_file[i] = open(tmp, O_RDONLY | O_NONBLOCK);
        if(long_relay_file[i]<0){
            record_error("Could not open files %s (%d)\n", tmp, long_relay_file[i]);
            return -1;
        }
    }
    return 0;
}

static int close_files(void)
{
    int i;
    for(i=0; i<ncpus;i++){
        close(relay_file[i]);
        close(long_relay_file[i]);
    }
    return 0;
}

struct job_parameters {
    int cpu;
    void (*callback)(void*, const size_t);
    int fd;
    size_t size;
};

static int create_worker_pool(void)
{
    int i;
    struct job_parameters *params;
    worker_thpool = thpool_init(ncpus*2);
    /* set reader jobs */
    for(i=0; i<ncpus; i++){
        params = (struct job_parameters*)malloc(sizeof(struct job_parameters)); // will be freed in worker
        params->cpu = i;
        params->callback = callback_job;
        params->fd = relay_file[i];
        params->size = sizeof(union prov_elt);
        thpool_add_work(worker_thpool, (void*)reader_job, (void*)params);
        params = (struct job_parameters*)malloc(sizeof(struct job_parameters)); // will be freed in worker
        params->cpu = i;
        params->callback = long_callback_job;
        params->fd = long_relay_file[i];
        params->size = sizeof(union long_prov_elt);
        thpool_add_work(worker_thpool, (void*)reader_job, (void*)params);
    }
    return 0;
}

static void destroy_worker_pool(void)
{
    thpool_wait(worker_thpool); // wait for all jobs in queue to be finished
    thpool_destroy(worker_thpool); // destory all worker threads
}

/* per worker thread initialised variable */
static __thread int initialised=0;

void relation_record(union prov_elt *msg){
    uint64_t type = prov_type(msg);

    if(prov_is_used(type) &&  prov_ops.log_used!=NULL)
        prov_ops.log_used(&(msg->relation_info));
    else if(prov_is_informed(type) && prov_ops.log_informed!=NULL)
        prov_ops.log_informed(&(msg->relation_info));
    else if(prov_is_generated(type) && prov_ops.log_generated!=NULL)
        prov_ops.log_generated(&(msg->relation_info));
    else if(prov_is_derived(type) && prov_ops.log_derived!=NULL)
        prov_ops.log_derived(&(msg->relation_info));
    else if(prov_is_influenced(type) && prov_ops.log_influenced!=NULL)
        prov_ops.log_influenced(&(msg->relation_info));
    else if(prov_is_associated(type) && prov_ops.log_associated!=NULL)
        prov_ops.log_associated(&(msg->relation_info));
    else
        record_error("Error: unknown relation type %llx\n", prov_type(msg));
}

void node_record(union prov_elt *msg){
    switch(prov_type(msg)){
        case ENT_PROC:
            if(prov_ops.log_proc!=NULL)
                prov_ops.log_proc(&(msg->proc_info));
            break;
        case ACT_TASK:
            if(prov_ops.log_task!=NULL)
                prov_ops.log_task(&(msg->task_info));
            break;
        case ENT_INODE_UNKNOWN:
        case ENT_INODE_LINK:
        case ENT_INODE_FILE:
        case ENT_INODE_DIRECTORY:
        case ENT_INODE_CHAR:
        case ENT_INODE_BLOCK:
        case ENT_INODE_PIPE:
        case ENT_INODE_SOCKET:
            if(prov_ops.log_inode!=NULL)
                prov_ops.log_inode(&(msg->inode_info));
            break;
        case ENT_MSG:
            if(prov_ops.log_msg!=NULL)
                prov_ops.log_msg(&(msg->msg_msg_info));
            break;
        case ENT_SHM:
            if(prov_ops.log_shm!=NULL)
                prov_ops.log_shm(&(msg->shm_info));
            break;
        case ENT_PACKET:
            if(prov_ops.log_packet!=NULL)
                prov_ops.log_packet(&(msg->pck_info));
            break;
        case ENT_IATTR:
            if(prov_ops.log_iattr!=NULL)
                prov_ops.log_iattr(&(msg->iattr_info));
            break;
        default:
            record_error("Error: unknown node type %llx\n", prov_type(msg));
            break;
    }
}

void prov_record(union prov_elt* msg) {
    if(prov_is_relation(msg))
        relation_record(msg);
    else
        node_record(msg);
}

/* handle application callbacks */
static void callback_job(void* data, const size_t prov_size)
{
    union prov_elt* msg;
    if(prov_size!=sizeof(union prov_elt)){
        record_error("Wrong size %d expected: %d.", prov_size, sizeof(union prov_elt));
        return;
    }
    msg = (union prov_elt*)data;
    /* initialise per worker thread */
    if(!initialised && prov_ops.init!=NULL){
        prov_ops.init();
        initialised=1;
    }

    if(prov_ops.received_prov!=NULL)
        prov_ops.received_prov(msg);
    if(prov_ops.is_query)
        return;
    // dealing with filter
    if(prov_ops.filter==NULL)
        goto out;
    if(prov_ops.filter((prov_entry_t*)msg)) // message has been fitlered
        return;
    out:
    prov_record(msg);
}

void long_prov_record(union long_prov_elt* msg){
    switch(prov_type(msg)){
        case ENT_STR:
            if(prov_ops.log_str!=NULL)
                prov_ops.log_str(&(msg->str_info));
            break;
        case ENT_PATH:
            if(prov_ops.log_file_name!=NULL)
                prov_ops.log_file_name(&(msg->file_name_info));
            break;
        case ENT_ADDR:
            if(prov_ops.log_address!=NULL)
                prov_ops.log_address(&(msg->address_info));
            break;
        case ENT_XATTR:
            if(prov_ops.log_xattr!=NULL)
                prov_ops.log_xattr(&(msg->xattr_info));
            break;
        case ENT_DISC:
            if(prov_ops.log_ent_disc!=NULL)
                prov_ops.log_ent_disc(&(msg->disc_node_info));
            break;
        case ACT_DISC:
            if(prov_ops.log_act_disc!=NULL)
                prov_ops.log_act_disc(&(msg->disc_node_info));
            break;
        case AGT_DISC:
            if(prov_ops.log_agt_disc!=NULL)
                prov_ops.log_agt_disc(&(msg->disc_node_info));
            break;
        case ENT_PCKCNT:
            if(prov_ops.log_packet_content!=NULL)
                prov_ops.log_packet_content(&(msg->pckcnt_info));
            break;
        case ENT_ARG:
        case ENT_ENV:
            if(prov_ops.log_arg!=NULL)
                prov_ops.log_arg(&(msg->arg_info));
            break;
        case AGT_MACHINE:
            if(prov_ops.log_machine!=NULL)
                prov_ops.log_machine(&(msg->machine_info));
            break;
        default:
            record_error("Error: unknown node long type %llx\n", prov_type(msg));
            break;
    }
}

/* handle application callbacks */
static void long_callback_job(void* data, const size_t prov_size)
{
    union long_prov_elt* msg;
    if(prov_size!=sizeof(union long_prov_elt)){
        record_error("Wrong size %d expected: %d.", prov_size, sizeof(union long_prov_elt));
        return;
    }
    msg = (union long_prov_elt*)data;

    /* initialise per worker thread */
    if(!initialised && prov_ops.init!=NULL){
        prov_ops.init();
        initialised=1;
    }

    if(prov_ops.received_long_prov!=NULL)
        prov_ops.received_long_prov(msg);
    if(prov_ops.is_query)
        return;
    // dealing with filter
    if(prov_ops.filter==NULL)
        goto out;
    if(prov_ops.filter((prov_entry_t*)msg)) // message has been fitlered
        return;
    out:
    long_prov_record(msg);
}

#define buffer_size(prov_size) (prov_size*1000)
static void ___read_relay(const int relay_file, const size_t prov_size, void (*callback)(void*, const size_t)){
    uint8_t *buf;
    uint8_t* entry;
    size_t size=0;
    size_t i=0;
    int rc;
    buf = (uint8_t*)malloc(buffer_size(prov_size));
    do{
        rc = read(relay_file, buf+size, buffer_size(prov_size)-size);
        if(rc<0){
            record_error("Failed while reading (%d).", errno);
            if(errno==EAGAIN) // retry
                continue;
            free(buf);
            return;
        }
        size += rc;
    }while(size%prov_size!=0);

    while(size>0){
        entry = buf+i;
        size-=prov_size;
        i+=prov_size;
        callback(entry, prov_size);
    }
    free(buf);
}

static int set_thread_affinity(int core_id)
{
    cpu_set_t cpuset;

    if (core_id < 0 || core_id >= ncpus) {
        return -1;
    }

    CPU_ZERO(&cpuset);
    CPU_SET(core_id, &cpuset);

    pid_t current = gettid();
    return sched_setaffinity(current, sizeof(cpu_set_t), &cpuset);
}

#define TIME_US 1000L
#define TIME_MS 1000L*TIME_US

#define POL_FLAG (POLLIN|POLLRDNORM|POLLERR)
#define RELAY_POLL_TIMEOUT 1000L

/* read from relayfs file */
static void reader_job(void *data)
{
    int rc;
    struct job_parameters *params = (struct job_parameters*)data;
    struct pollfd pollfd;
    struct timespec s;

    s.tv_sec = 0;
    s.tv_nsec = 5 * TIME_MS;

    rc = set_thread_affinity(params->cpu);
    if (rc) {
        record_error("Failed setting cpu affinity (%d).", rc);
        exit(-1);
    }

    do{
        nanosleep(&s, NULL);
        /* file to look on */
        pollfd.fd = params->fd;
        /* something to read */
        pollfd.events = POL_FLAG;
        /* one file, timeout */
        rc = poll(&pollfd, 1, RELAY_POLL_TIMEOUT);
        if(rc<0){
            record_error("Failed while polling (%d).", rc);
            continue; /* something bad happened */
        }
        ___read_relay(params->fd, params->size, params->callback);
    }while(running);
}