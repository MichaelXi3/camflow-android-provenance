# Changes Log of Building libprovenance and CamFlow user space Daemons using Android NDK

# libprovenance.so

1. **Change_1**: Copy and pasted [camflow-dev](https://github.com/CamFlow/camflow-dev/tree/master)/[include](https://github.com/CamFlow/camflow-dev/tree/master/include)/[uapi](https://github.com/CamFlow/camflow-dev/tree/master/include/uapi)/linux/ header files to `camflow-dev-include` directory.
    
    - In the original camflow, the header files are included as:
      
        `#include <linux/provenance_types.h>`
        
    - In my case, the header files are included as:
      
        `#include "camflow-dev-include/provenance_types.h"`
    
2. **Change_2**: Android NDK doesn’t have `uthash.h`, so I copied code from GitHub
    
    - In the original camflow, the header file is included as: 
    `#include <unistd.h>`
    - In my case, the header file is included as:
      
        `#include "uthash.h"`
    
3. **Change_3**: In `provenanceutil.c`, I commented out the following function, due to a linker error of the undefined symbol `compress` and `compressBound`:
   
    ```c
    int compress64encode(const char* in, size_t inlen, char* out, size_t outlen){
        uLongf len;
        char* buf;
    
        if(outlen < compress64encodeBound(inlen)){
            return -1;
        }
    
        len = compressBound(inlen);
        buf = (char*)malloc(len);
        compress((Bytef*)buf, &len, (Bytef*)in, inlen);
        base64encode(buf, len, out, outlen);
        free(buf);
    
        return 0;
    }
    ```
    
    **Reasons** of commenting out:
    
    - Linker error persists even there is a function referencing to it
    - **Used only** in camflowd "include/service-**mqtt**.h"
    - Shared library successfully built after commented out this single function
4. **Change_4**: I modified set_thread_affinity function since Android doesn’t have pthread set affinity function available.
    - In original camflow, the code is:
      
        ```c
        static int set_thread_affinity(int core_id)
        {
          cpu_set_t cpuset;
          pthread_t current;
        
          if (core_id < 0 || core_id >= ncpus)
            return -1;
          CPU_ZERO(&cpuset);
          CPU_SET(core_id, &cpuset);
        
          current = pthread_self();
          return pthread_setaffinity_np(current, sizeof(cpu_set_t), &cpuset);
        }
        ```
        
    - In my case, the code is:
      
        ```c
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
        ```
    
5. **Change_5**: For the compilation of the C-Thread-Pool static library, I directly copied the `thpool.c` and `thpool.h` files from GitHub and compiled them into a `.a` library using a CMakeList file. I'm not entirely sure how the original CamFlow did it, but it seems that it cloned the C-Thread-Pool repository and built it based on `thpool.c`. (Makefile [link](https://github.com/CamFlow/libprovenance/blob/46255580589d1d5c751cebe960daedc4c5724b27/threadpool/Makefile))
6. **Change_6**: Modified `RUN_PID_FILE` location
    - In original camflow, the code is:
      
        ```c
        #define RUN_PID_FILE "/run/provenance-service.pid"
        ```
        
    - In my case, the code is:
      
        ```c
        #define RUN_PID_FILE "/data/local/tmp/provenance-service.pid"
        ```
        

# camflowd executable

1. **Change_1**:  Android NDK doesn’t have `ini.h` and `ini.c`, so I copied code from github
    - In original camflow, the header file is included as: 
    `#include <ini.h>`
    - In my case, the header file is included as:
      
        `#include "../ini/ini.h"`
    
2. **Change_2**: I modified the CONFIF_PATH of camflow.ini, since the file location changed in Android case
    - In original camflow, the code is: 
    `#define CONFIG_PATH "/etc/camflowd.ini”`
    - In my case, the code is:
      
        `#define CONFIG_PATH "/data/local/tmp/camflowd.ini"`
        

# camconfd executable

1. **Change_1**:  Android NDK doesn’t have `ini.h` and `ini.c`, so I copied code from github
    
    - In original camflow, the header file is included as: 
    `#include <ini.h>`
    - In my case, the header file is included as:
      
        `#include "../ini/ini.h"`
    
2. **Change_2**: I modified the CONFIF_PATH of camflow.ini, since the file location changed in Android case
    
    - In the original camflow, the code is: 
    `#define CONFIG_PATH "/etc/camflow.ini”`
    - In my case, the code is:
      
        `#define CONFIG_PATH "/data/local/tmp/camflow.ini"`
    
3. **Change_3**: I modified the `CAMFLOW_MACHINE_ID_FILE` and `CAMFLOW_BOOT_ID_FILE` 
    - In the original camflow, the code is:
      
        ```c
        #define CAMFLOW_MACHINE_ID_FILE "/etc/camflow-machine_id"
        #define CAMFLOW_BOOT_ID_FILE "/etc/camflow-boot_id"
        ```
        
    - In my case, the code is:
      
        ```c
        #define CAMFLOW_MACHINE_ID_FILE "/data/local/tmp/camflow-machine_id"
        #define CAMFLOW_BOOT_ID_FILE "/data/local/tmp/camflow-boot_id"
        ```
    
4. **Change_4**: `gethostid()` POSIX function is not available in Android NDA
    - In original camflow, the code is:
      
        ```c
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
                srand(time(NULL)+gethostid());
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
        ```
        
    - In my case, the code is:
      
        ```c
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
        ```