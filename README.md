# Camflow Android Provenance 

[Camflow](https://camflow.org/) is a Linux Security Module (LSM) that captures data provenance for whole-system audit purposes. The provenance capture mechanism is highly configurable. The Camflow Android Provenance project is a transplant of Camflow to Android, applying the whole-system provenance concept to AOSP and capturing system-level audits.

## Getting Started

These instructions will guide you through building and installing Camflow Android in an Android environment, specifically the Android Cuttlefish virtual device.

### Prerequisites

- [Ubuntu 22.04.1](https://old-releases.ubuntu.com/releases/22.04.1/): the following installation instructions have been tested on the Ubuntu Linux distribution with version 22.04.1. It is encouraged to use the same environment.
- [Android Cuttlefish Virtual Device](https://source.android.com/docs/setup/create/cuttlefish): a configurable virtual Android device that replicates the framework-based behavior of a real device.
- [Android Kernel](https://source.android.com/docs/setup/build/building-kernels): build Android Kernel with Camflow patch. It installs the kernel part of Camflow provenance system. The Android kernel branch used is `common-android13-5.15-lts`.
- [Android Studio](https://developer.android.com/studio): Camflow Android user-space daemons are compiled and built in Android Studio.
- [Camflow](https://github.com/CamFlow/camflow-dev/releases/tag/v0.8.0): the kernel patch part of Camflow used in Android Camflow is **v0.8.0**. The modified userspace Camflow deamons are inclued in this repo and should be built in Android studio using `android-ndk-r23b`.

### Installing

A step by step guide of setting up Camflow Android Provenance System on Android virtual device.

---
#### Set Up Android Cuttlefish - Automation

##### Step 1: On Linux desktop, clone this repository and navigate to the `android-cuttlefish-automation` folder at the root level of the repository. Then, run the shell script.

```bash
source ./create-android-cuttlefish.sh
```

During Step 2 of the process, your laptop will **reboot**. Once the reboot is complete, simply execute the shell script again. The progress will be tracked, and previously completed commands will not be re-run. The reason for the reboot is to trigger the installation of additional kernel modules and the application of udev rules.

##### Step 2: Interact with Android Cuttlefish using Makefile

After executing the shell script, you should be located in the `~android-cuttlefish/cf` directory. The script also copied a Makefile to this directory to help you interact with the Android Cuttlefish virtual device. The commands are described as follows:

```bash
make shell                  # enter the shell of Android Cuttlefish
make root                   # running as root
make stop                   # stop the cuttlefish device
HOME=$PWD ./bin/launch_cvd  # launch a new cuttlefish virtual device
```
---
#### Set Up Android Cuttlefish - Manual

> **If you used "*Set Up Android Cuttlefish - Automation*", you can skip this part.** For the lastest manual launch instructions, check: https://android.googlesource.com/device/google/cuttlefish/

##### Step 1: In Linux desktop or virtual machine, make sure virtualization with KVM is available

```bash
grep -c -w "vmx\|svm" /proc/cpuinfo
```
This should return a non-zero value. If running on a cloud machine, this may take cloud-vendor-specific steps to enable.

##### Step 2: Download, build, and install the cuttlefish host debian packages

```bash
sudo apt install -y git devscripts config-package-dev debhelper-compat golang curl
git clone https://github.com/google/android-cuttlefish
cd android-cuttlefish
for dir in base frontend; do
  cd $dir
  debuild -i -us -uc -b -d
  cd ..
done
sudo dpkg -i ./cuttlefish-base_*_*64.deb || sudo apt-get install -f
sudo dpkg -i ./cuttlefish-user_*_*64.deb || sudo apt-get install -f
sudo usermod -aG kvm,cvdnetwork,render $USER
sudo reboot
```
This script installs the Android Cuttlefish environment on a Linux-based system.

##### Step 3: Download OTA images and host package of Android Cuttlefish 

-  **OTA** (Over-The-Air) image:  this file is a system image for the Cuttlefish Virtual Device (CVD), which is a part of AOSP.
-  **Host package**: this file is a host package for Cuttlefish. It includes binaries and scripts that need to be run on the host machine to set up and run the Cuttlefish virtual device.

1. Go to [http://ci.android.com/](http://ci.android.com/)
2. Enter a branch name. Start with `aosp-master` if you don‘t know what you’re looking for
3. Navigate to `aosp_cf_x86_64_phone` and click on `userdebug` for the latest build
4. Click on `Artifacts`
5. Scroll down to the **OTA** images. These packages look like `aosp_cf_x86_64_phone-img-xxxxxx.zip` -- it will always have `img` in the name. Download this file
6. Scroll down to `cvd-host_package.tar.gz`. You should always download a **host package** from the same build as your images
7. On your local system, `cd /path/to/android-cuttlefish`, combine the packages with following code
   
    ```bash
    mkdir cf
    cd cf
    tar xvf /path/to/cvd-host_package.tar.gz
    unzip /path/to/aosp_cf_x86_64_phone-img-xxxxxx.zip
    ```
    
##### Step 4: Launch cuttlefish and other useful cuttlefish commands 

1. Launch cuttlefish virtual machine
    ```bash
    HOME=$PWD ./bin/launch_cvd
    ```
2. Enable cuttlefish root
    ```bash
    ./bin/adb root
    ```
3. Launch cuttlefish shell
   
    ```bash
    ./bin/adb shell
    ```
4. Stop cuttlefish virtual machine
    ```bash
    pkill run_cvd
    ```
---
#### Build Android Kernel with Camflow Patch applied

##### Step 1: Create a directory for Android kernel build and install  `Repo` command for downloading Android Kernel source code (this directory MUST be separated from Android cuttlefish directory!)
> `Repo` command page: https://gerrit.googlesource.com/git-repo/+/refs/heads/main/README.md

```bash
# Debian/Ubuntu
$ sudo apt-get install repo

# Gentoo
$ sudo emerge dev-vcs/repo
```
Or install manually by the following code:
```bash
$ mkdir -p ~/.bin
$ PATH="${HOME}/.bin:${PATH}"
$ curl https://storage.googleapis.com/git-repo-downloads/repo > ~/.bin/repo
$ chmod a+rx ~/.bin/repo
```
Then at your home directory, create a directory for Android Kernel:
```bash
$ cd
$ mkdir android-kernel-5.15 && cd android-kernel-5.15
```

##### Step 2: Download Android Kernel source code
 ```bash
# Branch android13-5.15-LTS as an example
repo init -u https://android.googlesource.com/kernel/manifest -b common-android13-5.15-lts
repo sync -j12
 ```

The option `j12` means that the sync operation will use 12 parallel threads or jobs. If an error occurs during the sync process, you can try reducing the number of threads by lowering the number that follows the `j` option first.
    
##### Step 3: Apply the kernel patches to Android Kernel source code for customization

1. Download Camflow kernel patch from Camflow repository
	- Camflow is a major LSM for Linux kernel Provenance
	- Download one of the release of Camflow from the link above, in this example, we use `Camflow v0.8.0` since it's compatible with Android Kernel branch `android13-5.15-LTS`
	- The link of `Camflow v0.8.0` patch releases is: [Link](https://github.com/CamFlow/camflow-dev/releases/tag/v0.8.0)
2. Install Camflow kernel patch to kernel source code before building it
	- Apply the two Camflow patches to the `common` kernel source code directory
    ```bash
    cd  android-kernel-5.15/common
    git apply path/to/0001-information-flow.patch
    git apply path/to/0002-camflow.patch
    ```
3. Configure the kernel configuration to ensure the camflow provenance LSM is properly loaded and is processed last
	```bash
	cd  android-kernel-5.15/common
	make menuconfig
	```
	![camflow-config1](https://s2.loli.net/2023/07/29/uol1rChpDmw2Ls9.png)
	![camflow-config2](https://s2.loli.net/2023/07/29/MaABjHfgT9mzusN.png)
	![camflow-config3](https://s2.loli.net/2023/07/29/tLJuprdmaMlGkE6.png)
	- Make sure the "provenance" is added at the end of enabled LSMs list

4. Download and run this shell script to modify the `gki_defconfig` to **avoid the savedefconfig mismatch error**
> If the `gdown` command is not working, you can obtain this shell script from the `kernel-config-setting-shell` directory at the root level of this repository.

  ```bash
  gdown --id 1x2fLFHlr_UtoCa0_MmHSWHLkiDBnZrNe
  source ./modify-build-configs.sh
  ```

##### Step 4: Build the Android Kernel
> Since Android 10, Android has introduced a new **[Generic Kernel Image(GKI)](https://source.android.com/devices/architecture/kernel/generic-kernel-image)** in kernel 4.19 and above. This means that the kernel building process has been divided into two parts: `Generic Kernel` and `Vendor Modules`. We have to build these two parts separately.
> 
> ![kernel.png](https://s2.loli.net/2023/05/09/4iUwsP7QLefFHTx.png)
> - **GKI modules**: Kernel modules built by Google that can be dynamically loaded on devices where applicable. These modules are built as artifacts of the GKI kernel and are delivered alongside GKI as the `system_dlkm_staging_archive.tar.gz` archive.
> - **Vendor module**: A hardware-specific module developed by a partner and that contains SoC and device-specific functionality. A vendor module is a type of dynamically loadable kernel module.


1. **Build Generic Kernel**
    ```bash
    # bazel build
    tools/bazel build //common:kernel_x86_64_dist
    ```
    Successfully build should output following message:
    ```
    INFO: From Building GKI artifacts //common:kernel_x86_64_gki_artifacts:
    Creating boot-img.tar.gz for gki-info.txt boot.img
    INFO: From Building system_dlkm //common:kernel_x86_64_images_system_dlkm_image:
    ========================================================
    Creating system_dlkm image
    Target //common:kernel_x86_64_dist up-to-date:
    bazel-bin/common/kernel_x86_64_dist
    INFO: Elapsed time: 1377.103s, Critical Path: 1356.84s
    INFO: 253 processes: 239 internal, 14 linux-sandbox.
    INFO: Build completed successfully, 253 total actions
    ```

    ```bash
    # create output distribution
    tools/bazel run //common:kernel_x86_64_dist -- --dist_dir=/path/to/android-kernel-5.15/vendor-build-output-x86
    ```
    
2. **Build Vendor Modules for the Virtual Device**
    ```bash
    # bazel build
    tools/bazel build //common-modules/virtual-device:virtual_device_x86_64_dist
    ```
    
    Successfully build should output following message:
    ```
    Target //common-modules/virtual-device:virtual_device_x86_64_dist up-to-date:
    bazel-bin/common-modules/virtual-device/virtual_device_x86_64_dist
	INFO: Elapsed time: 185.179s, Critical Path: 183.47s
	INFO: 24 processes: 13 internal, 11 linux-sandbox.
	INFO: Build completed successfully, 24 total actions
    ```

    ```bash
    # create output distribution
    tools/bazel run //common-modules/virtual-device:virtual_device_x86_64_dist -- --dist_dir=/path/to/android-kernel-5.15/vendor-build-output-x86
    ```
	Upon successful completion of the build, `initramfs.img` and `bzImage` should be located at `/path/to/android-kernel-5.15/vendor-build-output-x86`. You can now proceed to swap this kernel into your Cuttlefish Android Virtual Device.

	- `initramfs.img`: the initial RAM filesystem is a temporary in-memory file system that contains essential files and utilities required for mounting the root file system. It is compressed and stored as an image file with name: `initramfs.img`.
	- `bzImage`: the `bzImage` is a compressed Linux kernel image created during the kernel compilation process. It is designed to be small enough to fit within limited memory space during the boot process. The `bzImage` is loaded by the bootloader, decompressed, and executed to initialize the system hardware and kernel before transitioning to the root file system.

---
#### Swap the Cutomized Android Kernel into Android Cuttlefish Virtual Device

1. In `/android-cuttlefish/cf` directory, set the environment variable `DIST_FOLDER` as the folder that contains `initramfs.img` and `bzImage`
   
    ```bash
    DIST_FOLDER=$(readlink -f /path/to/android-kernel-5.15/vendor-build-output-x86)
    ```
    
2. Navigate to `android-cuttlefish/cf`, and then use the following command to launch Cuttlefish using the kernel we just built.
	> If the launch of cuttlefish failed, try to stop previously launched cuttlefish first by `pkill run_cvd`
   
    ```bash
    HOME=${PWD} ./bin/launch_cvd -daemon -initramfs_path "${DIST_FOLDER}"/initramfs.img -kernel_path "${DIST_FOLDER}"/bzImage -memory_mb 27000 -data_policy always_create -blank_data_image_mb 30000 -cpus 1
    ```
    
3. Launch the shell of cuttlefish and check the kernel version to verify that kernel is swapped successfully
   
    ```bash
    ./bin/adb shell  # alternatively, make shell
    ```
    
    ```bash
    # run cat version before and after the kernel swap, the output should be different
    vsoc_x86_64:/proc $ cat version
    Linux version 5.15.120-maybe-dirty (build-user@build-host) (Android (8508608, based on r450784e) clang version 14.0.7 (https://android.googlesource.com/toolchain/llvm-project 4c603efb0cca074e9238af8b4106c30add4418f6), LLD 14.0.7) #1 SMP PREEMPT Thu Jan 1 00:00:00 UTC 1970
    ```

---
#### Set Up Camflow Android User-Space Daemons

> Camflow provenance system consists of kernel space capture mechanism and user space daemons. The architecture is described below, for more information, check [camflow.org](https://camflow.org/#overview).
> 
> ![camflow.png](https://s2.loli.net/2023/07/29/qeCQIR7WEL1TfGn.png)
> - **camflowd**: is a daemon responsible for recording the provenance captured in the kernel by CamFlow. Provenance records are published by CamFlow to pseudo-files in relayfs. The daemon retrieves these records, serializes them to a format specified in the configuration, and writes them to an output specified in the configuration.
> - **camconfd**: camconfd is a daemon charged with configuring the in-kernel capture mechanism. The configuration daemon reads from `camflow.ini` and load the specified configuration into the kernel via a securityfs interface. 
> - **libprovenance**: a C library implementing userspace utility functions to interact with CamFlow relayfs and securityfs interfaces.
> - **camflow-cli**: CLI that allows user to dynamically modify the capture configuration through the command line.
> - **camflow.ini**: capture configuration file read during the boot process by the camconfd service, and is used to set the capture policy.
> - **camflowd.ini**: output configuration file that specifies what and where the provenance information is published. (Currently only support log output in **SPADE JSON** format )

##### Step 1: Build Camflow Android User-Space Daemons in Android Studio
1. On Mac or Linux desktop, `git clone` this repo to Desktop and open this folder in Android Studio (Proceed to next step if you have already cloned the repository)
```bash
git clone https://github.com/MichaelXi3/camflow-android-provenance.git
```
2. Click the green `Build` button on the top right corner of Android Studio
```
BUILD SUCCESSFUL in 13s
43 actionable tasks: 43 executed
```
All the executables should be located at:
```
/Desktop/camflow-android-provenance/app/build/intermediates/cxx/Debug/k4r535v6/obj/x86_64
```
The executable and shared library list should include:
```
camconfd     camflow-cli     camflowd     camflowexample     libprovenance.so
```
##### Step 2: Install these executables and shared library to Android Cuttlefish
> Assuming we build the user-space daemons in Android Studio on a Mac, while Android Cuttlefish runs on a Linux desktop.

1. Move the userspace daemons and shared library to the Linux Desktop from Mac, assume all these five files are now moved to `/Downloads` folder on Linux Desktop
2. Move the configuration files `camflow.ini` and `camflowd.ini` located at `camflow-config-files` folder in this repo to  `/Downloads` folder on Linux Desktop as well
3. Navigate to `android-cuttlefish/cf`, enter the following commands to launch the Android virtual device with specified configurations
	```bash
	# stop the previous launched Android virtual device if there is any
	pkill run_cvd
	```
	```bash
	# set DIST_FOLDER to the directory that contains bzImage and initramfs.img
	DIST_FOLDER=$(readlink -f /path/to/android-kernel-5.15/vendor-build-output-x86)
	```
	```bash
	# Launch Android cuttlefish with RAM 27GB, Disk Space 30GB, 1 CPU
	HOME=${PWD} ./bin/launch_cvd -daemon -memory_mb 27000 -data_policy always_create -blank_data_image_mb 30000 -cpus 1 -initramfs_path "${DIST_FOLDER}"/initramfs.img -kernel_path "${DIST_FOLDER}"/bzImage
	```
3. Install the shared library and user-space daemons to Android Cuttlefish
	> **Using Makefile commands to automate is recommended**. A Makefile has been placed at `android-cuttlefish/cf` directory, you can use it right away or modify it to your needs.
	
	**First:  `make remount-all`**, or use following commands
    ```bash
    # remount Android cuttlefish device - need to install shared library
    ./bin/adb root
    ./bin/adb remount
    ./bin/adb reboot

    # mount several filesystem in Android cuttlefish device
    # if encounter 'Device or resource busy' error, wait a minute and try again
    ./bin/adb root
    ./bin/adb shell mount -t securityfs /sys/kernel/security
    ./bin/adb shell mount -t debugfs /sys/kernel/debugfs
    ./bin/adb shell mount -o rw,remount /system
    ```
    
   **Second:  `make prepare`**, assume everything is located at `/Downloads` directory
   > Checklist of what you need in `/Downloads` directory: `camconfd`, `camflow-cli`, `camflowd`, `1ibprovenance.so`, `camflowexample`, `camflow.ini`, `camflowd.ini`
    ```bash
    # install user-space daemons to android cuttlefish /data/local/tmp
    ./bin/adb push /path/to/Downloads/camflowd /data/local/tmp
    ./bin/adb push /path/to/Downloads/camflowexample /data/local/tmp
    ./bin/adb push /path/to/Downloads/camconfd /data/local/tmp
    ./bin/adb shell "cd /data/local/tmp && chmod 755 camflowd && chmod 755 camconfd && chmod 755 camflowexample"
    ```
    ```bash
    # install camflow-cli to android cuttlefish
    ./bin/adb push /path/to/Downloads/camflow-cli /system/bin
    ./bin/adb shell "cd /system/bin && mv camflow-cli camflow && chmod 755 /system/bin/camflow"
    ```
    ```bash
    # install libprovenance.so shared library to android cuttlefish
    ./bin/adb push /path/to/Downloads/libprovenance.so /system/lib64
    ```
    ```bash
    # install the camflow and camflowd configuration files
    ./bin/adb push /path/to/Downloads/camflow.ini /data/local/tmp
    ./bin/adb push /path/to/Downloads/camflowd.ini /data/local/tmp
    ```

##### Step 3: Run User-Space Daemons to Capture Provenance of Android System
1. Run the `camconfd` daemon to set the capture configuration. Note that in the default `camflow.ini`, the capture-all provenance is set to false since there will be massive provenance data generated if capture-all is set to true. You can fine-tune the capture policy later by modifying the configurations listed in `camflow.ini`.
	```bash
	./bin/adb shell /data/local/tmp/camconfd & # or, make run-camconfd
	```
2. Run the `camflowd` daemon to record the provenance captured in the kernel and serialize them to SPADE JSON format log in `/data/local/tmp/audit.log file`.
	```bash
	./bin/adb shell /data/local/tmp/camflowd & # or, make run-camflowd
	```
3. Now there should a file called `audit.log` locates at `/data/local/tmp/` that contains provenance log entries. Note that the log may be empty if your capture configuration is set to not capture anything, as defined in the default `camflow.ini`.
	```bash
	# enter android cuttlefish shell as root
	make root && make shell
	cd /data/local/tmp
	vi audit.log
	```
	```bash
	# the provenance log should be something similar to the following
{"type":"Entity","id":"EAAAAAAAABQFFQAAAAAAAAAAAAAAAAAAAQAAAAAAAAA=","annotations": {"object_id":"5381","object_type":"machine","boot_id":0,"cf:machine_id":"cf:0","version":1,"cf:date":"2023:07:24T15:23:35","cf:taint":"0","cf:jiffies":"0","cf:epoch":0,"u_sysname":"Linux","u_nodename":"(none)","u_release":"5.15.104-maybe-dirty","u_version":"#1 SMP PREEMPT Thu Jan 1 00:00:00 UTC 1970","u_machine":"x86_64","u_domainname":"(none)","k_version":"0.8.0","l_version":"v0.5.5"}}
	```
	```bash
	# to copy the provenance log file to /Documents directory
	exit         # exit android cuttlefish shell, now you should at ~/android-cuttlefish/cf
	make pull    # pull audit.log from cuttlefish to local machine
	```


## Running Tests

This section provides a walk-through of the Camflow Android Provenance System test, assuming that the user has already completed the instructions described above. Specifically, user should have already launched Android cuttlefish successfully, installed all user space daemons, shared library, and executed camconfd and camflowd to apply capture configurations and to generate provenance.

### Test 1: Get the provenance graph of an executable that opens and writes a file

1. Run `camflowexample` located at `/data/loca/tmp` installed in the previous steps
    - In the `camflowexample` executable, it turns on the `track-me` bit, so that this process can be tracked.
    ```bash
    # execute this command at /android-cuttlefish/cf
    ./bin/adb shell /data/local/tmp/camflowexample    # or, make run-example
    ```
2. Check out the provenance log generated in `audit.log`
    ```bash
    # enter the android cuttlefish commandline interface
    ./bin/adb shell      # or, make shell
    cd /data/local/tmp
    vi audit.log
    ```
3. Using Camflow Android Log Parser to parse and visualize the generated log
	- **Camflow Log Parser Github Link**: https://github.com/MichaelXi3/android-provenance-parser 

	![provG.jpg](https://s2.loli.net/2023/07/29/obi543zrtf2LGXl.jpg)
   



## Built With

* [Bazel](https://bazel.build/) - The build and test tool developed by Google to automate build processes for large-scale software such as Android Kernel and Modules
* [CMake](https://www.jetbrains.com/help/clion/cmakelists-txt-file.html) - The build system used for building Camflow Android user space daemons and shared library
* [AndroidNDK](https://rometools.github.io/rome/) - A cross-compiling tool for compiling code written in C/C++ for Android



## Project Structure

At the root directory of the project, there're a few important dictories:
1. `camflow-config-files`: stores `camflow.ini` and `camflowd.ini` for capture and outpur configurations
2. `camflow-makefile-example` : provides a sample makefile for android-cuttlefish commands
3. `prebuilt-userspace-daemons`: provides prebuilt daemons that can be used right away
4. `android-cuttlefish-automation`: provides the shell script that automates the android cuttlefish launch
5. `kernel-config-setting-shell`: provides shell script that modifies android kernel build configs, for backup purposes
4. `app`: is the directory that contains all source codes, specifically, the path is `AndroidStudioProjects/camflow-android-provenance/app/src/main/cpp`
	```
	   .
   ├── CMakeLists.txt
   ├── camconfd
   │   ├── CMakeLists.txt
   │   ├── camconf.h
   │   ├── config.c
   │   └── ini
   ├── camflow-cli
   │   ├── CMakeLists.txt
   │   └── camflow.c
   ├── camflowdd
   │   ├── CMakeLists.txt
   │   ├── camflowd-include
   │   │   ├── service-config.h
   │   │   └── service-log.h
   │   ├── ini
   │   └── main.c
   ├── example
   │   ├── CMakeLists.txt
   │   ├── cp.c
   │   ├── printf.c
   │   └── write.c
   └── provenancelib
    ├── CMakeLists.txt
    ├── camflow-dev-include
    │   ├── provenance_fs.h
    │   ├── provenance_types.h
    │   └── provenanceh.h
    ├── libprovenance-include
    │   ├── provenance.h
    │   ├── provenanceSPADEJSON.h
    │   ├── provenanceW3CJSON.h
    │   ├── provenance_utils.h
    │   └── provenancefilter.h
    ├── libprovenance.c
    ├── provenanceJSONcommon.h
    ├── provenanceSPADEJSON.c
    ├── provenanceW3CJSON.c
    ├── provenancefilter.c
    ├── provenanceutils.c
    ├── relay.c
    ├── threadpool
    │   ├── CMakeLists.txt
    │   ├── thpool.c
    │   └── thpool.h
    └── uthash.h
	```