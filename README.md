# Camflow Android Provenance 

[Camflow](https://camflow.org/) is a Linux Security Module (LSM) that captures data provenance for whole-system audit purposes. The provenance capture mechanism is highly configurable. The Camflow Android Provenance project is a transplant of Camflow to Android, applying the whole-system provenance concept to AOSP and capturing system-level audits.

## Getting Started

These instructions will guide you for building up Camflow in Android environment, including both kernel and user-space daemons build, for development and testing purposes. See deployment for notes on how to deploy the project on a live system, i.e. Android virtual device.

### Prerequisites

- [Android Cuttlefish](https://source.android.com/docs/setup/create/cuttlefish): a configurable virtual Android device that replicates the framework-based behavior of a real device.
- [Android Kernel](https://source.android.com/docs/setup/build/building-kernels): build Android Kernel with Camflow patch. It installs the kernel part of Camflow provenance system. The Android kernel branch used is `common-android13-5.15-lts`.
- [Android Studio](https://developer.android.com/studio): Camflow Android user-space daemons are compiled and built in Android Studio.
- [Camflow](https://github.com/CamFlow/camflow-dev/releases/tag/v0.8.0): the kernel patch part of Camflow used in Android Camflow is **v0.8.0**. The modified userspace Camflow deamons are inclued in this repo and should be built in Android studio using `android-ndk-r23b`.

### Installing

A step by step guide of setting up Camflow Android Provenance System on Android virtual device.

---
#### Set Up Android Cuttlefish
> For the lastest instructions, check: https://android.googlesource.com/device/google/cuttlefish/
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

##### Step 3: Download OTA images and host package of Android Cuttleish 

-  **OTA** (Over-The-Air) image:  this file is a system image for the Cuttlefish Virtual Device (CVD), which is a part of AOSP.
-  **Host package**: this file is a host package for Cuttlefish. It includes binaries and scripts that need to be run on the host machine to set up and run the Cuttlefish virtual device.


1. Go to [http://ci.android.com/](http://ci.android.com/)
2. Enter a branch name. Start with `aosp-master` if you don‘t know what you’re looking for
3. Navigate to `aosp_cf_x86_64_phone` and click on `userdebug` for the latest build
4. Click on `Artifacts`
5. Scroll down to the **OTA** images. These packages look like `aosp_cf_x86_64_phone-img-xxxxxx.zip` -- it will always have `img` in the name. Download this file
6. Scroll down to `cvd-host_package.tar.gz`. You should always download a **host package** from the same build as your images
7. On your local system, combine the packages with following code
   
    ```bash
    mkdir cf
    cd cf
    tar xvf /path/to/cvd-host_package.tar.gz
    unzip /path/to/aosp_cf_x86_64_phone-img-xxxxxx.zip
    ```
    
##### Step 4: Launch cuttlefish and other useful cuttlefish commands 

1. Launch cuttlefish virtual machine
    ```bash
    $ HOME=$PWD ./bin/launch_cvd
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
    HOME=$PWD ./bin/stop_cvd
    ```
---
#### Build Android Kernel with Camflow Patch applied

##### Step 1: Create a directory for Android kernel build and install  `Repo` command for downloading Android Kernel source code
> `Repo` command page: https://gerrit.googlesource.com/git-repo/+/refs/heads/main/README.md

```bash
  # Debian/Ubuntu.
  $ sudo apt-get install repo

  # Gentoo.
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
	- The link of Camflow v0.8.0 patch releases is: [Link](https://github.com/CamFlow/camflow-dev/releases/tag/v0.8.0)
2. Install Camflow kernel patch to kernel source code before building it
	- Apply the two Camflow patches to the `common` kernel source code directory
    ```bash
    cd  android-kernel-5.15/common
    git apply path/to/0001-information-flow.patch
    git apply path/to/0002-camflow.patch
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

    ```bash
    # create output distribution
    tools/bazel run //common:kernel_x86_64_dist -- --dist_dir=/path/to/android-kernel-5.15/vendor-build-output-x86
    ```
    
2. **Build Vendor Modules for the Virtual Device**
        
    ```bash
    # bazel build
    tools/bazel build //common-modules/virtual-device:virtual_device_x86_64_dist
    ```

    ```bash
    # create output distribution
    tools/bazel run //common-modules/virtual-device:virtual_device_x86_64_dist -- --dist_dir=/path/to/android-kernel-5.15/vendor-build-output-x86
    ```
	Upon successful completion of the build, `initramfs.img` and `bzImage` should be located at /path/to/android-kernel-5.15/vendor-build-output-x86. You can now proceed to swap this kernel into your Cuttlefish Android Virtual Device.

	- `initramfs.img`: the initial RAM filesystem is a temporary in-memory file system that contains essential files and utilities required for mounting the root file system. It is compressed and stored as an image file with name: `initramfs.img`.
	- `bzImage`: the `bzImage` is a compressed Linux kernel image created during the kernel compilation process. It is designed to be small enough to fit within limited memory space during the boot process. The `bzImage` is loaded by the bootloader, decompressed, and executed to initialize the system hardware and kernel before transitioning to the root file system.

---
#### Swap the Cutomized Android Kernel into Android Cuttlefish Virtual Device

1. Set the environment variable `DIST_FOLDER` as the folder that contains `initramfs.img` and `bzImage`
   
    ```bash
    DIST_FOLDER=$(readlink -f /path/to/android-kernel-5.15/vendor-build-output-x86)
    ```
    
2. Navigate to `android-cuttlefish/cf`, and then use the following command to launch Cuttlefish using the kernel we just built.
   
    ```bash
    HOME=${PWD} ./bin/launch_cvd -daemon -initramfs_path "${DIST_FOLDER}"/initramfs.img -kernel_path "${DIST_FOLDER}"/bzImage
    ```
    
3. Launch the shell of cuttlefish and check the kernel version to verify that kernel is swapped successfully
   
    ```bash
    ./bin/adb shell
    ```
    
    ```bash
    # run cat version before and after the kernel swap, the output should be different
    vsoc_x86_64:/proc $ cat version
    Linux version 5.15.78-maybe-dirty (build-user@build-host) (Android (8508608, based on r450784e) clang version 14.0.7 (https://android.googlesource.com/toolchain/llvm-project 4c603efb0cca074e9238af8b4106c30add4418f6), LLD 14.0.7)
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
1. `git clone` this repo to Desktop
```bash
git clone https://github.com/MichaelXi3/camflow-android-provenance.git
```
2. Click `Build` button on the top right corner of Android Studio
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
3. Install the shared library and user-space daemons to Android Cuttlefish
	> **Encapsulating and automating these commands in a Makefile is highly recommended**. Example of Makefile is provided at Appendix folder in this repo.
	> .
    ```bash
    # remount Android cuttlefish device - need to install shared library
    ./bin/adb root
    ./bin/adb remount
    ./bin/adb reboot
    ```
    ```bash
    # mount several filesystem in Android cuttlefish device
    # if encounter 'Device or resource busy' error, wait a minute and try again
    ./bin/adb root
    ./bin/adb shell mount -t securityfs /sys/kernel/security
    ./bin/adb shell mount -t debugfs /sys/kernel/debugfs
    ./bin/adb shell mount -o rw,remount /system
    ```
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
	./bin/adb shell /data/local/tmp/camconfd &
	```
2. Run the `camflowd` daemon to record the provenance captured in the kernel and serialize them to SPADE JSON format log in `/data/local/tmp/audit.log file`.
	```bash
	./bin/adb shell /data/local/tmp/camflowd &
	```
3. Now there should a file called `audit.log` locates at `/data/local/tmp/` that contains provenance log entries. Note that the log may be empty if your capture configuration is set to not capture anything, as defined in the default `camflow.ini`.
	```
	{"type":"Entity","id":"EAAAAAAAABQFFQAAAAAAAAAAAAAAAAAAAQAAAAAAAAA=","annotations": {"object_id":"5381","object_type":"machine","boot_id":0,"cf:machine_id":"cf:0","version":1,"cf:date":"2023:07:24T15:23:35","cf:taint":"0","cf:jiffies":"0","cf:epoch":0,"u_sysname":"Linux","u_nodename":"(none)","u_release":"5.15.104-maybe-dirty","u_version":"#1 SMP PREEMPT Thu Jan 1 00:00:00 UTC 1970","u_machine":"x86_64","u_domainname":"(none)","k_version":"0.8.0","l_version":"v0.5.5"}}
	```



## Running Tests

This section provides a walk-through of the Camflow Android Provenance System test, assuming that the user has already completed the instructions described above.

### Test 1: Get the provenance graph of an executable that opens and writes a file

1. Run `camflowexample` located at `/data/loca/tmp` installed in the previous steps
    - In the `camflowexample` executable, it turns on the `track-me` bit, so that this process can be tracked.
    ```bash
    ./bin/adb shell /data/local/tmp/camflowexample
    ```
2. Check out the provenance log generated in `audit.log`
    ```bash
    vi audit.log
    ```
    <details>
    	<summary>Raw Provenance Log</summary>
    	```
    	{"type":"Entity","id":"EAAAAAAAABQFFQAAAAAAAAAAAAAAAAAAAQAAAAAAAAA=","annotations": {"object_id":"5381","object_type":"machine","boot_id":0,"cf:machine_id":"cf:0","version":1,"cf:date":"2023:07:24T15:23:35","cf:taint":"0","cf:jiffies":"0","cf:epoch":0,"u_sysname":"Linux","u_nodename":"(none)","u_release":"5.15.104-maybe-dirty","u_version":"#1 SMP PREEMPT Thu Jan 1 00:00:00 UTC 1970","u_machine":"x86_64","u_domainname":"(none)","k_version":"0.8.0","l_version":"v0.5.5"}}
	{"type":"Entity","id":"EAAAAAAAABQFFQAAAAAAAAAAAAAykjc2AQAAAAAAAAA=","annotations": {"object_id":"5381","object_type":"machine","boot_id":0,"cf:machine_id":"cf:909611570","version":1,"cf:date":"2023:07:24T15:23:35","cf:taint":"0","cf:jiffies":"0","cf:epoch":0,"u_sysname":"Linux","u_nodename":"localhost","u_release":"5.15.104-maybe-dirty","u_version":"#1 SMP PREEMPT Thu Jan 1 00:00:00 UTC 1970","u_machine":"x86_64","u_domainname":"localdomain","k_version":"0.8.0","l_version":"v0.5.5"}}
	{"type":"Entity","id":"EAAAAAAAABQFFQAAAAAAAAEAAAAykjc2AQAAAAAAAAA=","annotations": {"object_id":"5381","object_type":"machine","boot_id":1,"cf:machine_id":"cf:909611570","version":1,"cf:date":"2023:07:24T15:23:35","cf:taint":"0","cf:jiffies":"0","cf:epoch":0,"u_sysname":"Linux","u_nodename":"localhost","u_release":"5.15.104-maybe-dirty","u_version":"#1 SMP PREEMPT Thu Jan 1 00:00:00 UTC 1970","u_machine":"x86_64","u_domainname":"localdomain","k_version":"0.8.0","l_version":"v0.5.5"}}
	{"type":"Entity","id":"AAEAAAAAACBSowEAAAAAAAEAAAAykjc2AAAAAAAAAAA=","annotations": {"object_id":"107346","object_type":"file","boot_id":1,"cf:machine_id":"cf:909611570","version":0,"cf:date":"2023:07:24T15:23:42","cf:taint":"0","cf:jiffies":"4295006389","cf:epoch":1,"uid":0,"gid":0,"mode":"0x81b6","secctx":"u:object_r:shell_data_file:s0","ino":4799,"uuid":"e3a9f2df-aaed-46c8-9593-f0262d475eb7"}}
	{"type":"Activity","id":"AQAAAAAAAEAtowEAAAAAAAEAAAAykjc2AAAAAAAAAAA=","annotations": {"object_id":"107309","object_type":"task","boot_id":1,"cf:machine_id":"cf:909611570","version":0,"cf:date":"2023:07:24T15:23:42","cf:taint":"0","cf:jiffies":"4295006389","cf:epoch":1,"pid":2086,"vpid":2086,"utime":"1488","stime":"0","vm":"10822056","rss":"2580","hw_vm":"10822356","hw_rss":"2608","rbytes":"0","wbytes":"4096","cancel_wbytes":"0","utsns":4026531838,"ipcns":0,"mntns":4026532864,"pidns":4026531836,"netns":4026531840,"cgroupns":4026531835,"secctx":"u:object_r:unlabeled:s0"}}
	{"type":"Used","from":"AQAAAAAAAEAtowEAAAAAAAEAAAAykjc2AAAAAAAAAAA=","to":"AAEAAAAAACBSowEAAAAAAAEAAAAykjc2AAAAAAAAAAA=","annotations": {"id":"gAAAAAAAIIABAAAAAAAAAAEAAAAykjc2AAAAAAAAAAA=","relation_id":"1","relation_type":"open","boot_id":1,"cf:machine_id":"cf:909611570","cf:date":"2023:07:24T15:23:42","epoch":1,"jiffies":"4295006389","allowed":"true","flags":"0","task_id":"107309","from_type":"task","to_type":"file"}}
	{"type":"WasAssociatedWith","from":"AQAAAAAAAEAtowEAAAAAAAEAAAAykjc2AAAAAAAAAAA=","to":"EAAAAAAAABQFFQAAAAAAAAEAAAAykjc2AQAAAAAAAAA=","annotations": {"id":"AQAAAAAABIACAAAAAAAAAAEAAAAykjc2AAAAAAAAAAA=","relation_id":"2","relation_type":"ran_on","boot_id":1,"cf:machine_id":"cf:909611570","cf:date":"2023:07:24T15:23:42","epoch":1,"jiffies":"4295006389","allowed":"true","flags":"0","task_id":"107309","from_type":"task","to_type":"machine"}}
	{"type":"Entity","id":"AAAIAAAAACAuowEAAAAAAAEAAAAykjc2AAAAAAAAAAA=","annotations": {"object_id":"107310","object_type":"process_memory","boot_id":1,"cf:machine_id":"cf:909611570","version":0,"cf:date":"2023:07:24T15:23:42","cf:taint":"0","cf:jiffies":"4295006389","cf:epoch":1,"uid":0,"gid":0,"tgid":2086,"secctx":"u:r:su:s0"}}
	{"type":"WasGeneratedBy","from":"AAAIAAAAACAuowEAAAAAAAEAAAAykjc2AAAAAAAAAAA=","to":"AQAAAAAAAEAtowEAAAAAAAEAAAAykjc2AAAAAAAAAAA=","annotations": {"id":"gAAAAAAAQIADAAAAAAAAAAEAAAAykjc2AAAAAAAAAAA=","relation_id":"3","relation_type":"memory_write","boot_id":1,"cf:machine_id":"cf:909611570","cf:date":"2023:07:24T15:23:42","epoch":1,"jiffies":"4295006389","allowed":"true","flags":"0","task_id":"107309","from_type":"process_memory","to_type":"task"}}
	{"type":"WasDerivedFrom","from":"AAAIAAAAACAuowEAAAAAAAEAAAAykjc2AAAAAAAAAAA=","to":"AABAAAAAACRMq8i4LBprnAEAAAAykjc2AAAAAAAAAAA=","annotations": {"id":"AQAAAAAAgIAEAAAAAAAAAAEAAAAykjc2AAAAAAAAAAA=","relation_id":"4","relation_type":"named","boot_id":1,"cf:machine_id":"cf:909611570","cf:date":"2023:07:24T15:23:42","epoch":1,"jiffies":"4295006406","allowed":"true","flags":"0","task_id":"107309","from_type":"process_memory","to_type":"path"}}
	{"type":"WasDerivedFrom","from":"AAEAAAAAACBSowEAAAAAAAEAAAAykjc2AAAAAAAAAAA=","to":"AABAAAAAACTHrMjvSnm7vAEAAAAykjc2AAAAAAAAAAA=","annotations": {"id":"AQAAAAAAgIAFAAAAAAAAAAEAAAAykjc2AAAAAAAAAAA=","relation_id":"5","relation_type":"named","boot_id":1,"cf:machine_id":"cf:909611570","cf:date":"2023:07:24T15:23:42","epoch":1,"jiffies":"4295006409","allowed":"true","flags":"0","task_id":"107309","from_type":"file","to_type":"path"}}
	{"type":"Activity","id":"AQAAAAAAAEAtowEAAAAAAAEAAAAykjc2AQAAAAAAAAA=","annotations": {"object_id":"107309","object_type":"task","boot_id":1,"cf:machine_id":"cf:909611570","version":1,"cf:date":"2023:07:24T15:23:42","cf:taint":"0","cf:jiffies":"4295006415","cf:epoch":1,"pid":2086,"vpid":2086,"utime":"11271","stime":"22418","vm":"10822056","rss":"2580","hw_vm":"10822356","hw_rss":"2608","rbytes":"0","wbytes":"4096","cancel_wbytes":"0","utsns":4026531838,"ipcns":0,"mntns":4026532864,"pidns":4026531836,"netns":4026531840,"cgroupns":4026531835,"secctx":"u:object_r:unlabeled:s0"}}
	{"type":"WasInformedBy","from":"AQAAAAAAAEAtowEAAAAAAAEAAAAykjc2AQAAAAAAAAA=","to":"AQAAAAAAAEAtowEAAAAAAAEAAAAykjc2AAAAAAAAAAA=","annotations": {"id":"AgAAAAAAEIAGAAAAAAAAAAEAAAAykjc2AAAAAAAAAAA=","relation_id":"6","relation_type":"version_activity","boot_id":1,"cf:machine_id":"cf:909611570","cf:date":"2023:07:24T15:23:42","epoch":1,"jiffies":"4295006415","allowed":"true","flags":"0","task_id":"107309","from_type":"task","to_type":"task"}}
	{"type":"Used","from":"AQAAAAAAAEAtowEAAAAAAAEAAAAykjc2AQAAAAAAAAA=","to":"AAEAAAAAACBSowEAAAAAAAEAAAAykjc2AAAAAAAAAAA=","annotations": {"id":"AAgAAAAAIIAHAAAAAAAAAAEAAAAykjc2AAAAAAAAAAA=","relation_id":"7","relation_type":"getattr","boot_id":1,"cf:machine_id":"cf:909611570","cf:date":"2023:07:24T15:23:42","epoch":1,"jiffies":"4295006415","allowed":"true","flags":"0","task_id":"107309","from_type":"task","to_type":"file"}}
	{"type":"WasGeneratedBy","from":"AAAIAAAAACAuowEAAAAAAAEAAAAykjc2AAAAAAAAAAA=","to":"AQAAAAAAAEAtowEAAAAAAAEAAAAykjc2AQAAAAAAAAA=","annotations": {"id":"gAAAAAAAQIAIAAAAAAAAAAEAAAAykjc2AAAAAAAAAAA=","relation_id":"8","relation_type":"memory_write","boot_id":1,"cf:machine_id":"cf:909611570","cf:date":"2023:07:24T15:23:42","epoch":1,"jiffies":"4295006415","allowed":"true","flags":"0","task_id":"107309","from_type":"process_memory","to_type":"task"}}
	{"type":"Activity","id":"AQAAAAAAAEAtowEAAAAAAAEAAAAykjc2AgAAAAAAAAA=","annotations": {"object_id":"107309","object_type":"task","boot_id":1,"cf:machine_id":"cf:909611570","version":2,"cf:date":"2023:07:24T15:23:42","cf:taint":"0","cf:jiffies":"4295006423","cf:epoch":1,"pid":2086,"vpid":2086,"utime":"12846","stime":"38562","vm":"10822056","rss":"2580","hw_vm":"10822356","hw_rss":"2608","rbytes":"0","wbytes":"4096","cancel_wbytes":"0","utsns":4026531838,"ipcns":0,"mntns":4026532864,"pidns":4026531836,"netns":4026531840,"cgroupns":4026531835,"secctx":"u:object_r:unlabeled:s0"}}
	{"type":"WasInformedBy","from":"AQAAAAAAAEAtowEAAAAAAAEAAAAykjc2AgAAAAAAAAA=","to":"AQAAAAAAAEAtowEAAAAAAAEAAAAykjc2AQAAAAAAAAA=","annotations": {"id":"AgAAAAAAEIAJAAAAAAAAAAEAAAAykjc2AAAAAAAAAAA=","relation_id":"9","relation_type":"version_activity","boot_id":1,"cf:machine_id":"cf:909611570","cf:date":"2023:07:24T15:23:42","epoch":1,"jiffies":"4295006423","allowed":"true","flags":"0","task_id":"107309","from_type":"task","to_type":"task"}}
	{"type":"Used","from":"AQAAAAAAAEAtowEAAAAAAAEAAAAykjc2AgAAAAAAAAA=","to":"AAAIAAAAACAuowEAAAAAAAEAAAAykjc2AAAAAAAAAAA=","annotations": {"id":"BAAAAAAAIIAKAAAAAAAAAAEAAAAykjc2AAAAAAAAAAA=","relation_id":"10","relation_type":"memory_read","boot_id":1,"cf:machine_id":"cf:909611570","cf:date":"2023:07:24T15:23:42","epoch":1,"jiffies":"4295006423","allowed":"true","flags":"0","task_id":"107309","from_type":"task","to_type":"process_memory"}}
	{"type":"Entity","id":"AAEAAAAAACBSowEAAAAAAAEAAAAykjc2AQAAAAAAAAA=","annotations": {"object_id":"107346","object_type":"file","boot_id":1,"cf:machine_id":"cf:909611570","version":1,"cf:date":"2023:07:24T15:23:42","cf:taint":"0","cf:jiffies":"4295006423","cf:epoch":1,"uid":0,"gid":0,"mode":"0x81b6","secctx":"u:object_r:shell_data_file:s0","ino":4799,"uuid":"e3a9f2df-aaed-46c8-9593-f0262d475eb7"}}
	{"type":"WasDerivedFrom","from":"AAEAAAAAACBSowEAAAAAAAEAAAAykjc2AQAAAAAAAAA=","to":"AAEAAAAAACBSowEAAAAAAAEAAAAykjc2AAAAAAAAAAA=","annotations": {"id":"AgAAAAAAgIALAAAAAAAAAAEAAAAykjc2AAAAAAAAAAA=","relation_id":"11","relation_type":"version_entity","boot_id":1,"cf:machine_id":"cf:909611570","cf:date":"2023:07:24T15:23:42","epoch":1,"jiffies":"4295006423","allowed":"true","flags":"0","task_id":"107309","from_type":"file","to_type":"file"}}
	{"type":"WasGeneratedBy","from":"AAEAAAAAACBSowEAAAAAAAEAAAAykjc2AQAAAAAAAAA=","to":"AQAAAAAAAEAtowEAAAAAAAEAAAAykjc2AgAAAAAAAAA=","annotations": {"id":"IAAAAAAAQIAMAAAAAAAAAAEAAAAykjc2AAAAAAAAAAA=","relation_id":"12","relation_type":"write","boot_id":1,"cf:machine_id":"cf:909611570","cf:date":"2023:07:24T15:23:42","epoch":1,"jiffies":"4295006423","allowed":"true","flags":"2","task_id":"107309","from_type":"file","to_type":"task"}}
	{"type":"Entity","id":"EAAAAAAAABQFFQAAAAAAAAEAAAAykjc2AQAAAAAAAAA=","annotations": {"object_id":"5381","object_type":"machine","boot_id":1,"cf:machine_id":"cf:909611570","version":1,"cf:date":"2023:07:24T15:23:42","cf:taint":"0","cf:jiffies":"4295006389","cf:epoch":1,"u_sysname":"Linux","u_nodename":"localhost","u_release":"5.15.104-maybe-dirty","u_version":"#1 SMP PREEMPT Thu Jan 1 00:00:00 UTC 1970","u_machine":"x86_64","u_domainname":"localdomain","k_version":"0.8.0","l_version":"v0.5.5"}}
	{"type":"Entity","id":"AABAAAAAACRMq8i4LBprnAEAAAAykjc2AAAAAAAAAAA=","annotations": {"object_id":"11271131271805840204","object_type":"path","boot_id":1,"cf:machine_id":"cf:909611570","version":0,"cf:date":"2023:07:24T15:23:42","cf:taint":"0","cf:jiffies":"4295006405","cf:epoch":1,"pathname":"/data/local/tmp/camflowexample"}}
	{"type":"Entity","id":"AABAAAAAACTHrMjvSnm7vAEAAAAykjc2AAAAAAAAAAA=","annotations": {"object_id":"13599596862532791495","object_type":"path","boot_id":1,"cf:machine_id":"cf:909611570","version":0,"cf:date":"2023:07:24T15:23:42","cf:taint":"0","cf:jiffies":"4295006409","cf:epoch":1,"pathname":"/local/tmp/HelloFromC.txt"}}
	{"type":"Activity","id":"AQAAAAAAAEAtowEAAAAAAAEAAAAykjc2AwAAAAAAAAA=","annotations": {"object_id":"107309","object_type":"task","boot_id":1,"cf:machine_id":"cf:909611570","version":3,"cf:date":"2023:07:24T15:23:43","cf:taint":"0","cf:jiffies":"4295006440","cf:epoch":1,"pid":2086,"vpid":2086,"utime":"12846","stime":"38562","vm":"10822056","rss":"2580","hw_vm":"10822356","hw_rss":"2608","rbytes":"0","wbytes":"4096","cancel_wbytes":"0","utsns":4026531838,"ipcns":0,"mntns":4026532864,"pidns":4026531836,"netns":4026531840,"cgroupns":4026531835,"secctx":"u:object_r:unlabeled:s0"}}
	{"type":"WasInformedBy","from":"AQAAAAAAAEAtowEAAAAAAAEAAAAykjc2AwAAAAAAAAA=","to":"AQAAAAAAAEAtowEAAAAAAAEAAAAykjc2AgAAAAAAAAA=","annotations": {"id":"BAAAAAAAEIANAAAAAAAAAAEAAAAykjc2AAAAAAAAAAA=","relation_id":"13","relation_type":"terminate_task","boot_id":1,"cf:machine_id":"cf:909611570","cf:date":"2023:07:24T15:23:43","epoch":1,"jiffies":"4295006442","allowed":"true","flags":"0","task_id":"34","from_type":"task","to_type":"task"}}
	{"type":"Entity","id":"AAAIAAAAACAuowEAAAAAAAEAAAAykjc2AQAAAAAAAAA=","annotations": {"object_id":"107310","object_type":"process_memory","boot_id":1,"cf:machine_id":"cf:909611570","version":1,"cf:date":"2023:07:24T15:23:43","cf:taint":"0","cf:jiffies":"4295006442","cf:epoch":1,"uid":0,"gid":0,"tgid":2086,"secctx":"u:r:su:s0"}}
	{"type":"WasDerivedFrom","from":"AAAIAAAAACAuowEAAAAAAAEAAAAykjc2AQAAAAAAAAA=","to":"AAAIAAAAACAuowEAAAAAAAEAAAAykjc2AAAAAAAAAAA=","annotations": {"id":"ACAAAAAAgIAOAAAAAAAAAAEAAAAykjc2AAAAAAAAAAA=","relation_id":"14","relation_type":"terminate_proc","boot_id":1,"cf:machine_id":"cf:909611570","cf:date":"2023:07:24T15:23:43","epoch":1,"jiffies":"4295006442","allowed":"true","flags":"0","task_id":"34","from_type":"process_memory","to_type":"process_memory"}}
    	```
    </details>

3. Using Camflow Android Log Parser to parse and visualize the generated log
	- **Camflow Log Parser Github Link**: https://github.com/MichaelXi3/android-provenance-parser 

![provG.jpg](https://s2.loli.net/2023/07/29/obi543zrtf2LGXl.jpg)
    

## Built With

* [Bazel](https://bazel.build/) - The build and test tool developed by Google to automate build processes for large-scale software such as Android Kernel and Modules
* [CMake](https://www.jetbrains.com/help/clion/cmakelists-txt-file.html) - The build system used for building Camflow Android user space daemons and shared library
* [AndroidNDK](https://rometools.github.io/rome/) - A cross-compiling tool for compiling code written in C/C++ for Android


## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details


