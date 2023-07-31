# For more information about using CMake with Android Studio, read the
# documentation: https://d.android.com/studio/projects/add-native-code.html

# Sets the minimum version of CMake required to build the native library.
cmake_minimum_required(VERSION 3.22.1)

set(CMAKE_VERBOSE_MAKEFILE ON)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -v")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -v")

# Declares and names the project.
project("provenance")

# Step_1: build .so shared library
# Note that in android cuttlefish, you must cp .so library to /system/lib64
add_subdirectory(provenancelib)

# Step_2: link the .so shared library to camflowd executable
add_subdirectory(camflowdd)

# Step_3: build the camflow example executable
add_subdirectory(example)

# Step_4: build the camconfd executable
add_subdirectory(camconfd)

# Step_5, build the camflow-cli executable
add_subdirectory(camflow-cli)