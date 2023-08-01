#!/bin/bash

# Define base directory
BASE_DIR=~/android-kernel-5.15

echo "Starting script..."

# Step 1: Change to the target directory
echo "Changing directory to ${BASE_DIR}/common/arch/x86/configs..."
cd ${BASE_DIR}/common/arch/x86/configs

# Step 2: Modify the gki_defconfig file using sed
echo "Modifying gki_defconfig file..."
sed -i '/CONFIG_RELAY=y/d' gki_defconfig
sed -i '/CONFIG_NETFILTER=y/d' gki_defconfig
sed -i '/CONFIG_SECURITYFS=y/d' gki_defconfig
sed -i '/CONFIG_SECURITY_NETWORK=y/d' gki_defconfig
echo "gki_defconfig file modified."

# Step 3: Change to the /common directory
echo "Changing directory to ${BASE_DIR}/common..."
cd ${BASE_DIR}/common

# Step 4: Run make mrproper
echo "Running make mrproper..."
make mrproper

# Step 5: Move back to base dir
echo "Changing directory back to ${BASE_DIR}/..."
cd ${BASE_DIR}/

echo "Script completed successfully."

