#!/bin/bash

set -ex

# Install all BCC dependencies
# Source: https://github.com/iovisor/bcc/blob/master/INSTALL.md#ubuntu---source

# For Bionic (18.04 LTS)
sudo apt-get -y install bison build-essential cmake flex git libedit-dev \
  libllvm6.0 llvm-6.0-dev libclang-6.0-dev python zlib1g-dev libelf-dev

# For Lua support
sudo apt-get -y install luajit luajit-5.1-dev

# Install and compile BCC
git clone https://github.com/iovisor/bcc.git
mkdir bcc/build; cd bcc/build
cmake ..
make
sudo make install

# Build python3 binding
apt install python3.6-distutils
cmake -DPYTHON_CMD=python3 .. 
pushd src/python/
make
sudo make install
popd