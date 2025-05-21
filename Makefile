# Makefile for ETSI TS 103 744

# Detect the operating system
UNAME_S := $(shell uname -s)

# Compiler and flags
CC := gcc
CFLAGS := -Wall
LDFLAGS := -lcrypto -loqs

# Directories
WORKSPACE := $(shell pwd)/quantumsafe
BUILD_DIR := $(WORKSPACE)/build
LIB_DIR := $(BUILD_DIR)/lib
SRC_DIR := $(shell pwd)
OBJ_DIR := $(shell pwd)/obj
BIN_DIR := $(shell pwd)/bin

# Source and object files
SRCS := $(wildcard $(SRC_DIR)/*.c)
OBJS := $(SRCS:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)

# Target executable
TARGET := $(BIN_DIR)/etsi-hkex-test

# Dependencies
DEPS := openssl liboqs oqs-provider

# Phony targets
.PHONY: all update install setup openssl liboqs oqs-provider test-oqs update-ldconfig compile update-ldconfig clean
#

# Default target
all: update install setup openssl liboqs oqs-provider test-oqs compile run
# all: update install setup openssl liboqs oqs-provider test-oqs compile 


# Update and install necessary packages (OS-specific)
update:
ifeq ($(UNAME_S),Linux)
	sudo apt update
	sudo apt -y install git build-essential perl cmake autoconf libtool zlib1g-dev
else ifeq ($(UNAME_S),Darwin)
	brew update
	brew install git cmake autoconf automake libtool
endif

# Setup workspace and build directory
setup:
	mkdir -p $(LIB_DIR)

# Clone and build OpenSSL
openssl:
	@if [ ! -d $(WORKSPACE)/openssl ]; then \
		echo "Cloning and building OpenSSL..."; \
		cd $(WORKSPACE) && \
		git clone -b openssl-3.2 https://github.com/openssl/openssl && \
		cd openssl && \
		./Configure \
 			--prefix=$(BUILD_DIR) \
  			no-ssl no-tls1 no-tls1_1 no-afalgeng \
  			no-shared threads -lm && \
        make && \
		echo "OpenSSL cloned and built successfully."; \
	else \
		echo "OpenSSL directory already exists. Skipping clone and build."; \
	fi

# Clone and build liboqs
liboqs:
	@if [ ! -d $(WORKSPACE)/liboqs ]; then \
		echo "Cloning and building liboqs..."; \
		cd $(WORKSPACE) && \
		git clone https://github.com/open-quantum-safe/liboqs  && \
		cd liboqs  && \
		git checkout 0.13.0-release && \
		mkdir build && cd build  && \
		cmake \
			-DBUILD_SHARED_LIBS=ON \
			-DOQS_USE_OPENSSL=OFF \
			-DCMAKE_BUILD_TYPE=Release \
			-DOQS_BUILD_ONLY_LIB=ON \
			-DOQS_DIST_BUILD=ON \
			..   && \
		make  && \
		echo "liboqs cloned and built successfully."; \
	else \
		echo "liboqs directory already exists. Skipping clone and build."; \
	fi

# Clone and build oqs-provider
oqs-provider:
	@if [ ! -d $(WORKSPACE)/oqs-provider ]; then \
		echo "Cloning and building oqs-provider..." ; \
		cd $(WORKSPACE) && \
		git clone https://github.com/open-quantum-safe/oqs-provider  && \
		cd oqs-provider && \
		git checkout 0.7.0-release && \
		liboqs_DIR=$(BUILD_DIR) cmake \
			-DOPENSSL_ROOT_DIR=$(WORKSPACE)/openssl/ \
			-DCMAKE_BUILD_TYPE=Release \
			-S . \
			-B $(BUILD_DIR)  && \
		sudo cmake --build $(BUILD_DIR) ; \
		echo "oqs-provider cloned, built, and configured successfully."; \
	else \
		echo "oqs-provider directory already exists. Skipping clone and build."; \
	fi

# Test OQS provider
test-oqs:
	@echo "Testing OQS provider..."
	@export OPENSSL_MODULES=$(BUILD_DIR)/lib && openssl list -kem-algorithms -provider oqsprovider

# Compile the project
compile:
	@echo "Compiling the project..."
	gcc -Wall -o etsi-hkex-test main.c crypto.c qshkex.c -lcrypto -loqs \
		-I$(WORKSPACE)/liboqs/build/include/ \
		-L$(BUILD_DIR)/lib
	@echo "Compilation completed. Executable: etsi-hkex-test"


# Run the compiled program
run: compile
	@echo "Running etsi-hkex-test..."
ifeq ($(UNAME_S),Linux)
	@export OPENSSL_MODULES=$(BUILD_DIR)/lib  && ./etsi-hkex-test
else ifeq ($(UNAME_S),Darwin)
	@DYLD_LIBRARY_PATH=$(BUILD_DIR)/lib:$$DYLD_LIBRARY_PATH ./etsi-hkex-test
endif

# Clean up
clean:
	rm -rf $(WORKSPACE)
	rm -f etsi-hkex-test
