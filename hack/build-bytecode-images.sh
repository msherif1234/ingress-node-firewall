#!/bin/bash

docker build \
 --build-arg BYTECODE_FILENAME=bpf_x86_bpfel.o \
 -f ./Containerfile.bytecode \
 ./pkg/ebpf -t $IMAGE_INFW_BC
