#!/bin/bash

dockerfile_dir=../dockerfiles
image_name=trojan_server
tag=v1

docker build -f ${dockerfile_dir}/Dockerfile.${image_name} -t ${image_name}:${tag} ${dockerfile_dir}/content
