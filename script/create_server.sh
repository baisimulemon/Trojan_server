#!/bin/bash

docker run -dit --privileged --init --net=bridge -v /etc/localtime:/etc/localtime:ro -v /etc/timezone:/etc/timezone:ro --name=trojan_server --hostname=trojan_server trojan_server:v1
