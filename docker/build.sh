#!/bin/sh
IMAGE_NAME=jiegec/tcp-lab-$(uname -m)
sudo docker build -t $IMAGE_NAME . && sudo docker push $IMAGE_NAME
