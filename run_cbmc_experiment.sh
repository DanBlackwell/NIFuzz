#!/bin/bash

set -e 

if [[ $(id -u) -ne 0 ]]; then 
  echo "Please run as root"
  exit
fi

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
cd $SCRIPT_DIR

echo "Building CBMC model checking experiment"
NAME="cbmc_leaks_exp"

IMAGE="${NAME}_image"
docker build -t $IMAGE -f Dockerfile.cbmc .

docker container run --shm-size=2g --ulimit core=0 --name $NAME $IMAGE

OUTPUT_DIR="results/CBMC/$(hostname)_$(date -d "today" +"%Y_%m_%d_%H%M")"
mkdir -p $OUTPUT_DIR
docker cp $NAME:/home/results/. $OUTPUT_DIR/ && docker rm $NAME

chown -R dblackwell $OUTPUT_DIR

echo "COMPLETED EXPERIMENT - COPIED RESULTS INTO $OUTPUT_DIR"

