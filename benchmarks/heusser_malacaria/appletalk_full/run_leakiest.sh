#!/bin/bash

set -e

time ./leakiest > leakiest_obs.txt 
time java -jar ../../../LeakiEst-1.4.9/leakiest-1.4.9.jar -cfg leakiest_config.txt
