#!/bin/bash

./leakiest > leakiest_obs.txt 
java -jar ../../../LeakiEst-1.4.9/leakiest-1.4.9.jar -cfg leakiest_config.txt
