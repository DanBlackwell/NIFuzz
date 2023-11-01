#!/bin/bash

./leakiest > leakiest_obs.txt 
for I in $(seq 1 10000); do
	./leakiest >> leakiest_obs.txt
done
java -jar ../../../LeakiEst-1.4.9/leakiest-1.4.9.jar -cfg leakiest_config.txt
