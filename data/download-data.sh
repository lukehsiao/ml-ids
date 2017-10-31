#!/bin/bash

# URL format:
# https://www.ll.mit.edu/ideval/data/1999/training/week2/monday/outside.tcpdump.gz

base_url="https://www.ll.mit.edu/ideval/data/1999/"

mkdir -p training
mkdir -p testing

echo "Downloading the DARPA 1999 IDS Dataset..."

for dataset in "training" "testing"; do
  if [ $dataset = "training" ]; then
    for week in "week1" "week2" "week3"; do
      for weekday in "monday" "tuesday" "wednesday" "thursday" "friday"; do

        echo wget $base_url$dataset/$week/$weekday/outside.tcpdump.gz
        wget $base_url$dataset/$week/$weekday/outside.tcpdump.gz -O $dataset/$week\_$weekday\_outside.gz -q
        gunzip $dataset/$week\_$weekday\_outside.gz
        
        echo wget $base_url$dataset/$week/$weekday/inside.tcpdump.gz
        wget $base_url$dataset/$week/$weekday/inside.tcpdump.gz -O $dataset/$week\_$weekday\_inside.gz -q
        gunzip $dataset/$week\_$weekday\_inside.gz
      done
    done
  else 
    for week in "week4" "week5"; do
      for weekday in "monday" "tuesday" "wednesday" "thursday" "friday"; do

        echo wget $base_url$dataset/$week/$weekday/outside.tcpdump.gz
        wget $base_url$dataset/$week/$weekday/outside.tcpdump.gz -O $dataset/$week\_$weekday\_outside.gz -q
        gunzip $dataset/$week\_$weekday\_outside.gz

        echo wget $base_url$dataset/$week/$weekday/inside.tcpdump.gz
        wget $base_url$dataset/$week/$weekday/inside.tcpdump.gz -O $dataset/$week\_$weekday\_inside.gz -q
        gunzip $dataset/$week\_$weekday\_inside.gz
      done
    done
  fi
done

echo "Done!"

