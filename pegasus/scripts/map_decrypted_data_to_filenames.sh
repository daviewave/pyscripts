#!/bin/bash

pegasus_dir=$PPATH
manifest_path=$1
filename=$2

if [ -z $manifest_path  ]; then
  read "enter the filepath for the manifest.json file to analyze: " manifest_path
fi

if [ -z $filename  ]; then
  read "enter the name of the file you want to save to: " filename
fi

save_path="$pegasus_dir/results/mappings/$filename.txt"

jq -r '.[] | "\(.file_id) \(.relative_path)"' $manifest_path > $save_path

echo -e "\nfilename mappings saved to: $save_path"


