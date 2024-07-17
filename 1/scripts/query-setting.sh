#!/bin/bash

repository_url="$1"
language="$2"
directory_name=$(basename "$repository_url")
                                                                                                                                                                                                                                                          
mkdir "/home/codevuln/target-repo/$directory_name"
mkdir "/home/codevuln/target-repo/$directory_name/codeql"
mkdir "/home/codevuln/target-repo/$directory_name/semgrep"
mkdir "/home/codevuln/target-repo/$directory_name/sonarqube"
mkdir "/home/codevuln/target-repo/$directory_name/scan_result"

clone_directory_name="$directory_name"-repo
mkdir -p /home/codevuln/target-repo/$directory_name/$clone_directory_name   
git clone --depth=1 "$repository_url" "/home/codevuln/target-repo/$directory_name/$clone_directory_name"


./scripts/semgrep.sh $directory_name $clone_directory_name &
# sonarqube.sh
# codeql.sh
# 

wait

echo "!!!!!!!! scan ok !!!!!!!!"

exit 0