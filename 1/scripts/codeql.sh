#!/bin/bash

directory_name="$1"
clone_directory_name="$2"
language="$3"

echo -e "\033[32m[+] Create database\033[0m $@"
sleep 2
cd ~

codeql database create --language="$language" --source-root="/home/codevuln/target-repo/$directory_name/$clone_directory_name" "/home/codevuln/target-repo/$directory_name/codeql/codeql-db-$directory_name"
        
codeql database analyze "/home/codevuln/target-repo/$directory_name/codeql/codeql-db-$directory_name" "/home/codevuln/codeql/codeql-repo/$language/ql/src/Security/CWE-089" --format=csv --output="/home/codevuln/target-repo/$directory_name/codeql/codeql1.csv"
codeql database analyze "/home/codevuln/target-repo/$directory_name/codeql/codeql-db-$directory_name" "/home/codevuln/codeql/codeql-repo/$language/ql/src/Security/CWE-079" --format=csv --output="/home/codevuln/target-repo/$directory_name/codeql/codeql2.csv"
echo "CSV output saved to $csv_output_file"

python3 /home/codevuln/codeql/codeql_integrate_csv.py "$directory_name" "$clone_directory_name"
echo "Python script executed successfully."

echo "Scan completed for $directory_name" > "/home/codevuln/codeql_complete.txt"

exit 0