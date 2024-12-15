#!/usr/bin/env bash

# Originally copied from https://github.com/nicc777/localstack-cheatsheet/blob/c87fb50d0cbe78a75033d704837f1c7cf948c652/scripts/package_lambda_function.sh#L7

help_message () {
    script_name=${0##*/}
    echo "Usage: ${script_name} -f STRING -p STRING [-h]"
    echo
    echo "  -f STRING   - Path to the Python script to package as AWS Lambda function"
    echo "  -p STRING   - Package name (without any extensions)"
    echo "  -h          - Display help"
    echo
    exit
}

display_help=0
pyhton_script_path=""
package_name="python_lambda_function"

while getopts hf:p: flag
do
    case "${flag}" in
        h) display_help=1;;
        f) pyhton_script_path=${OPTARG};;
        p) package_name=${OPTARG};;
    esac
done

if [ "$display_help" -gt "0" ]; then
    help_message
fi

if [ -z "$pyhton_script_path" ]
then
      echo "ERROR: When supplying the -f parameter, a STRING value must be provided. Use the -h parameter for help."
      exit
fi

if ! test -f $pyhton_script_path; then
  echo "ERROR: File does not exist."
  exit
fi

echo "Starting to package AWS Lamda Function (Python)"

package_dir="/tmp/package_`cat /proc/sys/kernel/random/uuid | sed 's/[-]//g'`"

echo "  Creating temporary packaging directory: ${package_dir}"
mkdir -p $package_dir

echo "  Copy Python lambda function to package directory"
cp $pyhton_script_path $package_dir

requirements_file="`dirname ${pyhton_script_path}`/requirements.txt"
echo "  Checking for the presence of requirements.txt in the same directory as the script: ${requirements_file}"
if test -f $requirements_file; then
    echo "    Adding requirements..."
    cp $requirements_file $package_dir

    echo "    Creating Python virtual environment"
    cd $package_dir
    python3 -m venv venv
    . venv/bin/activate

    echo "    Adding required packages"
    mkdir package
    pip3 install --target ./package -r requirements.txt
    cd package
    zip -r ../${package_name}.zip .

    cd ..
    zip ${package_name}.zip `basename ${pyhton_script_path}`
else
    cd $package_dir
    zip ${package_name}.zip `basename ${pyhton_script_path}`
fi

echo "DONE"
echo
echo "  Package Directory : ${package_dir}"
echo "  Package File      : ${package_dir}/${package_name}.zip"
echo




