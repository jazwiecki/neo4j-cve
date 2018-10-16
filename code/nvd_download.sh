#!/bin/sh

# https://gist.github.com/christiangalsterer/5f55389b9c50c74c31b9

# Copyright 2015 Christian Galsterer
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

# Downloads the National Vulnerability Database files from https://nvd.nist.gov
# If no parameter is specified the files will be downloaded to the current directory. Alternativly a target directory can be specified as an argument to the script.

# export https_proxy=<ADD HERE YOUR PROXY IF NEEDED>

START_YEAR=2002
END_YEAR=$(date +'%Y')
DOWNLOAD_DIR=.

CVE_12_MODIFIED_URL='https://nvd.nist.gov/download/nvdcve-Modified.xml.gz'
CVE_20_MODIFIED_URL='https://nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-Modified.xml.gz'
CVE_12_BASE_URL='https://nvd.nist.gov/download/nvdcve-%d.xml.gz'
CVE_20_BASE_URL='https://nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-%d.xml.gz'

if [[ $# -eq 1 ]] ; then
    DOWNLOAD_DIR=$1
fi

START_TIME=$(date +%s)

download () {
    echo
    echo "Starting download of $1"
    OUTPUT_FILE=${1##*/}
    wget --no-check-certificate $1 -P $DOWNLOAD_DIR -O $OUTPUT_FILE
    if [ "$?" != 0 ]; then
        echo "ERROR: Downloading of $1 failed."
        exit 1
    fi

    echo "Extracting $OUTPUT_FILE"
    gzip -df $OUTPUT_FILE

    if [ "$?" != 0 ]; then
        echo "ERROR: Extracting of $OUTPUT_FILE failed."
        exit 1
    fi

    echo "Download of $1 sucessfully completed."
    echo
}

echo "Starting download of NVD files ..."
download "$CVE_12_MODIFIED_URL"
download "$CVE_20_MODIFIED_URL"

for ((i=$START_YEAR;i<=$END_YEAR;i++));
do
    download "${CVE_12_BASE_URL//%d/$i}"

done

for ((i=$START_YEAR;i<=$END_YEAR;i++));
do
    download "${CVE_20_BASE_URL//%d/$i}"
done

END_TIME=$(date +%s)
DURATION=$((END_TIME-START_TIME))
echo "Download of NVD files successfully completed in $DURATION seconds."