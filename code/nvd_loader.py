import os
import re
import requests
import subprocess
import sys

from string import Template

def load_template(filename):
    if os.path.isfile(filename):
        with open(filename, 'r') as template_file:
            template_string = template_file.read()
            if template_string:
                return Template(template_string)

if __name__ == '__main__':

    ######
    # initialize a couple variables

    nvd_data_feeds_url = 'https://nvd.nist.gov/vuln/data-feeds'

    # this template is specific to the 1.0 version of the NVD JSON feed
    nvd_cypher_template = load_template('code/loader-template.cypher')


    # this pattern will get gzipped json data URLs for years 2000-2999
    # hard-coding the version number in the file name pattern as "1.0"
    # should help ensure that this script doesn't process any NVD feeds
    # that don't match the pattern expected in nvd_cypher_template
    nvd_json_pattern = re.compile('(https:\/\/nvd\.nist\.gov\/feeds\/json\/cve\/1\.0\/nvdcve-1\.0-2\d{3}.json.gz)')

    # end variable initialization
    ######


    print(f'Fetching NVD json feed URLs from {nvd_data_feeds_url}')
    sys.stdout.flush()
    nvd_feeds_page = requests.get(nvd_data_feeds_url)
    nvd_json_files = re.finditer(nvd_json_pattern, nvd_feeds_page.content.decode('utf-8'))
    if nvd_feeds_page.status_code == 200:
        for nvd_file_url_match in nvd_json_files:
            nvd_file_url = nvd_file_url_match.group(0)
            nvd_file_name_gzip = nvd_file_url.split('/')[-1]
            nvd_file_name = nvd_file_name_gzip.strip('.gz')
            print(f'Fetching {nvd_file_name_gzip}')
            sys.stdout.flush()
            nvd_file_contents = requests.get(nvd_file_url, stream=True)
            if nvd_file_contents.status_code == 200:
                with open(nvd_file_name_gzip, 'wb') as nvd_file:
                    for chunk in nvd_file_contents.iter_content(chunk_size=1024):
                        if chunk:
                            nvd_file.write(chunk)
                # by default this should unzip to nvd_file_name
                subprocess.run(['gunzip', nvd_file_name_gzip])
            else:
                print(f'Error fetching {nvd_file_contents}')
            print(f'Loading {nvd_file_name} to Neo4j')
            sys.stdout.flush()
            cypher_shell_result = subprocess.run(['cypher-shell'],
                                                input=nvd_cypher_template.safe_substitute(nvd_file_name = nvd_file_name).encode('utf-8'),
                                                stdout = subprocess.PIPE, stderr = subprocess.PIPE)
            os.remove(nvd_file_name)
            if cypher_shell_result.returncode == 0:
                print(f'Successfully loaded {nvd_file_name}')
            else:
                sys.exit('Error loading {}: {}'.format(nvd_file_name, cypher_shell_result))
    else:
        sys.exit('Error fetching NVD data feeds page.')
    print('Finished loading NVD json.')