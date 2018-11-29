import os
import re
import requests
import subprocess
import sys

from string import Template

nvd_data_feeds_url = 'https://nvd.nist.gov/vuln/data-feeds'

# get gzipped json data URLs for years 2000-2999
nvd_json_pattern = re.compile('(https:\/\/nvd\.nist\.gov\/feeds\/json\/cve\/1\.0\/nvdcve-1\.0-2\d{3}.json.gz)')

nvd_cypher_template = Template('''
CREATE CONSTRAINT ON (cve:CVE) ASSERT cve.name IS UNIQUE;
CREATE CONSTRAINT ON (cvss:CVSS) ASSERT cvss.name IS UNIQUE;
CREATE CONSTRAINT ON (attack_vector:AttackVector) ASSERT attack_vector.name IS UNIQUE;
CREATE CONSTRAINT ON (vendor:Vendor) ASSERT vendor.name IS UNIQUE;
CREATE CONSTRAINT ON (product:Product) ASSERT product.name IS UNIQUE;
CREATE CONSTRAINT ON (product_version:ProductVersion) ASSERT product_version.name IS UNIQUE;

CALL apoc.load.json('file:///var/lib/neo4j/code/$nvd_file_name') YIELD value AS nvd
UNWIND nvd.CVE_Items as vuln
MERGE (cve:CVE {
    attack_complexity: COALESCE(vuln.impact.baseMetricV3.cvssV3.attackComplexity, 'NA'),
    availability_impact: COALESCE(vuln.impact.baseMetricV3.cvssV3.availabilityImpact, 'NA'),
    base_score: COALESCE(vuln.impact.baseMetricV3.cvssV3.baseScore, -1),
    base_severity: COALESCE(vuln.impact.baseMetricV3.cvssV3.baseSeverity, 'NA'),
    confidentiality_impact: COALESCE(vuln.impact.baseMetricV3.cvssV3.confidentialityImpact, 'NA'),
    description: [desc IN vuln.cve.description.description_data WHERE desc.lang = 'en'| desc.value],
    exploitability_score: COALESCE(vuln.impact.baseMetricV3.exploitabilityScore, -1),
    impact_score: COALESCE(vuln.impact.baseMetricV3.impactScore, -1),
    integrity_impact: COALESCE(vuln.impact.baseMetricV3.cvssV3.integrityImpact, 'NA'),
    name: vuln.cve.CVE_data_meta.ID,
    privileges_required: COALESCE(vuln.impact.baseMetricV3.cvssV3.privilegesRequired, 'NA'),
    published: apoc.date.fromISO8601(apoc.text.replace(vuln.publishedDate,'Z$',':00Z')),
    scope: COALESCE(vuln.impact.baseMetricV3.cvssV3.scope, 'NA'),
    user_interaction: COALESCE(vuln.impact.baseMetricV3.cvssV3.userInteraction, 'NA')
    })

FOREACH (cvss_vector_string IN vuln.impact.baseMetricV3.cvssV3.vectorString |
    MERGE (cvss:CVSS {
        name: apoc.text.replace(cvss_vector_string,'CVSS:3.0/','')
        })
    MERGE (cve)-[:IS_ENCODED_AS]->(cvss)
    )

FOREACH (cve_attack_vector IN vuln.impact.baseMetricV3.cvssV3.attackVector |
    MERGE (attack_vector:AttackVector {name: cve_attack_vector})
    MERGE (cve)-[:IS_ATTACKABLE_THROUGH]-(attack_vector)
    )

FOREACH (vendor_data IN vuln.cve.affects.vendor.vendor_data |
        MERGE (vendor:Vendor {name: vendor_data.vendor_name})

        FOREACH (product_data IN vendor_data.product.product_data |
            MERGE (product:Product {name: product_data.product_name})
            MERGE (product)-[:MADE_BY]->(vendor)

            FOREACH (version_data IN product_data.version.version_data |
                MERGE (product_version:ProductVersion {
                    name: vendor_data.vendor_name + '_' + product_data.product_name + '_' + version_data.version_affected + version_data.version_value,
                    version_value: version_data.version_value
                    })
                MERGE (product_version)-[:VERSION_OF]-(product)
                MERGE (cve)-[:AFFECTS]->(product_version))
            )
    );
''')

if __name__ == '__main__':
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