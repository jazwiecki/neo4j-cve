# neo4j-cve
Graph database version of the [NVD CVE database](http://nvd.nist.gov) by
Jim Jazwiecki and Nathan Kluth, built using [the official Neo4j Docker image](https://neo4j.com/developer/docker/)
([GitHub](https://github.com/neo4j/docker-neo4j)). Please post feedback/questions
as GitHub issues.

## Setup

1. Run `docker-compose build` to download the Neo4j Docker image and install the APOC plugin
2. Run `docker-compose up` to start Neo4j
3. Run `docker exec -t nvdgraph python3 code/nvd_loader.py` to load the NVD data feeds

## Starting Neo4j

Run `docker-compose up` to start the container. Open [http://localhost:7474/browser/](http://localhost:7474/browser/)
to start an interactive browser-based session. By default, there is no authentication
set, but it can be set in Docker from your local environent by setting the
`NEO4J_AUTH` environment variable to a `username/password` pair. For example:

```
export NEO4J_AUTH="admin/password"
```

## Python Setup

There are two different Python environments used in this project. `code/requirements.txt`
is used by the Neo4j container to load the NVD data to Neo4j, but doesn't include the
Python Neo4j driver, because it is not needed by `nvd_loader.py`. To work with
the Neo4j database locally using Python and the official Neo4j Python package,
create a virtual environment and run `pip install -r requirements.txt`.

## Python Usage

### Connecting to the DB

The following will work out of the box, unless you've set the NEO4J_AUTH
environment variable:

```driver = GraphDatabase.driver('bolt://localhost')```

Then, to create a new session:

```s = driver.session()```

### Queries

To run a query from within a session:

```s.run("CREATE (a:Greeting) SET a.message = 'Hello World' RETURN a.message + ', from node ' + id(a)")```

## Loading CVE Data

https://nvd.nist.gov/vuln/data-feeds lists all feeds of data. `nvd_loader.py` will
fetch this page, parse it to identify complete (i.e. not partial/update) v1.0 gzipped
JSON feed URLs, fetch the files one by one, unpack, and load them using the template
specified in `loader-template.cypher`.

### loader-template.cypher

First, the script will set uniqueness constraints on our nodes, implicitly creating
indices. `$nvd_file_name` will be replaced during execution with the name of the
JSON file being loaded. Then we loop over all the individual CVEs.


### Exploring data
Run this command to load a test file, `code/nvd-test-samples.json`, which contains
a couple sample CVEs:
```
CALL apoc.load.json('file:///var/lib/neo4j/code/nvd-test-samples.json') YIELD value AS nvd
UNWIND nvd.CVE_Items as vuln
RETURN vuln
```

See https://neo4j-contrib.github.io/neo4j-apoc-procedures/
for more details on `apoc.load.json`.

### Creating nodes

With `apoc.load.json`:
```
CALL apoc.load.json('file:///var/lib/neo4j/code/nvd-test-samples.json') YIELD value AS nvd
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
        name: apoc.text.replace(cvss_vector_string,'CVSS\\:3\\.0\\/','')
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
    )
```


get loss_types and range
```
call apoc.load.xmlSimple("file:///var/lib/neo4j/nvd-3-items.xml") YIELD value AS nvd
UNWIND nvd._entry AS vuln
RETURN vuln.name,
    [vuln_range IN keys(vuln._range) WHERE vuln_range <> '_type' | vuln._range[vuln_range]._type] AS vuln_ranges,
    [loss_type IN keys(vuln._loss_types) WHERE loss_type <> '_type' | vuln._loss_types[loss_type]._type] AS vuln_loss_types
```

product versions
```
call apoc.load.xmlSimple("file:///var/lib/neo4j/nvd-3-items.xml") YIELD value AS nvd
UNWIND nvd._entry AS vuln
RETURN vuln.name, vuln._vuln_soft._prod.name AS product, vuln._vuln_soft._prod.vendor AS vendor, [product_version IN vuln._vuln_soft._prod._vers | [toInteger(split(product_version.num,'.')[0]), product_version.edition] ] as pv
```

constraints automatically create indexes:
```
CREATE CONSTRAINT ON (cve:CVE) ASSERT cve.name IS UNIQUE
```

using periodic commits:
```
CALL apoc.periodic.commit("<CYPHER STATEMENT>", {batchSize:1000, parallel:false})
```


With the newer XML loader:

```
call apoc.load.xml("file:///var/lib/neo4j/nvd-3-items.xml", '/*/*', {}) YIELD value AS vuln
UNWIND vuln._children AS vuln_children
WITH DISTINCT vuln, collect(apoc.map.fromPairs([attr IN vuln_children._children WHERE attr._type in ['descript'] | [attr._type, attr._text]]).descript) AS descript_text
MERGE (cve:CVE {
    name: vuln.name,
    severity: vuln.severity,
    published: toInteger(replace(vuln.published, '-', '')),
    cvss_score: toFloat(vuln.CVSS_score),
    cvss_vector: vuln.CVSS_vector,
    cvss_base_score: toFloat(vuln.CVSS_base_score),
    cvss_impact_subscore: toFloat(vuln.CVSS_impact_subscore),
    cvss_expoit_subscore: toFloat(vuln.CVSS_exploit_subscore),
    description: descript_text})
```