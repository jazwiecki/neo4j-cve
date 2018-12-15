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

```s.run("MATCH n RETURN n LIMIT 25")```

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

### Sample queries

Calculate the number of vulnerabilities found in the same software with
the same impact score:
```
MATCH
    (vendor : Vendor {name : ’ microsoft ’})
        −[:MADE BY]−
    (product : Product {name: ’edge ’})
        −[:VERSION OF]−
    (product version:ProductVersion)
        −[:AFFECTS]−
    (cve :CVE)
RETURN cve.‘v2.impact score ‘, count(cve)
```

Calculate the number of vulnerabilities found in the same software with
the same impact score across two consecutive years:
```
UNWIND range(1988, 2018, 1) AS t
WITH
    apoc.date.fromISO8601(t + '-01-01T00:00:00.000Z')
        AS start_window,
    apoc.date.fromISO8601((t + 1) + '-12-31T23:59:59.999Z')
        AS end_window
MATCH
    (vendor: Vendor)
        -[:MADE_BY]-
    (product:Product)
        -[:VERSION_OF]-
    (product_version:ProductVersion)
        -[:AFFECTS]-
    (cve:CVE)
WHERE
    cve.published >= start_window
        AND
    cve.published <= end_window
RETURN
    apoc.date.format(start_window)
        AS start_window,
    apoc.date.format(end_window)
        AS end_window,
    vendor.name,
    product.name,
    cve.`v2.impact_score`
        AS impact_score,
    count(cve) AS vulnerabilties
ORDER BY
    start_window,
    vendor.name,
    product.name
```

Find count of vulnerabilities that require user interaction through the
network, under the CVSS 3.0 definition of "attack vector"
```
MATCH
    (attack_vector:AttackVector {name: 'NETWORK'})
        -[:ATTACKABLE_THROUGH {cvss_version: 3}]-
    (cve:CVE {`v3.user_interaction`: 'REQUIRED'})
RETURN count(cve)
```

Identify easy network-accessible exploits that don't involve user actions
which simplify access to high-impact exploits which are otherwise high-complexity:

```
MATCH
    (attack_vector:AttackVector {
            name: 'NETWORK'
        }
    )
        -[:ATTACKABLE_THROUGH]-
    (cve:CVE {
        `v3.scope`: 'CHANGED',
        `v3.user_interaction`: 'NONE',
        `v3.attack_complexity`: 'LOW'
        }
    )
        -[:AFFECTS]-
    (product_version:ProductVersion)
        -[:AFFECTS]-
    (escalated_cve:CVE {
        `v3.privileges_required`: 'HIGH',
        `v3.user_interaction`: 'NONE',
        `v3.integrity_impact`: 'HIGH'}
    )
        -[:ATTACKABLE_THROUGH]-
   (escalacted_vector:AttackVector {name: 'LOCAL'})
RETURN cve.name,
    product_version.name,
    escalated_cve.name
```