# neo4j-cve
Graph database version of the CVE database

## Starting Neo4j

Run `docker-compose up` to start the container.

## Python Setup

Create a virtual environment and run `pip install -r requirements.txt`.

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

https://nvd.nist.gov/vuln/data-feeds#XML_FEED lists all XML feeds of data.

### Exploring data
Run this command to load a test file:
```
CALL apoc.load.xml("file:///var/lib/neo4j/nvd-test.xml", '/*/*', {}) YIELD value
AS vuln RETURN vuln.severity, vuln.name, vuln.published, vuln.CVSS_score, vuln.CVSS_vector
```

See https://neo4j-contrib.github.io/neo4j-apoc-procedures/#_load_xml_introduction
for more details on `apoc.load.xml`.

### Creating nodes

```
call apoc.load.xml("file:///var/lib/neo4j/nvd-3-items.xml", '/*/*', {}) YIELD value AS vuln
UNWIND vuln._children AS vuln_children
WITH DISTINCT vuln, collect(apoc.map.fromPairs([attr IN vuln_children._children WHERE attr._type in ['descript'] | [attr._type, attr._text]]).descript) AS descript_text
MERGE (cve:CVE {
    name: vuln.name,
    severity: vuln.severity,
    published: vuln.published,
    cvss_score: vuln.CVSS_score,
    cvss_vector: vuln.CVSS_vector,
    cvss_base_score: vuln.CVSS_base_score,
    cvss_impact_subscore: vuln.CVSS_impact_subscore,
    cvss_expoit_subscore: vuln.CVSS_exploit_subscore,
    description: descript_text})
```