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

`https://nvd.nist.gov/vuln/data-feeds#XML_FEED` lists all XML feeds of data.

Run this command to load a test file:

```call apoc.load.xml("file:///var/lib/neo4j/nvd-test.xml", '/*/*', {}) yield value as vuln return vuln.severity, vuln.name, vuln.published, vuln.CVSS_score, vuln.CVSS_vector", '/*/*', {}) yield value as vuln
```

See https://neo4j-contrib.github.io/neo4j-apoc-procedures/#_load_xml_introduction
for more details on `apoc.load.xml`.