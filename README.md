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

With xmlSimple:
```
USING PERIODIC COMMIT


CALL apoc.load.xmlSimple("file:///var/lib/neo4j/nvd-test.xml") YIELD value AS nvd
UNWIND nvd._entry AS vuln
MERGE (cve:CVE {
    name: vuln.name,
    severity: coalesce(vuln.severity, 'Unknown'),
    published: toInteger(replace(vuln.published, '-', '')),
    cvss_score: coalesce(toFloat(vuln.CVSS_score), -1),
    cvss_vector: coalesce(vuln.CVSS_vector, 'Unknown'),
    cvss_base_score: coalesce(toFloat(vuln.CVSS_base_score), -1),
    cvss_impact_subscore: coalesce(toFloat(vuln.CVSS_impact_subscore), -1),
    cvss_expoit_subscore: coalesce(toFloat(vuln.CVSS_exploit_subscore), -1),
    description: vuln._desc._descript._text})

// have to handle 'sec_prot' loss type differently
// b/c it has information in an attribute of the node
// (<sec_prot user="1"/>, <sec_prot admin="1"/>)
// which we can't cleanly handle the same way, since
// there isn't a good way to turn 'user' and 'admin'
// into relationship attributes based on this XML format
FOREACH (vuln_loss_type IN [loss_type IN keys(vuln._loss_types) WHERE NOT loss_type IN ['_type', '_sec_prot'] | vuln._loss_types[loss_type]._type] |
         MERGE (loss_type:LossType {name:vuln_loss_type})
         MERGE (cve)-[:LOSES]->(loss_type))

// now handle sec_prot loss types w/ special case
FOREACH (vuln_loss_type IN [loss_type IN keys(vuln._loss_types) WHERE loss_type = '_sec_prot' | vuln._loss_types[loss_type]._type] |
         MERGE (loss_type:LossType {name:vuln_loss_type})
         MERGE (cve)-[:LOSES {scope:coalesce(replace(vuln._loss_types._sec_prot.user, '1', 'user'), replace(vuln._loss_types._sec_prot.admin, '1', 'admin'))}]->(loss_type))

FOREACH (vuln_range IN [vuln_range IN keys(vuln._range) WHERE vuln_range <> '_type' | vuln._range[vuln_range]._type] |
         MERGE (access_vector:AccessVector {name:vuln_range})
         MERGE (cve)-[:ACCESSED_BY]->(access_vector))

FOREACH (prod in vuln._vuln_soft._prod |
         MERGE (product:Product {name:prod.name})
         MERGE (vendor:Vendor {name:prod.vendor})
         MERGE (product)-[:MADE_BY]->(vendor)

         FOREACH (prod_vers in prod._vers |
                MERGE (product_version:ProductVersion {
                        name:prod_vers.num,
                        major_version: coalesce(toInteger(split(prod_vers.num, '.')[0]), -1),
                        edition: coalesce(prod_vers.edition, 'None')
                        })
                MERGE (cve)-[:AFFECTS]->(product_version)
                MERGE (product_version)-[:VERSION_OF]->(product))
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