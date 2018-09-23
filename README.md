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