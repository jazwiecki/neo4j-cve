FROM neo4j:3.3.3
ENV NEO4J_AUTH=${NEO4J_AUTH}

RUN wget \
    --directory-prefix=./plugins/ \
    https://github.com/neo4j-contrib/neo4j-apoc-procedures/releases/download/3.3.0.4/apoc-3.3.0.4-all.jar

RUN wget \
    http://jzw.s3.amazonaws.com/nvd-test.xml