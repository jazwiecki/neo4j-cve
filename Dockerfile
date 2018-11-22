FROM neo4j:3.3.3
ENV NEO4J_AUTH=${NEO4J_AUTH}

RUN wget \
    --directory-prefix=./plugins/ \
    https://github.com/neo4j-contrib/neo4j-apoc-procedures/releases/download/3.3.0.4/apoc-3.3.0.4-all.jar

RUN apk add --no-cache --quiet curl

RUN curl \
    https://nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-2018.json.gz \
    -o nvdcve-1.0-2018.json.gz && \
    gunzip nvdcve-1.0-2018.json.gz

RUN wget \
    http://jzw.s3.amazonaws.com/nvd-300.json

RUN wget \
    http://jzw.s3.amazonaws.com/nvd-3.json