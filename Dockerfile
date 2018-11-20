FROM neo4j:3.3.3
ENV NEO4J_AUTH=${NEO4J_AUTH}

RUN wget \
    --directory-prefix=./plugins/ \
    https://github.com/neo4j-contrib/neo4j-apoc-procedures/releases/download/3.3.0.4/apoc-3.3.0.4-all.jar

#RUN apk add --no-cache --quiet curl

#RUN curl \
#    https://nvd.nist.gov/feeds/xml/cve/2.0/nvdcve-2.0-2018.xml.gz \
#    -o nvdcve-2.0-2018.xml.gz && \
#    gunzip nvdcve-2.0-2018.xml.gz

RUN wget \
    http://jzw.s3.amazonaws.com/nvd-300.json

RUN wget \
    http://jzw.s3.amazonaws.com/nvd-3.json