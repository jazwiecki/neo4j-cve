FROM neo4j:3.3.3
ENV NEO4J_AUTH=${NEO4J_AUTH}

RUN apk add --no-cache --quiet curl python3

RUN curl -L \
    https://github.com/neo4j-contrib/neo4j-apoc-procedures/releases/download/3.3.0.4/apoc-3.3.0.4-all.jar \
    -o plugins/apoc-3.3.0.4-all.jar

RUN mkdir /var/lib/neo4j/code

COPY ./code/ /var/lib/neo4j/code/

WORKDIR /var/lib/neo4j/code

RUN pip3 install -r requirements.txt

WORKDIR /var/lib/neo4j/
