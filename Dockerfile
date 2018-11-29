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

RUN echo "dbms.security.auth_enabled=false" >> /var/lib/neo4j/conf/neo4j.conf && \
    echo "apoc.import.file.enabled=true" >> /var/lib/neo4j/conf/neo4j.conf && \
    neo4j start && \
    python3 nvd_loader.py

WORKDIR /var/lib/neo4j/

RUN neo4j stop

#RUN pip3 install -r requirements.txt

#RUN python3 nvd_loader.py