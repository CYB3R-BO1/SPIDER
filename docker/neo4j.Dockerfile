FROM neo4j:5-community

# Enable APOC plugin
ENV NEO4J_PLUGINS='["apoc"]'
ENV NEO4J_AUTH=neo4j/spider_default
