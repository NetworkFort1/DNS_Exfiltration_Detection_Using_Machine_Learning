from elasticsearch import Elasticsearch

es = Elasticsearch("http://192.168.196.98:9200")

# es.index(index='dns-exfiltration-alerts', document={
#     "timestamp": 123,
#     "query": "abc@example.com"
# })

# print(es.search(
#     index='dns-exfiltration-alerts'
# ))

# print(es.indices.delete(index='dns-exfiltration-alerts'))