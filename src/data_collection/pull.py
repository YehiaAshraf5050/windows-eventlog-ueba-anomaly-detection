from elasticsearch import Elasticsearch
import urllib3

try:
    from config import ELASTIC_HOST, ELASTIC_USER, ELASTIC_PASSWORD, RAW_INDEX_NAME, VERIFY_CERTS
except ImportError:
    raise ImportError(
        "Create config.py from config.template.py and fill in your local Elasticsearch settings."
    )

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

es = Elasticsearch(
    ELASTIC_HOST,
    basic_auth=(ELASTIC_USER, ELASTIC_PASSWORD),
    verify_certs=VERIFY_CERTS
)


def get_logs(size=9000):

    response = es.search(
    index=INDEX_NAME,
    size=size,
    query={
        "bool": {
            "must": [
                {
                    "range": {
                        "@timestamp": {
                            "gte": "now-1d"
                        }
                    }
                },
                {
                    "terms": {
                        "event.code": [
                            "1",
                            "3",
                            "11",
                            "4624",
                            "4625",
                            "5379"
                        ]
                    }
                }
            ]
        }
    },
    sort=[
        {
            "@timestamp": {
                "order": "desc"
            }
        }
    ]
)
    logs = [hit["_source"] for hit in response["hits"]["hits"]]
    return logs


if __name__ == "__main__":
    logs = get_logs(size=9000)
    for log in logs:
        print(log)