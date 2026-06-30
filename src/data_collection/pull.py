from elasticsearch import Elasticsearch
import urllib3

try:
    from config import (
        ELASTIC_HOST,
        ELASTIC_USER,
        ELASTIC_PASSWORD,
        RAW_INDEX_NAME,
        VERIFY_CERTS,
    )
except ImportError as exc:
    raise ImportError(
        "Create config.py from config.template.py and fill in your local "
        "Elasticsearch settings."
    ) from exc


if not VERIFY_CERTS:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


es = Elasticsearch(
    ELASTIC_HOST,
    basic_auth=(ELASTIC_USER, ELASTIC_PASSWORD),
    verify_certs=VERIFY_CERTS,
)


def get_logs(size=9000, lookback="now-1d", index_name=None):
    """
    Pull raw Windows/Sysmon events from Elasticsearch.
    """

    target_index = index_name or RAW_INDEX_NAME

    response = es.search(
        index=target_index,
        size=size,
        query={
            "bool": {
                "must": [
                    {
                        "range": {
                            "@timestamp": {
                                "gte": lookback
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
                                "5379",
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
        ],
    )

    logs = [hit["_source"] for hit in response["hits"]["hits"]]
    return logs


if __name__ == "__main__":
    logs = get_logs(size=9000)

    print(f"Pulled {len(logs)} logs from Elasticsearch.")

    for log in logs[:10]:
        print(log)