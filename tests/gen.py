import json
import uuid

if __name__ == "__main__":
    txs = []
    for _ in range(500):
        txs.append({
            "method": "LOG_record",
            "params": {
                "id": 0,
                "msg": f"Unique message: {uuid.uuid4()}"
            }
        })
    print(json.dumps({"transactions": txs}))