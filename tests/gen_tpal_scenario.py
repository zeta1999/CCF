import json
import uuid
import hashlib

if __name__ == "__main__":
    txs = []
    for _ in range(500):
        h = hashlib.sha256(uuid.uuid4().bytes).hexdigest()
        txs.append({
            "method": "LOG_record",
            "params": {
                "id": 0,
                "msg": f"Copyright (c) Microsoft Corporation. All rights reserved. {h}"
            }
        })
    print(json.dumps({"transactions": txs}))