import xml.etree.ElementTree as ET
import requests
import json

# Elasticsearch settings
elasticsearch_host = "http://localhost:9200"
index_name = "attack-surface"

# Path to Nmap XML file
nmap_xml_file = "nmap.xml"

# Function to construct the bulk API request
def construct_bulk_request(hostname, ip_address, ports):
    bulk_request = {
        "index": {
            "_index": index_name
        }
    }
    document = {
        "hostname": hostname,
        "ip_address": ip_address,
        "ports": ports,
        "subsidiary": "Evil Corp"  # Placeholder for subsidiary information
    }
    return json.dumps(bulk_request) + "\n" + json.dumps(document)

# Read and parse Nmap XML file
tree = ET.parse(nmap_xml_file)
root = tree.getroot()

bulk_data = ""  # Accumulate bulk request data

# Iterate over each host in the XML
for host in root.findall('host'):
    hostname = host.find('hostnames/hostname').attrib.get('name', 'N/A')
    ip_address = host.find('address').attrib['addr']
    ports = []

    # Iterate over each open port
    for port in host.findall('ports/port'):
        if port.find('state').attrib['state'] == 'open':
            port_number = port.attrib['portid']
            service_element = port.find('service')
            service_name = service_element.attrib.get('product', 'N/A')
            ports.append({"port": port_number, "service_name": service_name})

    # Check if document exists based on hostname
    query = {
        "query": {
            "term": {
                "hostname.keyword": {
                    "value": hostname
                }
            }
        }
    }
    response = requests.get(f"{elasticsearch_host}/{index_name}/_search", json=query)
    data = response.json()
    if "hits" in data and "total" in data["hits"]:
        document_exists = data["hits"]["total"]["value"] > 0
    else:
        document_exists = False

    if document_exists:
        # Update existing document using Update API
        doc_id = data["hits"]["hits"][0]["_id"]
        update_request = {
            "script": {
                "source": """
                    ctx._source.ip_address = params.ip_address;
                    ctx._source.ports = params.ports;
                """,
                "lang": "painless",
                "params": {
                    "ip_address": ip_address,
                    "ports": ports
                }
            }
        }
        bulk_request = json.dumps({"update": {"_index": index_name, "_id": doc_id}}) + "\n" + json.dumps(update_request)
    else:
        # Add new document
        bulk_request = construct_bulk_request(hostname, ip_address, ports)

    # Accumulate bulk request data
    bulk_data += bulk_request + "\n"

# Send the bulk request to Elasticsearch
response = requests.post(f"{elasticsearch_host}/_bulk", data=bulk_data, headers={"Content-Type": "application/x-ndjson"})

# Check the response for errors
if response.status_code == 200:
    print("Bulk indexing complete.")
else:
    print(f"Bulk indexing failed. Response: {response.text}")
