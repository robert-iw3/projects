### server_parser.py ###
import json
import http.server
import socketserver
import requests
import datetime
import logging
import traceback
import asyncio
import aiohttp
import os
import socket  # Added for gethostname

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Load schema
with open('schema.json', 'r') as f:
    SCHEMA = json.load(f)
output_type = os.getenv("OUTPUT_TYPE", "Elastic")
SCHEMA_MAP = SCHEMA['cim' if output_type == "Splunk" else 'ecs']
INFERENCES = SCHEMA_MAP.pop("inferences", {})

class ThreadedHTTPServer(ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True

class LogHandler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length).decode('utf-8')
            logs = json.loads(post_data)
            if not isinstance(logs, list):
                logs = [logs]

            processed_logs = []
            chunk_size = int(os.getenv("CHUNK_SIZE", 1000))
            for i in range(0, len(logs), chunk_size):
                chunk = logs[i:i + chunk_size]
                for log in chunk:
                    try:
                        processed = process_log(log)
                        processed_logs.append(processed)
                    except Exception as e:
                        logging.error(f"Error processing log: {traceback.format_exc()} - Skipping log: {log}")

            if processed_logs:
                forward_logs(processed_logs)

            self.send_response(200)
            self.end_headers()
        except Exception as e:
            logging.error(f"Error processing request: {traceback.format_exc()}")
            self.send_response(500)
            self.end_headers()

def process_log(log):
    processed = {
        "host": socket.gethostname(),
    }
    # Map fields (assumes flat input from client)
    for input_key, output_key in SCHEMA_MAP.items():
        if input_key in log:
            processed[output_key] = log[input_key]

    # Apply inferences
    event_id_str = str(processed.get("signature_id" if output_type == "Splunk" else "event.code"))
    if event_id_str in INFERENCES:
        processed.update(INFERENCES[event_id_str])

    # Add defaults
    if output_type == "Splunk":
        if "time" not in processed:
            processed["time"] = datetime.datetime.utcnow().isoformat()
    else:
        if "@timestamp" not in processed:
            processed["@timestamp"] = datetime.datetime.utcnow().isoformat()

    return processed

def forward_logs(logs):
    if output_type == "Splunk":
        url = os.getenv("SPLUNK_HEC_URL", "")
        token = os.getenv("SPLUNK_HEC_TOKEN", "")
        headers = {"Authorization": f"Splunk {token}", "Content-Type": "application/json"}
        for log in logs:
            payload = {"event": log}
            try:
                response = requests.post(url, json=payload, headers=headers)
                if response.status_code != 200:
                    logging.error(f"Splunk forward failed: {response.text}")
            except Exception as e:
                logging.error(f"Error forwarding to Splunk: {traceback.format_exc()}")
    else:  # Elastic
        base_url = os.getenv("ELASTIC_URL", "http://localhost:9200")
        index = os.getenv("ELASTIC_INDEX", "logs-ecs")
        if os.getenv("USE_ASYNC", "True").lower() == "true":
            asyncio.run(async_forward_to_elastic(logs, base_url, index))
        else:
            headers = {"Content-Type": "application/x-ndjson"}
            batch_size = int(os.getenv("BATCH_SIZE", 1000))
            for i in range(0, len(logs), batch_size):
                batch = logs[i:i + batch_size]
                bulk_data = ""
                for log in batch:
                    bulk_data += json.dumps({"index": {"_index": index}}) + "\n"
                    bulk_data += json.dumps(log) + "\n"
                bulk_url = f"{base_url}/_bulk"
                try:
                    response = requests.post(bulk_url, data=bulk_data, headers=headers)
                    if response.status_code != 200:
                        logging.error(f"Elastic forward failed: {response.text}")
                except Exception as e:
                    logging.error(f"Error forwarding to Elastic: {traceback.format_exc()}")

async def async_forward_to_elastic(logs, base_url, index):
    headers = {"Content-Type": "application/x-ndjson"}
    async with aiohttp.ClientSession() as session:
        batch_size = int(os.getenv("BATCH_SIZE", 1000))
        for i in range(0, len(logs), batch_size):
            batch = logs[i:i + batch_size]
            bulk_data = ""
            for log in batch:
                bulk_data += json.dumps({"index": {"_index": index}}) + "\n"
                bulk_data += json.dumps(log) + "\n"
            bulk_url = f"{base_url}/_bulk"
            try:
                async with session.post(bulk_url, data=bulk_data, headers=headers) as response:
                    if response.status != 200:
                        logging.error(f"Async Elastic forward failed: {await response.text()}")
            except Exception as e:
                logging.error(f"Async error forwarding to Elastic: {traceback.format_exc()}")

if __name__ == "__main__":
    PORT = 9880
    server = ThreadedHTTPServer(("", PORT), LogHandler)
    logging.info(f"Server running on port {PORT}")
    server.serve_forever()