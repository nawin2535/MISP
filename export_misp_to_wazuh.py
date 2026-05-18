import os
import argparse
import urllib3
import concurrent.futures
from typing import Optional, List, Dict
from pymisp import PyMISP
from dotenv import load_dotenv

load_dotenv()

# Disable warnings for insecure requests
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configuration defaults (can be overridden by environment variables)
MISP_URL = os.environ.get("MISP_URL", "https://misp-mdo.moph.go.th/")
API_KEY = os.environ.get("MISP_API_KEY", "XmfTJOQMTkSr89sbzH5xbRxcMwpIeLgLVZ3HIaL5")
VERIFY_SSL = os.environ.get("MISP_VERIFY_SSL", "False").lower() in ("true", "1", "t")

# Batch size for pagination. Recommended: 1000.
BATCH_SIZE = 1000
MAX_WORKERS = 5
MAX_RETRIES = 3

def format_wazuh_entry(attr: Dict) -> Optional[str]:
    """Formats a MISP attribute into a Wazuh CDB compatible string, properly quoting colons."""
    value = attr.get("value")
    event_id = attr.get("event_id")
    
    if value:
        # Wazuh CDB format: key:value
        # If the value contains a colon (IPv6, MAC address, etc.), quote it.
        if ":" in value:
            return f'"{value}":Event_{event_id}'
        return f"{value}:Event_{event_id}"
    return None

def fetch_page_attributes(misp_instance: PyMISP, page: int, limit: int, type_attribute) -> Optional[List[Dict]]:
    """Fetches a single page of attributes with retry logic."""
    print(f"[{type_attribute}] Fetching page {page}...")
    
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            response = misp_instance.search(
                controller='attributes',
                type_attribute=type_attribute,
                to_ids=1,
                #tags='NCSA',
                #last='90d',
                return_format='json',
                limit=limit,
                page=page
            )
            
            if isinstance(response, dict) and 'response' in response:
                return response['response'].get('Attribute', [])
            elif isinstance(response, list):
                return response
            elif isinstance(response, dict):
                return response.get('Attribute', [])
            return []
            
        except Exception as e:
            print(f"[{type_attribute}] Error fetching page {page} (Attempt {attempt}/{MAX_RETRIES}): {e}")
            if attempt == MAX_RETRIES:
                print(f"[{type_attribute}] Failed to fetch page {page} after {MAX_RETRIES} attempts.")
                return None
            
    return None

def fetch_and_export_attributes(misp: PyMISP, output_file: str, type_attribute):
    print(f"Connecting to MISP for {type_attribute} -> {output_file} with {MAX_WORKERS} workers...")
    total_entries = 0

    with open(output_file, 'w', encoding='utf-8') as f:
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            # Initial batch of tasks
            future_to_page = {
                executor.submit(fetch_page_attributes, misp, page, BATCH_SIZE, type_attribute): page 
                for page in range(1, MAX_WORKERS + 1)
            }
            
            next_page_to_submit = MAX_WORKERS + 1
            stop_submission = False

            while future_to_page:
                # Wait for at least one future to complete
                done, _ = concurrent.futures.wait(
                    future_to_page, return_when=concurrent.futures.FIRST_COMPLETED
                )

                for future in done:
                    page = future_to_page.pop(future)
                    try:
                        attributes = future.result()
                        
                        if attributes is None:
                            # A page failed completely after all retries.
                            # Stop submission to prevent infinite looping on a disconnected server.
                            print(f"Stopping further submission due to repeated failures on page {page}.")
                            stop_submission = True
                        else:
                            count = 0
                            for attr in attributes:
                                entry = format_wazuh_entry(attr)
                                if entry:
                                    f.write(f"{entry}\n")
                                    count += 1
                            total_entries += count
                            
                            # If we fetched successfully and got fewer attributes than the limit,
                            # we have reached the end of the data stream.
                            if len(attributes) < BATCH_SIZE:
                                stop_submission = True
                        
                        if not stop_submission:
                            new_future = executor.submit(
                                fetch_page_attributes, misp, next_page_to_submit, BATCH_SIZE, type_attribute
                            )
                            future_to_page[new_future] = next_page_to_submit
                            next_page_to_submit += 1
                            
                    except Exception as exc:
                        print(f"Page {page} generated an unexpected exception: {exc}")
                        stop_submission = True

    print(f"Done. Successfully wrote {total_entries} entries to {output_file}")

def main():
    parser = argparse.ArgumentParser(description="Export MISP attributes to Wazuh CDB format.")
    parser.add_argument("output_file", nargs="?", default="misp_sha256", help="Output file name or 'all' to export predefined sets.")
    parser.add_argument("--type", dest="type_attribute", default="sha256", help="MISP attribute type (e.g. sha256, ip-src, etc.)")
    parser.add_argument("--output-dir", dest="output_dir", default=".", help="Directory to save the exported files")
    
    args = parser.parse_args()

    # Create output directory if it doesn't exist
    if args.output_dir != ".":
        os.makedirs(args.output_dir, exist_ok=True)

    # Initialize PyMISP connection once, to be reused across all thread pools
    print(f"Initializing PyMISP connection to {MISP_URL}...")
    try:
        misp = PyMISP(MISP_URL, API_KEY, ssl=VERIFY_SSL)
    except Exception as e:
        print(f"Failed to connect to MISP: {e}")
        return

    if args.output_file == "all":
        # Predefined mapping: output_file -> type_attribute
        tasks = [
            ("misp_ip-src", "ip-src"),
            ("misp_ip-dst", "ip-dst"),
            ("misp_sha256", "sha256"),
            ("misp_domain", ["domain", "hostname"])
        ]
        
        print("Starting batch export for ALL types...")
        for out_file, attr_type in tasks:
            full_path = os.path.join(args.output_dir, out_file)
            print(f"\n--- Starting export: {attr_type} -> {full_path} ---")
            fetch_and_export_attributes(misp, full_path, attr_type)
            print(f"--- Finished export: {attr_type} ---")
    else:
        # Single file export
        full_path = os.path.join(args.output_dir, args.output_file)
        fetch_and_export_attributes(misp, full_path, args.type_attribute)

if __name__ == "__main__":
    main()