
import os
import json
import base64

captures_dir = "/tmp/phishing_captures"
captures = []
by_id = {}

print(f"Checking directory: {captures_dir}")
if os.path.exists(captures_dir):
    files = os.listdir(captures_dir)
    print(f"Files found: {len(files)}")
    for filename in files:
        print(f" - {filename}")
        if filename.startswith("capture_") and filename.endswith(".json"):
            filepath = os.path.join(captures_dir, filename)
            try:
                with open(filepath, 'r') as f:
                    capture_data = json.load(f)
                    cid = filename[len("capture_"):-len(".json")]
                    capture_data['capture_id'] = cid
                    by_id[cid] = capture_data
                    print(f"   Loaded capture: {cid}")
            except Exception as e:
                print(f"   Error reading capture {filename}: {e}")
else:
    print("Directory does not exist")

print(f"Total captures loaded: {len(by_id)}")
