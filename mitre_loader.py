# mitre_loader.py
import json
import random

def load_mitre_techniques(json_path="enterprise-attack.json"):
    with open(json_path, 'r', encoding='utf-8') as f:
        data = json.load(f)

    techniques = []
    for obj in data["objects"]:
        if obj.get("type") == "attack-pattern" and not obj.get("revoked", False):
            ext_refs = obj.get("external_references", [])
            technique_id = next((x["external_id"] for x in ext_refs if x["source_name"] == "mitre-attack"), None)
            name = obj.get("name")
            description = obj.get("description", "")
            if technique_id and technique_id.startswith("T"):
                techniques.append({
                    "id": technique_id,
                    "name": name,
                    "description": description
                })
    return techniques

def sample_techniques(n=10):
    all_techniques = load_mitre_techniques()
    return random.sample(all_techniques, n)
