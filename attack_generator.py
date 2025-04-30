import hashlib
import os
import subprocess
import re
from mitre_loader import sample_techniques
from database import get_failed_techniques, store_attack_result
from exploit_fetcher import fetch_exploits_for_technique

# Step 1: Get the list of failed techniques
failed_techniques = get_failed_techniques()
print(f"⚠️ [DEBUG] Excluding recently failed techniques: {failed_techniques}")

# Step 2: Get all available techniques and exclude failed ones
techniques = sample_techniques()
filtered_techniques = [t for t in techniques if t['id'] not in failed_techniques]

# If no techniques remain after filtering, sample without exclusion
if not filtered_techniques:
    filtered_techniques = techniques

technique_prompt = "\n".join([f"{t['id']}: {t['name']}" for t in filtered_techniques])

# Step 3: Define AI prompt
ai_prompt = f"""
You are an expert red team planner.

Given the following MITRE ATT&CK techniques:

{technique_prompt}

Choose the most effective technique for initial access or execution.
Explain why you chose it and generate an obfuscated PowerShell payload for it.
Only respond in this format:

Technique ID: <ID>
Justification: <brief justification>
PowerShell:
<obfuscated PowerShell>
Explanation: <detailed explanation of why this technique was chosen and how the payload works>
"""

# Step 4: Send prompt to AI model (Ollama in this case)
print("🧠 [DEBUG] Sending prompt to Ollama...\n")

process = subprocess.Popen(
    ['ollama', 'run', 'openhermes'],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True,
    encoding='utf-8'
)

process.stdin.write(ai_prompt)
process.stdin.close()

stdout, stderr = process.communicate()

if stderr:
    print(f"❌ [ERROR] Ollama stderr: {stderr}")

if process.returncode != 0:
    print(f"❌ [ERROR] Ollama command failed with return code {process.returncode}")
    exit()
else:
    print("✅ Ollama responded successfully.")

# Step 5: Parse the AI response
print("🔎 [DEBUG] Parsing AI response...\n")

# Preprocess: remove technique name suffix (e.g., ": Distributed Component Object Model")
stdout = re.sub(r'(Technique ID:\s*T\d+\.\d+):.*', r'\1', stdout)

# Output the PowerShell section for debugging
print("🧨 [DEBUG] Raw PowerShell Output:\n")
raw_powershell = re.findall(r'PowerShell:\s*(.*?)\s*Explanation:', stdout, re.DOTALL)
if raw_powershell:
    print(raw_powershell[0].strip())

# More tolerant matching for response
matches = re.findall(
    r'Technique ID:\s*(T\d+\.\d+)\s*Justification:\s*(.*?)\s*PowerShell:\s*(.*?)\s*Explanation:\s*(.*)',
    stdout,
    re.DOTALL
)

if not matches:
    print("❌ [ERROR] Could not parse AI response.")
    print("Response was:", stdout)
    exit()

# Step 6: Process each matched technique
for match in matches:
    technique_id, justification, powershell_code, explanation = map(str.strip, match)

    if len(powershell_code) > 1000:
        print(f"❌ [ERROR] PowerShell code is too long or possibly corrupted: {powershell_code[:100]}... (truncated)")
        powershell_code = "Obfuscated/Corrupted PowerShell Code"

    technique_name = next((t["name"] for t in filtered_techniques if t["id"] == technique_id), "Unknown")

    print(f"🧨 [DEBUG] Searching Exploit-DB for technique: {technique_name}")
    exploits = fetch_exploits_for_technique(technique_name)

    if exploits:
        exploit_summary = "\n".join([f"- {e['title']} ({e['url']})" for e in exploits])
        justification += f"\n\n[+] Related Exploits:\n{exploit_summary}"
        exploit_info = exploit_summary
    else:
        justification += "\n\n[+] No related exploits found in Exploit-DB."
        exploit_info = "None"

    payload_hash = hashlib.sha256(powershell_code.encode()).hexdigest()

    print(f"\n✅ Selected Technique: {technique_id}")
    print(f"🧠 Justification:\n{justification}\n")
    print("📜 PowerShell Payload:")
    print(powershell_code)

    generated_payload_file = f"generated_attack_{technique_id}.ps1"
    technique_info_file = f"technique_info_{technique_id}.txt"

    with open(generated_payload_file, "w", encoding="utf-8") as f:
        f.write(powershell_code)

    with open(technique_info_file, "w", encoding="utf-8") as f:
        f.write(f"{technique_id}\n{justification}\n{exploit_info}\n{explanation}")

    result = "unknown"
    store_attack_result(technique_id, payload_hash, justification, result, exploit_info)

    print(f"\n💾 [DEBUG] Saved: {generated_payload_file} + {technique_info_file}")
