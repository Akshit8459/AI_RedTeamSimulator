import hashlib
import os
import subprocess
import glob
from database import store_attack_result  # Required to store the attack result in DB

# Step 1: Dynamically identify the most recent generated attack file
generated_files = glob.glob("generated_attack_*.ps1")  # List all .ps1 files
technique_info_files = glob.glob("technique_info_*.txt")  # List all .txt files

if not generated_files:
    print("❌ [ERROR] No generated attack files found.")
    exit()

# Sort files by creation date, so we can pick the most recent one
latest_generated_attack_file = max(generated_files, key=os.path.getctime)
latest_technique_info_file = f"technique_info_{os.path.basename(latest_generated_attack_file).replace('generated_attack_', '').replace('.ps1', '.txt')}"

print(f"🔍 [DEBUG] Latest generated attack: {latest_generated_attack_file}")
print(f"🔍 [DEBUG] Corresponding technique info: {latest_technique_info_file}")

# Step 2: Extract technique ID from the filenames
technique_id = os.path.basename(latest_generated_attack_file).replace("generated_attack_", "").replace(".ps1", "")
print(f"🔍 [DEBUG] Extracted Technique ID: {technique_id}")

# Step 3: Load the technique information from the technique info file
with open(latest_technique_info_file, "r", encoding="utf-8") as f:
    technique_info = f.read()

# Extract relevant info (e.g., justification, exploit info)
justification = technique_info.split('\n')[0].strip()
exploit_info = '\n'.join(technique_info.split('\n')[1:]).strip()

# Step 4: Load the generated PowerShell payload
with open(latest_generated_attack_file, "r", encoding="utf-8") as f:
    powershell_code = f.read()

# Step 5: Hash the payload for uniqueness (SHA256)
payload_hash = hashlib.sha256(powershell_code.encode()).hexdigest()

# Step 6: Path to Atomic Red Team tests folder
atomics_folder = "atomics"

# Step 7: Dynamically construct the test file path based on the technique ID
test_file_path = os.path.join(atomics_folder, technique_id, f"{technique_id}.yaml")
print(f"Test file path: {os.path.abspath(test_file_path)}")

# Step 8: Run the corresponding Atomic Red Team test
print(f"[*] Running Atomic Red Team test for technique {technique_id}...")

test_command = [
    "powershell", "-ExecutionPolicy", "Bypass",
    "Import-Module", "Invoke-AtomicRedTeam", ";",
    "Invoke-AtomicTest", "-Path", test_file_path,
    "-AtomicTechnique", technique_id
]

# Running the Atomic Red Team test
process = subprocess.Popen(test_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
stdout, stderr = process.communicate()

# Step 9: Determine the result of the test
if process.returncode == 0:
    print(f"[+] Atomic test for {technique_id} ran successfully!")
    result = "success"
else:
    print(f"[!] Atomic test for {technique_id} failed: {stderr}")
    result = "failure"

# Step 10: Save the results to the database
store_attack_result(technique_id, payload_hash, justification, result, exploit_info)
print(f"[+] Test result saved for {technique_id}: {result}")
