import os
import subprocess

# Set directories
DECRYPTED_DIR = "decrypted-ip15-bak"  # Change this to match your path
OUTPUT_DIR = "plists"

# Ensure the output directory exists
os.makedirs(OUTPUT_DIR, exist_ok=True)

def is_plist_file(file_path):
    """Determine if a file is a plist based on its hexadecimal representation."""
    try:
        with open(file_path, "rb") as f:
            magic_bytes = f.read(8)  # Read first 8 bytes to determine file type

            if "plist" in str(magic_bytes):  # Compare against bytes, not string
                print(f"mbs: {file_path}")
                return True
            else:
                return False

    except Exception as e:
        print(f"[!] Error checking {file_path}: {e}")
        return False


def get_plist_filename(hex_filename):
    """
    Converts a hex-encoded filename to a human-readable string using xxd.
    """

    print("ayoo")
    print(hex_filename)

    try:
        # Run xxd to decode hex to text
        cmd = f"echo {hex_filename} | xxd -r -p"
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True
        )
        bin_result = result.stdout
        return bin_result

    except Exception as e:
        print(f"[!] Error converting hex to filename: {e}")
        return None

def convert_plist(input_file, output_filename):
    """Run plutil -p on a plist and write the output to a file."""
    output_path = os.path.join(OUTPUT_DIR, output_filename)

    try:
        result = subprocess.run(["plutil", "-p", input_file], capture_output=True, text=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(result.stdout)

        print(f"[✔] Processed: {input_file} -> {output_path}")
    except Exception as e:
        print(f"[!] Failed to process {input_file}: {e}")

def process_plists():
    """First, collect all plist file paths. Then process them."""
    
    plist_files = []

    # First loop: Identify plist files and store their paths
    for root, _, files in os.walk(DECRYPTED_DIR):
        for file in files:
            file_path = os.path.join(root, file)
            if is_plist_file(file_path):
                plist_files.append(file_path)

    print(plist_files)
    # Second loop: Process stored plist files
    for plist_path in plist_files:
        hex_filename = os.path.basename(plist_path)  # Extract the hex filename
        human_readable_name = get_plist_filename(hex_filename)  # Convert it

        if human_readable_name:
            output_filename = f"{human_readable_name}"
            convert_plist(plist_path, output_filename)

# Run the script
process_plists()
