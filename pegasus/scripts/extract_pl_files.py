import os, subprocess

#!/usr/bin/env python3

import os
import sys
import shutil
import argparse
import subprocess
from pathlib import Path


def determine_filetype(fp):
    """determining the file type"""

    try:
        cmd = ["file", "--mime-type", "-b", fp]
        result = subprocess.run(cmd, capture_output=True, text=True)
        mime_type = result.stdout.strip()
        basename_hash = os.path.basename(fp)

        return {basename_hash, mime_type}
    except Exception as e:
        print(f"error checking file type: {e}")
        raise (e)


def categorize_filetypes(decrypt_dir):
    """loop through each file in the decrypted data directory, running a command to determine each file type and saving to a single key value dictionary with the hash value as the key and the filetype as the value"""

    pass


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Extract and restore PLIST files from decrypted iPhone backup data."
    )

    parser.add_argument(
        "decrypt_dir",
        nargs="?",
        type=str,
        help="Path to the decrypted iPhone backup data",
    )
    parser.add_argument("mappings_file", nargs="?", help="Path to the mappings file")
    parser.add_argument(
        "--pegasus_dir",
        default=os.getenv("PPATH", "."),
        help="Path to Pegasus directory (default: $PPATH)",
    )

    args = parser.parse_args()

    # Prompt user for missing arguments
    if not args.decrypt_dir:
        args.decrypt_dir = input(
            "Enter the filepath to the decrypted backup iPhone data: "
        ).strip()

    if not args.mappings_file:
        args.mappings_file = input("Enter the filepath to the mappings file: ").strip()

    extract_plist_files(args.decrypt_dir, args.mappings_file, args.pegasus_dir)
