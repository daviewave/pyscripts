#!/bin/bash

pegasus_dir=$PPATH
decrypt_dir=$1
mappings_path=$2


if [ -z $decrypt_dir  ]; then
  read "enter the filepath for the manifest.json file to analyze: " decrypt_dir
fi

if [ -z $mappings_path  ]; then
  read "enter the name of the file you want to save to: " mappings_path
fi



pegasus_dir=$PPATH
decrypt_dir="$1"
mappings_file="$2"

if [ -z "$1" ]; then
  read "enter the filepath to the decrypted backup iphone data: " decrypt_dir
fi

if [ -z "$2" ]; then
  read "enter the filepath to the decrypted backup iphone data: " mappings_file
fi

mappings_filename=$(basename "$mappings_file")
mappings_short_filename="${mappings_filename%.*}"
save_dir="$pegasus_dir/results/pl_files/$mappings_short_filename"

if [ ! -d "$save_dir" ]; then
    mkdir -p "$save_dir"
fi

echo "extracting plist files from $decrypt_dir using $mappings_file..."

# Read mappings file and process each file
while read -r hash original_path; do
    file_path="$decrypt_dir/$hash"

    # Check if the file exists before processing
    if [ -f "$file_path" ]; then
        # Check if it's a plist file using `file` command (alternative: exiftool)
        file_type=$(file --mime-type -b "$file_path")

        if [[ "$file_type" == "application/x-plist" || "$file_type" == "text/xml" ]]; then
            # Determine save path
            save_path="$save_dir/$(basename "$original_path")"

            # Copy plist file to results directory
            cp "$file_path" "$save_path"

            echo "✅ Saved: $file_path -> $save_path"
        fi
    fi
done < "$mappings_file"

echo "Plist extraction complete! 📂"


#--------------

# def is_plist(fp: str) -> list:
#     """Check if a current iteration in the decrypt dir is a plist, save to list, return the list of pfiles"""
#     plist_fps = []
#     try:
#         cmd = ["file", "--mime-type", "-b", fp]
#         result = subprocess.run(cmd, capture_output=True, text=True)
#         mime_type = result.stdout.strip()
#         if "plist" in mime_type:
#             plist_fps.append(fp)

#         return "application/x-plist" in mime_type or "text/xml" in mime_type
#     except Exception as e:
#         print(f"Error checking file type: {e}")
#         return False


# def extract_plist_files(decrypt_dir, mappings_file, pegasus_dir):
#     if not os.path.isdir(decrypt_dir):
#         print(f"Error: Decrypt directory '{decrypt_dir}' does not exist.")
#         sys.exit(1)

#     mappings_filename = os.path.basename(mappings_file)
#     mappings_short_filename = mappings_filename[:-4]
#     save_dir = f"{pegasus_dir}/results/pl_files/{mappings_short_filename}"
#     os.makedirs(save_dir, exist_ok=True)

#     print(f"extracting plist files from {decrypt_dir} using {mappings_file}...")

#     with open(mappings_file, "r") as f:
#         for line in f:
#             parts = line.strip().split(" ", 1)
#             if len(parts) != 2:
#                 continue  # Skip malformed lines

#             file_hash, original_path = parts
#             file_path = os.path.join(decrypt_dir, file_hash)

#             if os.path.isfile(file_path) and is_plist(file_path):
#                 save_path = os.path.join(save_dir, os.path.basename(original_path))
#                 shutil.copy(file_path, save_path)
#                 print(f"  ✅ Saved: {file_path} -> {save_path}")

#     print("Plist extraction complete! 📂")

