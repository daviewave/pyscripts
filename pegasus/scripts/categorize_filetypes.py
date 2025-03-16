import os, subprocess, argparse
from typing_extensions import Dict, List

import pprint

pegasus_path = os.environ.get("PPATH")
automation_dir = f"{pegasus_path}/auto"
tmp3 = []


def handle_exiftool_failure(mime_type):
    mime_map = {
        "x-sony-tim": "playstation",
        "x-dbt": "dbt-memo",
        "octet-stream": "raw-bin",
        "x-empty": "empty",
        "vnd.sqlite3": "sqlite",
    }
    return mime_map.get(mime_type, "unknown")


def determine_filetype(fp: str) -> Dict[str, str]:
    """determining the file type, and return key value pair {hash: filetype}"""
    basename_hash = os.path.basename(fp)
    try:
        # --> gz
        # --> json
        # --> jpg
        # --> plist
        # --> heic
        # --> aae
        # --> macos
        # --> mov
        # --> png
        # --> txt
        cmd = ["exiftool", fp]
        grep = ["grep", "File Type Extension"]
        full_result = subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True)
        refined_result = subprocess.run(
            grep, stdin=full_result.stdout, capture_output=True, text=True
        )
        filetype = refined_result.stdout.strip().split(":")[1].strip()
        return {basename_hash: filetype}

    except Exception as e:
        cmd = ["file", "--mime-type", "-b", fp]
        result = subprocess.run(cmd, capture_output=True, text=True)
        refined_result = result.stdout.split("/")[1]
        filetype = handle_exiftool_failure(refined_result)
        print(f"unknown type: {refined_result}")
        print(fp)
        print("")
        return {basename_hash: filetype}


def write_to_output_file():
    pass


def categorize_filetypes(decrypt_dir, output_fp):
    """loop through each file in the decrypted data directory, running a command to determine each file type and saving to a single key value dictionary with the hash value as the key and the filetype as the value"""

    subdirs = [
        f"{decrypt_dir}/{item}"
        for item in os.listdir(decrypt_dir)
        if os.path.isdir(f"{decrypt_dir}/{item}")
    ]

    categorized_fts = []
    for subdir in subdirs:
        subdir_files = os.listdir(subdir)
        for file in subdir_files:
            fp = f"{subdir}/{file}"
            fp_ft_dict = determine_filetype(fp)
            if fp_ft_dict:
                categorized_fts.append(fp_ft_dict)

    if output_fp:
        write_to_output_file(output_fp, categorized_fts)
    else:
        print("\ndone.")
        print("results: ")
        # pprint.pprint(categorized_fts)
        tmp = []
        for d in categorized_fts:
            h, t = next(iter(d.items()))
            tmp.append(t)

        tmp2 = set(tmp)
        tmp = list(tmp2)
        for x in tmp:
            print(f"--> {x}")

        print("\n")
        tmp4 = set(tmp3)
        for x in list(tmp4):
            print(f"--> {x}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Use the decrypted data dir to create a dictionary containing key value pairs of ."
    )

    parser.add_argument(
        "--decrypt_dir",
        type=str,
        required=True,
        help="Path to the decrypted iPhone backup data",
    )
    parser.add_argument(
        "--output",
        required=False,
        default="",
        help="if you want to store the output to a file include this flag followed by the fp to store at",
    )

    args = parser.parse_args()
    decrypt_dir = args.decrypt_dir
    output_fp = args.output

    # attempting to fix irregular path's
    if pegasus_path not in decrypt_dir:
        # if "data/" not in decrypt_dir:
        #     decrypt_dir = f"{pegasus_path}/data/{decrypt_dir}"
        # else:
        decrypt_dir = f"{pegasus_path}/{decrypt_dir}"

    if output_fp != "" and automation_dir not in output_fp:
        if "results/" not in output_fp:
            output_fp = f"{automation_dir}/results/{decrypt_dir}"
        else:
            output_fp = f"{automation_dir}/{decrypt_dir}"

    print("categorizing decrypted iphone data by filetypes...")
    categorize_filetypes(decrypt_dir, output_fp)
