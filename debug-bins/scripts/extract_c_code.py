import argparse, os, sys
import r2pipe

script_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(
    os.path.abspath(os.path.join(os.path.dirname(__file__), os.environ.get("py")))
)

from common_tools import IOUtils, FsUtils, FileUtils

io = IOUtils()


def get_c_code(fp, func):
    try:
        r2 = r2pipe.open(fp)
        r2.cmd("aaaa")
        r2.cmd(f"s {func}")
        c_code = r2.cmd("pdg")
        return c_code
    except Exception as e:
        io.error_msg(status="1/2", func="get_c_code()")
        raise Exception(e)

def prep_output_dir(fp):
    f = FileUtils()
    fs = FsUtils()
    bin_file = os.path.basename(fp)
    results_dir = f"{script_dir}/../reuslts/{bin_file}"
    results_dir = fs.ensure_absolute_path(results_dir)
    if not fs.exists(results_dir):
        fs.create_dir(results_dir)
    results_file = f"{results_dir}/{bin_file}-main-c.c"
    return results_file

def extract_c_code(fp, func, json_format):
    # a) 
    fs = FsUtils()
    fs.is_valid_path(fp, strict="file")

    # b) 
    c_code = get_c_code(fp, func)

    # c) 
    output_fp = prep_output_dir(fp)

    # d)
    f = FileUtils()
    f.write(output_fp, c_code)

    io.success_msg(f"deassembled '{os.path.basename(fp)}' into C code at: {output_fp}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="")

    parser.add_argument(
        "-f",
        "--file",
        type=str,
        required=True,
        help="binary file to examine",
    )
    parser.add_argument(
        "--func",
        type=str,
        required=False,
        default="main",
        help="specify a specific function to decompile, only decompiles main by default",
    )
    parser.add_argument(
        "-j",
        "--json",
        type=str,
        required=False,
        default="main",
        help="output c code in json",
    )

    args = parser.parse_args()
    fp = args.file
    func = args.func
    json_format = args.json

    extract_c_code(fp, func, json_format)



#=== psudo code ===#

#-- args --#
# 1. file: str -> required
# 2. funcs: list -> default=None
# 3. r2: bool -> default=False
# 4. json: bool -> default=True

#-- process --#
# 1. call the script to get all functions with use_console=False
# 
# 2. determine functions to get c code using the 'funcs' argument:
#       a) funcs is None or empty --> return all functions c code
#       
#       b) len(funcs) == 1 and the 1 item is "i" (for interactive) --> get all functions, and prompt user for   
#           selections
#       
#       c) can assume that the user has passed the names/addresses of the functions they want to get the code for
#           and only return only those, using the list of functions returned in step 1 to validate the functions 
#           passed in were valid
# 
# 3. prep output dir (can use current function with minimal updates)
# 
# 4. call the rzpipe or r2pipe 
#       --> use rzpipe by default but check if r2 bool arg is passed and use r2pipe if needed !

#-- notes --#
#- do you want to return all functions c code ?
#   --> accept an arg called funcs, a list, that allows the user to only return a specific functions
#   --> if the user passes in just 1 item of the list called something like 'interactive' or 'choose', then list
#        all options with the prompt helper i made in helper tools 

