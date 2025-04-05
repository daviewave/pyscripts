import argparse, os, sys
import r2pipe

script_dir = os.path.dirname(os.path.abspath(__file__))
# sys.path.append(
#     os.path.abspath(os.path.join(os.path.dirname(__file__), os.environ.get("py")))
# )

sys.path.append(
    os.path.abspath(os.path.join(os.path.dirname(__file__), "/home/da/pyscripts"))
)
sys.path.append(os.path.join(os.path.dirname(__file__), "scripts"))


from common_tools import IOUtils, FsUtils, FileUtils, PromptUtils

io = IOUtils()

from scripts.list_functions import list_functions


def get_addresses(target_functions):
    addresses = []
    for func in target_functions:
        addr, name = func.split()
        addresses.append(addr)
    return addresses


def determine_target_funcs(available, funcs):
    """returns a list of function addresses to extract c code from"""

    def process_functions_output(functions):
        functions_list = functions.splitlines()
        processed_functions = []
        for func in functions_list:
            parts = func.split()
            if len(parts) > 1:
                address, func_name = parts[0], parts[-1]
                processed_func = f"{address} {func_name}"
                processed_functions.append(processed_func)
        return processed_functions

    def get_valid_functions_specified(available, specified):
        validated = []
        for func in available:
            addr, name = func.split()
            if addr in specified or name in specified:
                validated.append(func)
        return validated

    processed_available = process_functions_output(available)

    if not funcs:
        return processed_available

    elif len(funcs) == 1 and funcs[0] in ["i", "interactive"]:
        prompt = PromptUtils()  # prompt user for list selections
        selections = prompt.list_selection(
            "Available Functions:\n", processed_available
        )
        return selections

    else:
        validated_specified_funcs = get_valid_functions_specified(
            processed_available, funcs
        )
        return validated_specified_funcs


def prep_output_dir(fp, use_r2=False):
    f = FileUtils()
    fs = FsUtils()
    bin_file = os.path.basename(fp)
    results_dir = f"{script_dir}/reuslts/{bin_file}"
    results_dir = fs.ensure_absolute_path(results_dir)
    if not fs.exists(results_dir):
        fs.create_dir(results_dir)

    results_file_pretext = "r2" if use_r2 else "rz"
    results_file = f"{results_dir}/{results_file_pretext}-c_functions.c"
    return results_file


def get_c_code(bin_fp, funcs, use_r2):
    if use_r2:
        import r2pipe

        r2 = r2pipe.open(bin_fp)
        r2.cmd("aaaa")
        c_code_dicts = []
        for func in funcs:
            addr, name = func.split()
            r2.cmd(f"s {addr}")
            c_code = r2.cmd("pdg")
            c_code_dicts.append({name: c_code})
        return c_code_dicts
    else:
        import rzpipe

        rz = rzpipe.open(bin_fp)
        rz.cmd("aaaa")
        c_code_dicts = []
        for func in funcs:
            addr, name = func.split()
            rz.cmd(f"s {addr}")
            c_code = rz.cmd("pdg")
            c_code_dicts.append({name: c_code})
        return c_code_dicts


def write_results_to_output_fp(code_dicts, output_fp):
    for func_dict in code_dicts:
        name, code = next(iter(func_dict.items()))
        output_fp.write(f"// {name}")
        output_fp.write(f"{code}\n\n\n")


def extract_c_code(fp, funcs=None, use_r2=False, json=False):
    fs = FsUtils()
    fs.is_valid_path(fp, strict="file")

    # 1.
    functions = list_functions(fp)

    # 2.
    target_functions = determine_target_funcs(available=functions, funcs=funcs)
    print(target_functions)

    # 3.
    output_fp = prep_output_dir(fp, use_r2)
    print(output_fp)

    # 4. use the output filepath to extract each functions
    c_code_dicts = get_c_code(fp, target_functions, use_r2)
    # io.pp.pprint(c_code_dicts)

    # 5.
    with open(output_fp, "w") as f:
        write_results_to_output_fp(c_code_dicts, f)

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
        "--funcs",
        type=str,
        nargs="+",
        default=None,
        help="if not passed, returns all functions. if first element is 'i' list all functions found and select the ones of interest or if you already know the functions you want just pass them in list '--funcs func1 func2' format",
    )
    parser.add_argument(
        "--r2",
        action="store_true",
        default=False,
        help="add this flag to specify that you want to use radare2. Uses rizin by default (the newer fork of radare2)",
    )
    parser.add_argument(
        "-j",
        "--json",
        action="store_true",
        default=False,
        help="",
    )

    args = parser.parse_args()
    fp = args.file
    funcs = args.funcs
    use_r2 = args.r2
    json = args.json

    extract_c_code(fp, funcs, use_r2, json)


# === psudo code ===#

# -- args --#
# 1. file: str -> required
# 2. funcs: list -> default=None
# 3. r2: bool -> default=False
# 4. json: bool -> default=True

# -- process --#
# 1. call the script to get all functions with use_console=False
#
# 2. determine target functions and return addresses based on the 'funcs' argument passed in during script/function call:
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

# -- notes --#
# - do you want to return all functions c code ?
#   --> accept an arg called funcs, a list, that allows the user to only return a specific functions
#   --> if the user passes in just 1 item of the list called something like 'interactive' or 'choose', then list
#        all options with the prompt helper i made in helper tools
