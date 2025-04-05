import argparse, os, sys


# sys.path.append(
#     os.path.abspath(os.path.join(os.path.dirname(__file__), os.environ.get("py")))
# )

sys.path.append(
    os.path.abspath(os.path.join(os.path.dirname(__file__), "/home/da/pyscripts"))
)


from common_tools import IOUtils, FsUtils, FileUtils

io = IOUtils()


def get_radare2_funcs(fp):
    import r2pipe

    try:
        r2 = r2pipe.open(fp)
        r2.cmd("aaaa")
        funcs = r2.cmd("afl")
        return funcs
    except Exception as e:
        io.error_msg(status="1/2", func="get_radare2_funcs()")
        raise Exception(e)


def get_rizin_funcs(fp):
    import rzpipe

    try:
        rz = rzpipe.open(fp)
        rz.cmd("aaaa")
        funcs = rz.cmd("afl")
        return funcs
    except Exception as e:
        io.error_msg(status="1/2", func="get_radare2_funcs()")
        raise Exception(e)


def list_functions(fp, to_console=False, use_r2=False):

    functions = None
    if use_r2:
        functions = get_radare2_funcs(fp)
    else:
        functions = get_rizin_funcs(fp)

    if not functions:
        io.warning_msg("No function found for binary file passed")

    if to_console:
        print(functions)
        # for func in functions:
        #     print(func)

    return functions


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
        "-c",
        "--console",
        action="store_true",
        help="pass this when not calling as a standalone script -- ie using it as a subfunction in another script and it will return it as a list instead of printing it to console.",
    )
    parser.add_argument(
        "--r2",
        action="store_true",
        default=False,
        help="add this flag to specify that you want to use radare2. Uses rizin by default (the newer fork of radare2)",
    )

    # set arguments to variables
    args = parser.parse_args()
    fp = args.file
    to_console = args.console
    use_r2 = args.r2

    list_functions(fp, to_console, use_r2)
