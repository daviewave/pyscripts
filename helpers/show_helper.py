import argparse, os, sys

sys.path.append(
    os.path.abspath(os.path.join(os.path.dirname(__file__), os.environ.get("py")))
)
from common_tools import CmdUtils


def cat_main_file():
    cmd = CmdUtils()
    help_dir = os.environ.get("pyhelp")
    command = ["cat", "examples/new_script.txt"]
    result = cmd.run(command, run_from=help_dir)
    return result.stdout


def get_filter_args(args):
    to_keep = []
    for arg, value in args.items():
        if value:
            to_keep.append(arg)
    return to_keep


def filter_helper_file(filters, file: str):
    cmd = CmdUtils()
    filtered_lines = []
    for line in file.splitlines():
        if not (line.strip().startswith("parser.add_argument")):
            filtered_lines.append(line)
        else:
            if any(f in line for f in filters):
                filtered_lines.append(line)
    return "\n".join(filtered_lines)


def show_helper(show_all, args):

    full_file = cat_main_file()

    if show_all or CmdUtils.cmd_has_no_args():
        print(full_file)
        sys.exit(0)

    filters = get_filter_args(args)
    filterd_file = filter_helper_file(filters, full_file)

    print(filterd_file)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="")

    parser.add_argument("-a", action="store_true", help="show all helpers")
    parser.add_argument("-s", action="store_true", help="show string helper")
    parser.add_argument("-i", action="store_true", help="show integer helper")
    parser.add_argument("-b", action="store_true", help="show boolean helper")
    parser.add_argument("-l", action="store_true", help="show list helper")
    parser.add_argument("-f", action="store_true", help="show file helper")
    parser.add_argument("-fl", action="store_true", help="show float helper")
    parser.add_argument("-c", action="store_true", help="show choice helper")

    args = parser.parse_args()
    show_all = args.a
    show_string = args.s
    show_integer = args.i
    show_boolean = args.b
    show_list = args.l
    show_file = args.f
    show_float = args.fl
    show_choice = args.c

    args = {
        "string": show_string,
        "integer": show_integer,
        "boolean": show_boolean,
        "list": show_list,
        "file": show_file,
        "float": show_float,
        "choice": show_choice,
    }

    show_helper(show_all, args)
