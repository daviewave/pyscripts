import argparse, sys, os

script_dir = os.path.abspath(__file__)
sys.path.append(
    os.path.abspath(os.path.join(os.path.dirname(__file__), os.environ.get("py")))
)

from common_tools import EnvUtils, IOUtils


# - 1.
def check_deps():
    # a)
    env = EnvUtils()
    brew_requirements_fp = f"{script_dir}/brew-requirements.txt"
    pip_requirements_fp = f"{script_dir}/brew-requirements.txt"

    print(f"brfp: {brew_requirements_fp}")
    print(f"prfp: {pip_requirements_fp}")

    # b)
    has_brew_dependencies = env.has_brew_deps(brew_requirements_fp)

    # c)
    has_pip_dependencies = env.has_brew_deps(pip_requirements_fp)

    return has_brew_dependencies and has_pip_dependencies


# - 2.
def get_target_iphone_id():
    pass


# - 3.
def pair_iphone(iphone_id):
    pass


# - 4.
def enable_encryption():
    pass


# - 5.
def run_backup():
    pass


# == main
def backup_iphone_data(no_encrypt, full_backup, output_dir):
    io = IOUtils()

    # 1.
    io.start_msg(
        status="1/5",
        func="check_deps()",
        message="checking your system for required depencencies...",
    )
    check_deps()
    io.done(newline=True)

    # 2.

    # 3.

    # 4.

    # 5.

    io.success_msg(f"iphone data backed up at: {output_dir}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="")

    parser.add_argument(
        "--dont-encrypt",
        action="store_true",
        help="location of the directory containing the idevicebackup2 decrypted backup data",
    )

    parser.add_argument(
        "-f",
        "--full",
        action="store_true",
        help="location of the directory containing the idevicebackup2 decrypted backup data",
    )

    parser.add_argument(
        "-o",
        "--output",
        default="",
        required=False,
        # required=True,
        help="if you want to store the output to a file include this flag followed by the fp to store at",
    )

    # NOTE: could allow the deps files as optional arguments
    args = parser.parse_args()
    no_encrypt = args.dont_encrypt
    full_backup = args.full
    output_dir = args.output

    backup_iphone_data(no_encrypt, full_backup, output_dir)


# pseudo-code
# args:
# -> --no-encrypt: dont encrypt backup (boolean)
# -> -f/--full: full backup (boolean)
# -> --output: directory to store the backup (path-string)

# 1. check_deps()
#       --> check brew packages
#       --> check python/pip packages

# 2. get_target_iphone_id()
#       --> run `idevice_id -l` to list iphones connected to computer and:
#       --> if 0 returned, return error message
#       --> if 1 returned, return id
#       --> else 2 or more returned prompt user for list selection
#       return: id of connected phone (/ selection)

# 3. pair_iphone(iphone_id)
#       --> try/expect to pair iphone using id with idevicepair comamnd (`idevicepair pair -u <id>`)
#           --> in except, check for trust, and print message to notify user if needed
#       --> validate connection using (`idevicepair validate -u <id>`)

# 4. enable_encryption() --> check encrypt before calling
#       --> if password not None, try/except to enable encryption using --password flag
#           --> user is required to pass passcode in here
#       --> else, try/except to enable encryption in interactive mode
#           (*)--> if exception hits in either make sure error does say its already enabled,
#                   print info_msg (compare_str="Backup encryption is already enabled")

# 5. run_backup(iphone_id, output_dir, encrypt_data, full, password)
#       --> run backup command (adding --full if necessary), save to output dir

# 6. (maybe) make_backup_dir_immutable(immutable_arg)
#       --> could at the very print the info commands for user to see after successfull backup


# NOTES:
# --> iphone must be unlocked !
# --> there are several times where authentication is needed on iphone
#   --> when turning of encryption
# --> when turning encryption of, i  was unable to pass password as a flag,
#   --> --password can only be passed with restore
