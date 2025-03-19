import argparse, sys, os

script_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(
    os.path.abspath(os.path.join(os.path.dirname(__file__), os.environ.get("py")))
)

from common_tools import EnvUtils, IOUtils, CmdUtils, PromptUtils, FsUtils

io = IOUtils()


# - 1.
def check_deps():

    env = EnvUtils()

    # a) confirm brew deps
    io.start_msg(
        status="a",
        message="validating your system has the required homebrew packages...",
        prev_line=True,
    )
    env.validate_brew_installed()
    brew_requirements_file = f"{script_dir}/os-requirements.txt"
    env.validate_deps_installed(brew_requirements_file, pkg_mgr="brew")
    io.done(subfunction=True)

    # b)
    io.start_msg(
        status="b",
        message="checking system/virtualenv for required pip packages...",
        prev_line=True,
    )
    pip_requirements_file = f"{script_dir}/pip-requirements.txt"
    env.validate_deps_installed(pip_requirements_file, pkg_mgr="pip")
    io.done(subfunction=True)

    return


# - 2.
def get_target_iphone_id():
    # a) run command to print current connected iphones
    cmd = CmdUtils()
    command = ["idevice_id", "-l"]
    result = cmd.run(command)
    available_ids = result.stdout.split()
    num_available = len(available_ids)

    # b) handle based on num ids returned
    if num_available == 0:
        io.error_msg(status="2.b", func="get_target_iphone_id")
        raise Exception("could not detect any connected iphones")
    elif num_available >= 2:
        prompt = PromptUtils()
        return prompt.list_selection(
            "found multiple iphones connected, select the one you would like to backup",
            available_ids,
        )
    else:
        return available_ids[0]


# - 3.
def pair_iphone(id):
    def handle_auth_error(cmd_output):
        if "Please enter the passcode" in cmd_output:
            PromptUtils.enter_to_continue()
            pair_iphone(id)
        elif "Please accept the trust dialog" in cmd_output:
            PromptUtils.enter_to_continue()
            pair_iphone(id)
        else:
            raise Exception("failed to pair")

    # a) run command attempt pair, ensure
    def save_conditional(output):
        if output and ("SUCCESS" in output or "ERROR" in output):
            return output

    cmd = CmdUtils()
    command = ["idevicepair", "pair", "-u", id]
    process_result = cmd.await_subproc(
        command,
        get_output=True,
        save_conditional=save_conditional,
    )

    if "ERROR" in process_result:
        print(process_result)
        handle_auth_error(process_result)

    return True


# - 4.
def prep_backup_dir(backup_name, no_encrypt):
    fs = FsUtils()

    if fs.is_valid_path(backup_name, no_exception=True) and fs.is_empty_dir(
        backup_name
    ):
        return backup_name

    backup_dir = f"{script_dir}/results/backups"
    if no_encrypt:
        backup_dir = f"{backup_dir}/unencrypted/{backup_name}"
    else:
        backup_dir = f"{backup_dir}/encrypted/{backup_name}"

    fs.create_dir(backup_dir)
    return backup_dir


# - 5.
def run_backup(id, backup_dir, full_backup, no_encryption):

    def enable_encryption(id):
        helper_msg = io._apply_color("(enter passcode after passwords)", "orange")
        io.start_msg(
            status="a",
            message=f"attempting to enable encryption... \n{helper_msg}",
        )
        cmd = CmdUtils()
        command = ["idevicebackup2", "-u", id, "-i", "encryption", "on"]
        subproc_output = cmd.await_subproc(command, get_output=True)
        result = io._apply_color(subproc_output, "green")

        if "successfully" in result or "already enabled" in result:
            return result
        else:
            io.error_msg(
                status="5.a", func="enable_encryption()", message=subproc_output
            )
            raise Exception()

    def determine_backup_flags(full, no_encryption):
        flags = []
        if full:
            flags.append("--full")

        # if not no_encryption:
        #     flags.append("--encrypt")

        return flags

    # a) enable encryption unless no-encrypt flag passed
    if not no_encryption:
        enabled = enable_encryption(id)
        io.info_msg(enabled, emphasize=True)

    # b) add full backup flag if arg passed
    io.start_msg(
        status="b" if not no_encrypt else "a",
        message="determining backup flags...",
        prev_line=True,
    )
    flags = determine_backup_flags(full_backup, no_encryption)
    io.done(subfunction=True)

    # c) run backup command --> idevicebackup2 -u <iphone_id> backup --full --encrypt <backup_dir>
    io.start_msg(
        status="c" if not no_encrypt else "b",
        message="executing iphone backup...",
        prev_line=True,
    )
    cmd = CmdUtils()
    command = ["idevicebackup2", "-u", id, "backup"] + flags + [backup_dir]
    complete = cmd.stream_await_subproc(command, get_output=True)
    if "Could not perform backup" in complete:
        return True

    raise Exception("backup failed.")


# == main
def backup_iphone_data(no_encryption, full_backup, backup_name):

    # 1.
    io.start_msg(
        status="1/5",
        func="check_deps()",
        message="checking your system for required depencencies...",
    )
    check_deps()
    io.done()

    # 2.
    io.start_msg(
        status="2/5",
        func="get_target_phone_id()",
        message="searching for connected iphones...",
        prev_line=True,
    )
    iphone_id = get_target_iphone_id()
    io.done()

    # 3.
    io.start_msg(
        status="3/5",
        func="pair_iphone()",
        message="attempting to pair iphone...",
        # prev_line=True,
    )
    pair_iphone(iphone_id)
    io.done()

    # 4.
    io.start_msg(
        status="4/5",
        func="prep_backup_dir()",
        message="preparing directory for iphone backup data...",
        prev_line=True,
    )
    backup_dir = prep_backup_dir(backup_name, no_encryption)
    io.done()

    # 5.
    io.start_msg(
        status="5/5",
        func="run_backup()",
        message="backing up iphone data...",
    )
    run_backup(iphone_id, backup_dir, full_backup, no_encryption)
    io.done()
    io.success_msg(f"iphone data backed up at: {backup_dir}")


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
        "-n",
        "--name",
        default="",
        required=True,
        help="enter the backup name to create and store the backup in",
    )

    # NOTE: could allow the deps files as optional arguments
    args = parser.parse_args()
    no_encrypt = args.dont_encrypt
    full_backup = args.full
    backup_name = args.name

    backup_iphone_data(no_encrypt, full_backup, backup_name)


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
