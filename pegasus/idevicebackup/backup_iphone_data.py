import argparse, os


def backup_iphone_data(args):
    pass


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="")

    parser.add_argument(
        "--decrypt-dir",
        type=str,
        help="location of the directory containing the idevicebackup2 decrypted backup data",
    )

    parser.add_argument(
        "--output",
        required=False,
        default="",
        help="if you want to store the output to a file include this flag followed by the fp to store at",
    )

    args = parser.parse_args()

    backup_iphone_data(args)


# pseudo-code
# args:
# -> --no-encrypt: dont encrypt backup (boolean)
# -> -f/--full: full backup (boolean)
# -> --output: directory to store the backup (path-string)

# 1. check_deps()
#       --> check brew packages
#       --> check python/pip packages

# 2. get_connected_iphone_id()
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

# 5. backup_iphone_data(iphone_id, output_dir, encrypt_data, full, password)
#       --> run backup command (adding --full if necessary), save to output dir

# 6. (maybe) make_backup_dir_immutable(immutable_arg)
#       --> could at the very print the info commands for user to see after successfull backup


# NOTES:
# --> iphone must be unlocked !
# --> there are several times where authentication is needed on iphone
#   --> when turning of encryption
# --> when turning encryption of, i  was unable to pass password as a flag,
#   --> --password can only be passed with restore
