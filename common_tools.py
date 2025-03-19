import os, subprocess, sys
from pathlib import Path


from collections import namedtuple


class IOUtils:
    """for consitent, easily customizable printing in scripts"""

    COLORS = {
        "purple": "\033[38;5;54m",
        "lpurple": "\033[95m",
        "lblue": "\033[94m",
        "blue": "\033[38;5;21m",
        "lorange": "\033[38;5;214m",
        "orange": "\033[38;5;166m",
        "lgreen": "\033[92m",
        "green": "\033[32m",
        "lred": "\033[91m",
        "red": "\033[31m",
        "yellow": "\033[93m",
        "cyan": "\033[96m",
        "gray": "\033[90m",
        "black": "\033[30m",
        "RESET": "\033[0m",
    }

    def __init__(self):
        import pprint as pp

        self.colors = IOUtils.COLORS
        self.pp = pp

    def _apply_color(self, text: str, color: str = None) -> str:
        if color and color in self.colors:
            return self.colors[color] + text + self.colors["RESET"]
        return text

    def start_msg(self, status, message, func=None, prev_line=False):
        start_msg = ""

        if "1" in status:
            print("")

        # 1.
        if "/" in status:
            status = f"({status})"
            status = self._apply_color(status, "blue")
        else:
            status = f"  ({status})"
            status = self._apply_color(status, "purple")

        # 2.
        start_msg = f"{status} {func}: {message}" if func else f"{status}-> {message}"

        # 3.
        print(start_msg, end="" if prev_line else "\n")

    def done(self, subfunction=False):
        done = "done." if subfunction else "Done."
        colored_done = self._apply_color(done, "green")
        print(colored_done)
        if not subfunction:
            print("---------\n")

    def skip_msg(self):
        msg = "skipped."
        msg = self._apply_color(msg, "green")
        print(msg)

    def warning_msg(
        self,
        message,
        emphasize,
        prompt_continue=False,
    ):
        msg_pretext = "\n\nWARNING:" if emphasize else "(warning) -->"
        msg_pretext = self._apply_color(msg_pretext, "orange")
        full_msg = f"{msg_pretext} {message}"
        if emphasize:
            full_msg = f"{full_msg}\n"

        print(full_msg)

        if prompt_continue:
            prompt = PromptUtils()
            prompt.to_continue()

    def info_msg(self, message, emphasize=False):
        msg_pretext = "\n\nINFO:" if emphasize else "(info) -->"
        msg_pretext = self._apply_color(msg_pretext, "blue")
        full_msg = f"{msg_pretext} {message}"
        if emphasize:
            full_msg = f"{full_msg}\n"

        print(full_msg)

    def success_msg(self, message, result_var=None):
        import json

        msg_pretext = self._apply_color("success!", "green")
        full_msg = f"{msg_pretext} {self._apply_color(message, 'green')}"

        def format_result_output(result_var):
            if result_var:
                if type(result_var) == str and (
                    os.path.isfile(result_var) or os.path.isdir(result_var)
                ):
                    return f"\t-> results saved to: {result_var}"
                elif type(result_var) == str:
                    return f"-> output:\n\t {result_var}"
                elif type(result_var) == list:
                    if type(result_var[0]) != dict:
                        return f"-> output:\n {json.dumps(result_var, indent=2)}"
                    else:
                        print("-> output:")
                        self.pp.pprint(result_var, indent=4)
                elif type(result_var) == dict:
                    print("-> output:")
                    self.pp.pprint(result_var, indent=4)

        print("")
        print(full_msg)
        format_result_output(result_var)
        print("==========================")

    def error_msg(self, status, func, message=None, exception=None):
        # 1. going to assume that if exception isnt raised on the error, will always want to prompt to continue
        # 2. also can assume that if the Exception(e) object is passed, the exception was not raised and therefore it was a non-fatal error, will still prompt the user to continue automatically at this point

        # prep message
        msg_pretext = (
            f"\n\nError! ({status}) {func}"
            if message
            else f"\n\nError! ({status}) {func} -->"
        )
        msg_pretext = self._apply_color(msg_pretext, "red")

        full_msg = msg_pretext
        if message:
            full_msg = f"{msg_pretext} {message}"

        if exception:
            full_msg = f"{full_msg}:\n{exception}"

        print(full_msg)
        if exception:
            prompt = PromptUtils()
            prompt.to_continue()

    def clear_screen(self):
        os.system("clear")


class CmdUtils:
    """simplify running commands in python scripts"""

    Result = namedtuple("Result", ["stdout", "stderr", "returncode"])

    def __init__(self):
        import shlex as shlex

        self.io = IOUtils()
        self.cmd_safety = shlex

    def build_result_tuple(self, result):
        return self.Result(
            stdout=result.stdout,
            stderr=result.stderr,
            returncode=result.returncode,
        )

    def run(
        self,
        cmd_list: list,
        use_console=False,
        run_from=None,
        check=None,
        time_out_after=None,
        env=None,
        input=None,
        no_exception=False,
    ):
        """simple run command with arg options"""
        try:
            result = subprocess.run(
                cmd_list,
                text=True,
                capture_output=not use_console,
                cwd=run_from,
                check=check,
                timeout=time_out_after,
                env=env,
                input=input,
            )
            return self.build_result_tuple(result)
        except Exception as e:
            if no_exception:
                self.io.error_msg(status="CmdUtils", func="run()", exception=e)
                return False
            else:
                self.io.error_msg(status="CmdUtils", func="run()")
                raise Exception(e)

    def run_str(
        self,
        cmd_str: list,
        use_console=False,
        run_from=None,
        time_out_after=None,
        env=None,
        no_exception=False,
    ):
        """accepts a string as command argument (not safe), so precautions are taken with shlex.quote()"""
        try:
            secured_cmd = self.cmd_safety.quote(cmd_str)

            result = subprocess.run(
                secured_cmd,
                text=True,
                capture_output=not use_console,
                cwd=run_from,
                timeout=time_out_after,
                env=env,
            )
            return self.build_result_tuple(result)
        except Exception as e:
            if no_exception:
                self.io.error_msg(status="CmdUtils", func="run_str()", exception=e)
                return False
            else:
                self.io.error_msg(status="CmdUtils", func="run_str()")
                raise Exception(e)

    # come back to this when needed in script
    def interactive(
        self,
        cmd_list: list,
        executable=None,
        connect_input=False,  # allows to connect to the the stdin (subprocess.PIPE)
        get_output=False,  # allows to capture the output (subprocess.PIPE)
        get_error=False,  # allows to capture the error (subprocess.PIPE)
        run_from=None,
        env=None,
        use_bytes=False,
        new_session=False,
        no_exception=False,
    ):
        """uses subprocess.Popen() which allows for communication with the process as events happen"""
        try:
            process = subprocess.Popen(
                cmd_list,
                executable=executable,
                text=not use_bytes,
                # stdin=sys.stdin if connect_input == True else None,
                stdin=subprocess.PIPE if connect_input == True else None,
                # stdout=sys.stdout if get_output == True else None,
                stdout=subprocess.PIPE if get_output == True else None,
                # stderr=sys.stderr if get_error == True else None,
                stderr=subprocess.PIPE if get_error == True else None,
                cwd=run_from,
                env=env,
                start_new_session=new_session,
            )
            return process
        except Exception as e:
            if no_exception:
                self.io.error_msg(status="CmdUtils", func="interactive()", exception=e)
                return False
            else:
                self.io.error_msg(status="CmdUtils", func="interactive()")
                raise Exception(e)

    def call(
        self,
        cmd_list: list,
        run_from=None,
        time_out_after=None,
        env=None,
        no_exception=False,
    ):
        """runs a command but only the exit code can be returned to a variable"""
        try:
            return_code = subprocess.call(
                cmd_list, cwd=run_from, timeout=time_out_after, env=env
            )
            return return_code
        except Exception as e:
            if no_exception:
                self.io.error_msg(status="CmdUtils", func="call()", exception=e)
                return False
            else:
                self.io.error_msg(status="CmdUtils", func="call()")
                raise Exception(e)

    def check_call(
        self,
        cmd_list: list,
        run_from=None,  # dir to execute command
        time_out_after=None,
        env=None,
        no_exception=False,
    ):
        """same as call() but returns an Exception (like check arg in run()), runs a command but only the exit code can be returned to a variable"""

        try:
            return_code = subprocess.call(
                cmd_list, cwd=run_from, timeout=time_out_after, env=env
            )
            return return_code
        except Exception as e:
            if no_exception:
                self.io.error_msg(status="CmdUtils", func="call()", exception=e)
                return False
            else:
                self.io.error_msg(status="CmdUtils", func="call()")
                raise Exception(e)

    def grep(self, grep_for: str, cmd_output: str):
        cmd = ["grep", grep_for]
        result = self.run(cmd, input=cmd_output)
        return result

    @staticmethod
    def cmd_has_no_args():
        return len(sys.argv) == 1


class PromptUtils:
    def __init__(self):
        self.io = IOUtils()

    def _is_empty_input(self, input):
        if input == "":
            # self.io.error_msg(message="input cannot be empty.")
            return True
        return False

    def _is_valid_input(self, input: str, allowed: list) -> bool:
        if input not in allowed:
            self.io.error_msg(f"input '{input}' not allowed.")
            return False
        return True

    def _is_valid_input_type(self, input: str, allowed_type: type) -> bool:
        if not isinstance(input, allowed_type):
            self.io.error_msg(f"input '{input}' not allowed type.")
            return False
        return True

    def yes_or_no(self, prompt: str) -> bool:
        while True:
            uinput = input(f"{prompt} (y/n): ").lower()
            if not self._is_empty_input(uinput) and self._is_valid_input(
                uinput, ["y", "n"]
            ):
                return uinput

    def open_ended(self, prompt: str) -> str:
        while True:
            uinput = input(f"{prompt}: ")
            if not self._is_empty_input(uinput):
                return uinput

    def list_selection(self, prompt: str, options: list) -> str:
        while True:
            print(f"{self.io._apply_color(prompt, 'black')}")
            for i, option in enumerate(options):
                opt_str = f"{i + 1} -> {option}"
                print(f"{self.io._apply_color(opt_str, 'gray')}")
            uinput = input("\nEnter number of selection: ")
            if not self._is_empty_input(uinput) and self._is_valid_input(
                uinput, [str(i) for i in range(1, len(options) + 1)]
            ):
                return options[int(uinput) - 1]

    @staticmethod
    def enter_to_continue():
        input("\nPress enter to continue...")

    def to_overwrite(self, path):
        msg = f"found existing '{path}'"
        self.io.warning_msg(msg, upper=True, add_spacing=True, prev_line=True)
        yon = self.yes_or_no("Would you like to overwrite the existing? ")
        if yon == "yes":
            return True
        else:
            return False

    def to_continue(self):
        yon = self.yes_or_no("Do you want to continue?")
        if yon == "no":
            print("exiting...")
            sys.exit(1)
        return True

    def for_path(
        self,
        fod=None,
        must_exist=False,
    ):
        fs = FsUtils()
        beginning_prompt = f"enter {fod if fod else 'valid'} path"
        must_exist_str = "--> must be an existing" if must_exist else ""
        prompt = f"{beginning_prompt} {must_exist_str}"

        while True:
            path = self.open_ended(prompt)
            if must_exist or fod == "file":
                if fs.is_valid_path(path):
                    return fs.ensure_absolute_path(path)
            else:
                try:
                    path = fs.ensure_absolute_path(path)
                except:
                    self.io.warning_msg("failed to get absolute path.")

                fs.create_dir(path)
                return path


class PdfUtils:
    def __init__(self):
        self.cmd = CmdUtils()

    def check_digital_signature(self, pdf_path):
        cmd = ["pdfsig", pdf_path]
        self.cmd.run(cmd, use_console=True, check=True)


class FsUtils:
    @staticmethod
    def remove_dir(dir):
        import shutil

        fs = FsUtils()
        if fs.is_valid_path(dir, strict="dir"):
            shutil.rmtree(dir)

    @staticmethod
    def create_dir(path):
        return os.makedirs(path, exist_ok=True)

    def __init__(self):
        self.io = IOUtils()
        self.mkdir = FsUtils.create_dir
        self.rm = FsUtils.remove_dir

    def exists(self, path):
        return Path(path).exists()

    def is_valid_file(self, path):
        return Path(path).is_file()

    def is_valid_dir(self, path):
        return Path(path).is_dir()

    def is_empty_dir(dir):
        return os.listdir(dir) == 0

    def is_valid_path(
        self,
        path,
        strict=["file", "dir"],
        no_exception=False,
    ):
        if type(strict) == str:
            if strict == "file" and self.is_valid_file(path):
                return True

            if strict == "dir" and self.is_valid_dir(path):
                return True

            if no_exception:
                return False

        elif self.is_valid_file(path) or self.is_valid_dir(path):
            return True

        elif no_exception:
            return False

        else:
            self.io.error_msg(status="FsUtils", func="is_valid_path()", message=path)
            raise OSError("invalid path provided")

    def is_abs_path(self, path):
        return Path(path).is_absolute()

    def ensure_absolute_path(self, path):
        """assumes that path has already been validated"""
        return Path(path).absolute()

    def get_path_type(self, path):
        if self.is_valid_file(path):
            return "file"
        else:
            return "dir"

    def validate_output_dir(
        self, path, must_exist=False, saving_a="file", raise_excpeption=False
    ):
        """scenario where the script is creating a new file or directory"""
        if saving_a == "file":
            if self.is_valid_path(path, strict="dir", raise_exception=raise_excpeption):
                return path

            if not must_exist:
                self.io.info_msg(f"creating new directory at '{path}'")
                path = self.ensure_absolute_path(path)
                self.create_dir(path)
                return path
            else:
                self.io.error_msg(
                    "the directory must already exist", raise_exception=raise_excpeption
                )
                return False

        # full directory --> never want this to already exist
        else:
            while True:
                if self.exists(path):
                    prompt = PromptUtils()
                    wants_to_overwrite = prompt.to_overwrite(path)
                    if wants_to_overwrite:
                        self.rm(path)
                        self.mkdir(path)
                        return path
                    else:
                        path = prompt.for_path(fod="dir")

    def set_immutable(
        self,
        path,
        strict=["file", "dir"],
        system=False,
        append_only=False,
        max=False,
    ):
        def get_immutability_level(system, append_only):
            if system:
                if max:
                    return "6"
                elif append_only:
                    return "5"
                else:
                    return "4"
            else:
                if max:
                    return "3"
                elif append_only:
                    return "2"
                else:
                    return "1"

        def get_immutablity_level_flag(level):
            mappings = {
                "1": "uappend",
                "2": "sappend",
                "3": "uchg",
                "4": "schg",
                "5": "uimmutable",
                "6": "simmutable",
            }
            return mappings.get(level)

        # 1. validate path
        if not self.is_valid_path(path, strict=strict):
            return False

        # 2. prepare command
        cmd_start = ["sudo", "chflags"] if system else ["chflags"]
        immutablity_level = get_immutability_level(system, append_only)
        immutable_flag = get_immutablity_level_flag(immutablity_level)
        full_cmd = cmd_start + [immutable_flag, path]

        # 3. run command
        cmd = CmdUtils()
        result = cmd.run(full_cmd)
        if result.returncode == 0:
            self.io.info_msg(f"{path} is now immutable.")
            return True
        else:
            self.io.warning_msg(f"failed to set {path} as immutable.")
            return False

    def get_file_directory(path):
        return Path(path).stem()

    def handle_symlink(self, fp):
        if Path(fp).is_symlink():
            pass


class EnvUtils:
    """functions to validate dependencies acorss various operating systems, pkg managers, pkgs/libs"""

    sh = __import__("shutil")

    def __init__(self):
        self.io = IOUtils()
        self.cmd = CmdUtils()

    def get_versioning_digits(self, version_tag):
        split_version_nums = []
        for char in version_tag:
            if char.isdigit():
                split_version_nums.append(char)

            if len(split_version_nums) == 3:
                return split_version_nums

    def get_pkg_mgr_list_cmd(self, pkg_mgr):
        mappings = {
            "brew": ["brew", "list", "--versions"],
            "pip": ["pip", "list"],
        }
        return mappings.get(pkg_mgr)

    def get_requirements_file(self, fp):
        # i. open and store contents of file in list
        f = FileUtils()
        deps_file_contents = f.open(fp, mode="r", return_type="lines")

        # ii. loop through deps file, creating dict structures for each line
        try:
            structured_deps = []
            for dep in deps_file_contents:
                cleaned_dep = dep.split()
                structured_dep = {cleaned_dep[0]: cleaned_dep[1]}
                structured_deps.append(structured_dep)

            return structured_deps
        except Exception as e:
            self.io.error_msg(status="EnvUtils", func="get_requirements_file()")
            raise Exception(e)

    def _check_curr_dep(self, dependency, list_cmd):

        def check_system_for_pkg(req_pkg, list_cmd_output):
            lines = list_cmd_output.splitlines()
            for line in lines:
                if req_pkg in line:
                    return line
            return False

        def has_minimum_version(version_found, reqd_version):
            version_found_list = self.get_versioning_digits(version_found)
            reqd_version_list = self.get_versioning_digits(reqd_version)

            # 1. split version string into corresponding variables
            version_found_num_primary = int(version_found_list[0])
            version_found_num_secondary = int(version_found_list[1])
            version_found_num_minor = int(version_found_list[2])

            reqd_version_num_primary = int(reqd_version_list[0])
            reqd_version_num_secondary = int(reqd_version_list[1])
            reqd_version_num_minor = int(reqd_version_list[2])

            # 2. determine if version req's are met-- comparing major version number first
            if version_found_num_primary > reqd_version_num_primary:
                return True
            elif version_found_num_primary < reqd_version_num_primary:
                return False
            else:
                # next compares secondary version number
                if version_found_num_secondary > reqd_version_num_secondary:
                    return True
                elif version_found_num_secondary < reqd_version_num_secondary:
                    return False
                else:
                    # at this point as long as the 3 number >= it satisfies req
                    if version_found_num_minor >= reqd_version_num_minor:
                        return True
                    else:
                        return False

        # 1. unpack values out of dict args
        req_pkg, req_version = next(iter(dependency.items()))

        # 2. contruct and run main command
        result = self.cmd.run(list_cmd)
        result = result.stdout

        # 3. local_pkg_search() --> will be able to determine if packaged installed on system at this point
        found_local_pkg_info = check_system_for_pkg(req_pkg, result)
        if not found_local_pkg_info:
            return False

        # 4. structure found to {pkg: version}
        regex = RegexUtils()
        found_local_pkg = found_local_pkg_info.split()[0].strip()
        found_local_version = regex.extract_version_tag(found_local_pkg_info)

        # 5. has_minimum_version()
        if has_minimum_version(found_local_version, req_version):
            return True
        else:
            return False

    def validate_brew_installed(self, os="mac"):
        # determine command based on os
        cmd = None
        if os == "mac":
            cmd = ["which", "brew"]
        elif os == "linux":
            cmd = ["which", "brew"]
        else:
            # windows
            # cmd = ["which", "brew"]
            pass

        # run cmd and use output to return true or false
        result = self.cmd.run(cmd)
        result = result.stdout
        lines = result.splitlines()
        if len(lines) == 1:
            return True
        else:
            raise OSError("homebrew not installed on system")

    # major func
    def validate_deps_installed(self, fp, pkg_mgr, os="mac"):
        # i.
        fs = FsUtils()
        fs.is_valid_path(fp, strict="file")
        fp = fs.ensure_absolute_path(fp)
        if FileUtils.is_empty_file(fp):
            return False

        # ii.
        brew_list_cmd = self.get_pkg_mgr_list_cmd(pkg_mgr)

        # iii.
        dependencies = self.get_requirements_file(fp)

        # iv.
        failed = []
        for dep in dependencies:
            try:
                has_dependency = self._check_curr_dep(dep, brew_list_cmd)
                if not has_dependency:
                    failed.append(dep)
            except Exception as e:
                self.io.error_msg(
                    status="iv", func="validate_deps_installed()", message=f"dep: {dep}"
                )
                raise Exception(e)

        # v.
        if len(failed) == 0:
            return True
        else:
            self.io.error_msg(
                status="v",
                func="validate_deps_installed()",
                message=f"the following {pkg_mgr} dependencies requirements were not met: {failed}",
            )
            raise OSError()


class RegexUtils:
    PATTERNS = {
        "version_tags_simple": r"\b\d+\.\d+\.\d+\b",
        "version_tags": r"\b\d+\.\d+\.\d+(?:[-_+][\w\d.]+)?\b",
        "version_tags_complex": r"\b[vV]?\d+\.\d+\.\d+(?:[-_+][\w\d.]+)?\b",
    }

    # NOTE: main 're' package functions
    # -> .match(pattern, str): only checks beginning of the string
    # -> .search(pattern, str): searches entire string
    # -> .findall(pattern, str): returns all regex matches
    # -> .finditer(pattern, str): returns an iterator yielding match objects for all matches.
    # -> .sub(pattern, replace_str, str): replace all regex instances with new string
    # -> .split(pattern, str): splits string at the regex

    def __init__(self):
        import re as r

        self.patterns = RegexUtils.PATTERNS
        self.re = r

    def extract_version_tag(self, search_str, complexity_level=3):
        complexity_level_mappings = {
            "1": "version_tags_simple",
            "2": "version_tags",
            "3": "version_tags_complex",
        }
        c_level_search = complexity_level_mappings.get(str(complexity_level))
        pattern = self.patterns.get(c_level_search)
        match = self.re.search(pattern, search_str)
        if match:
            return match.group()
        else:
            return False


class FileUtils:
    def __init__(self):
        self.io = IOUtils()

    def open(self, fp, mode="r", return_type="lines", no_exception=False):
        try:
            with open(fp, mode) as f:
                file_content = f.read()

                if not file_content:
                    return "empty"

                if return_type == "lines":
                    lines = file_content.splitlines()
                    return lines

                else:
                    return file_content

        except Exception as e:
            if no_exception:
                self.io.error_msg(
                    status="FileUtils", func="open()", message=f"file: {fp}"
                )
                return False
            else:
                self.io.error_msg(status="FileUtils", func="open()")
                raise Exception(e)

    @staticmethod
    def is_empty_file(fp):
        f = FileUtils()
        if f.open(fp) == "empty":
            return True
        else:
            return False
