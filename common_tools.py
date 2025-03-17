import os, subprocess, sys
from pathlib import Path


from collections import namedtuple


class IOUtils:
    """for consitent, easily customizable printing in scripts"""

    pp = __import__("pprint")

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
        self.colors = IOUtils.COLORS

    def _apply_color(self, text: str, color: str = None) -> str:
        if color and color in self.colors:
            return self.colors[color] + text + self.colors["RESET"]
        return text

    def start_msg(self, message, curr_status, subfunction=False, prev_line=False):
        if subfunction:
            print(
                f"\t{self._apply_color(f'({curr_status})', 'purple')} {self._apply_color(message, 'gray')}... ",
                end="",
            )
        else:
            print(
                f"{self._apply_color(f'{curr_status}', 'blue')} {self._apply_color(message, 'black')}... ",
                end="" if prev_line else "\n",
            )

    def done(
        self,
        upper=True,
        newline=False,
    ):
        done = "done."
        if upper:
            done = "Done."
        colored_done = self._apply_color(done, "green")

        print(colored_done)
        if newline:
            print("---------\n")

    def warning_msg(
        self,
        message,
        upper=False,
        add_spacing=False,
        prompt_continue=False,
        prev_line=False,
    ):
        msg_pretext = "WARNING!" if upper else "(warning) ->"
        full_msg = f"{self._apply_color(msg_pretext, 'orange')} {self._apply_color(message, 'orange')}"

        if add_spacing:
            full_msg = f"\n{full_msg}\n"

        if prev_line:
            print("")

        print(full_msg)
        if prompt_continue:
            prompt = PromptUtils()
            prompt.to_continue()

    def info_msg(self, message, upper=False, add_spacing=False):
        msg_pretext = "INFO:" if upper else "(info) ->"
        full_msg = f"{self._apply_color(msg_pretext, 'blue')} {self._apply_color(message, 'gray')}"

        if add_spacing:
            full_msg = f"\n{full_msg}\n"

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

    def error_msg(
        self,
        message=None,
        status=None,
        func=None,
        error=None,
        raise_exception=False,
        prompt_continue=False,
    ):
        # prep message
        upper = True if raise_exception or prompt_continue else False
        error_substr = "\nERROR" if upper else "\n(error)"
        full_msg = (
            f"{error_substr} -> ({status}) failed with error:"
            if status
            else f"{error_substr} -> failed with error:"
        )
        full_msg = self._apply_color(full_msg, "red")

        if raise_exception:
            print(full_msg)
            if error:
                raise Exception(error)
            sys.exit(1)

        if message:
            if not error:
                full_msg = f"{full_msg} {message}"
            else:
                error = str(error)
                full_msg = f"{full_msg} \n{error}"

        print(full_msg)
        if prompt_continue:
            prompt = PromptUtils()
            prompt.to_continue()

    def clear_screen(self):
        os.system("clear")


class CmdUtils:
    """simplify running commands in python scripts"""

    shlex = __import__("shlex")
    Result = namedtuple("Result", ["stdout", "stderr", "returncode"])

    def __init__(self):
        self.io = IOUtils()

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
        time_out_after=None,
        env=None,
        input=None,
        raise_exception=True,
        prompt_continue=False,
    ):
        """simple run command with arg options"""
        try:
            result = subprocess.run(
                cmd_list,
                text=True,
                capture_output=not use_console,
                cwd=run_from,
                timeout=time_out_after,
                env=env,
                input=input,
            )
            return self.build_result_tuple(result)
        except Exception as e:
            self.io.error_msg(
                status="CmdUtils.run()",
                error=e,
                raise_exception=raise_exception,
                prompt_continue=prompt_continue,
            )

    def run_str(
        self,
        cmd_str: list,
        use_console=False,
        raise_exception=False,
        run_from=None,
        time_out_after=None,
        prompt_continue=False,
        env=None,
    ):
        """accepts a string as command argument (not safe), so precautions are taken with shlex.quote()"""
        try:
            secured_cmd = self.shlex.quote(cmd_str)

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
            self.io.error_msg(
                message="run_str command failed",
                error=e,
                status="cmd.run_str()",
                raise_exception=raise_exception,
                prompt_continue=prompt_continue,
            )

    def interactive(
        self,
        cmd_list: list,
        executable: str,
        connect_input=False,  # allows to connect to the the stdin (subprocess.PIPE)
        get_output=False,  # allows to capture the output (subprocess.PIPE)
        get_error=False,  # allows to capture the error (subprocess.PIPE)
        run_from=None,
        env=None,
        use_bytes=False,
        new_session=False,
        raise_exception=False,
        prompt_continue=False,
    ):
        """uses subprocess.Popen() which allows for communication with the process as events happen"""
        try:
            process = subprocess.Popen(
                cmd_list,
                executable=executable,
                text=not use_bytes,
                stdin=subprocess.PIPE if connect_input == True else None,
                stdout=subprocess.PIPE if get_output == True else None,
                stderr=subprocess.PIPE if get_error == True else None,
                cwd=run_from,
                env=env,
                start_new_session=new_session,
            )
            return process
        except Exception as e:
            self.io.error_msg(
                message="run command failed",
                status="cmd.interactive()",
                error=e,
                raise_exception=raise_exception,
                prompt_continue=prompt_continue,
            )

    def call(
        self,
        cmd_list: list,
        run_from=None,
        time_out_after=None,
        env=None,
    ):
        """runs a command but only the exit code can be returned to a variable"""
        try:
            return_code = subprocess.call(
                cmd_list, cwd=run_from, timeout=time_out_after, env=env
            )
            return return_code
        except Exception as e:
            self.io.error_msg("call command failed", e)

    def check_call(
        self,
        cmd_list: list,
        run_from=None,  # dir to execute command
        time_out_after=None,
        env=None,
        raise_exception=None,
        prompt_continue=None,
    ):
        """same as call() but returns an Exception (like check arg in run()), runs a command but only the exit code can be returned to a variable"""

        try:
            return_code = subprocess.call(
                cmd_list, cwd=run_from, timeout=time_out_after, env=env
            )
            return return_code
        except Exception as e:
            self.io.error_msg(
                message="check_call command failed",
                status="cmd.check_call()",
                error=e,
                raise_exception=raise_exception,
                prompt_continue=prompt_continue,
            )

    def grep(
        self,
        grep_for: str,
        cmd_output: str,
        raise_exception=True,
        prompt_continue=False,
    ):
        try:
            cmd = ["grep", grep_for]
            result = self.run(cmd, input=cmd_output)
            return result
            # return self.build_result_tuple(result)
        except Exception as e:
            self.io.error_msg(
                status="CmdUtils.grep()",
                error=e,
                raise_exception=raise_exception,
                prompt_continue=prompt_continue,
            )

    @staticmethod
    def cmd_has_no_args():
        return len(sys.argv) == 1


class PromptUtils:

    def __init__(self):
        self.io = IOUtils()

    def _is_empty_input(self, input):
        if input == "":
            self.io.error_msg("input cannot be empty.")
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
            print(f"{self._apply_color(prompt, 'black')}")
            for i, option in enumerate(options):
                opt_str = f"{i + 1} -> {option}"
                print(f"{self._apply_color(opt_str, 'gray')}")
            uinput = input("\nEnter number of selection: ")
            if not self._is_empty_input(uinput) and self._is_valid_input(
                uinput, [str(i) for i in range(1, len(options) + 1)]
            ):
                return options[int(uinput) - 1]

    def enter_to_continue(self):
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
        io = IOUtils()
        try:
            os.makedirs(path, exist_ok=True)
        except Exception as e:
            io.error_msg("")

    def __init__(self):
        self.io = IOUtils()
        self.mkdir = FsUtils.create_dir
        self.rm = FsUtils.remove_dir

    def exists(self, path):
        return Path(path).exists()

    def set_immutable(
        self,
        path,
        append_only=False,
        strict=False,
        user=True,
        system=False,
        fod=None,  # options are 'file'/'dir' to prevent make a directory you didn't intend immutable
    ):
        """makes file/directory passed as path immutable. only user immutable by default"""
        pass

        # if enforce_path_type:
        #     if enforce_path_type == "file":

        #     else
        # else:

    def is_valid_file(self, path, raise_exception=False, prompt_continue=False):
        if Path(path).is_file():
            return True
        else:
            self.io.error_msg(
                f"the path '{path}' is not a valid file",
                raise_exception=raise_exception,
                prompt_continue=prompt_continue,
            )
            return False

    def is_valid_dir(self, path, raise_exception=False, prompt_continue=False):
        if Path(path).is_dir():
            return True
        else:
            self.io.error_msg(
                f"the path '{path}' is not a valid file",
                raise_exception=raise_exception,
                prompt_continue=prompt_continue,
            )
            return False

    def is_valid_path(
        self, path, strict=["file", "dir"], raise_exception=False, prompt_continue=False
    ):
        if type(strict) == str:
            if strict == "file" and self.is_valid_file(
                path, raise_exception=raise_exception, prompt_continue=prompt_continue
            ):
                return True
            if strict == "dir" and self.is_valid_dir(
                path, raise_exception=raise_exception, prompt_continue=prompt_continue
            ):
                return True
        else:
            return self.is_valid_file(
                path, raise_exception=raise_exception, prompt_continue=prompt_continue
            ) or self.is_valid_dir(
                path, raise_exception=raise_exception, prompt_continue=prompt_continue
            )

    def is_abs_path(self, path):
        return Path(path).is_absolute()

    def ensure_absolute_path(self, path):
        """assumes that path has already been validated"""
        return Path(path).absolute()

    def get_path_type(self, path):
        if self.is_valid_path(path):
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
        fs = FsUtils()
        f = FileUtils()
        prompt = PromptUtils()

        if not fs.is_valid_path(fp, strict="file"):
            fp = prompt.for_path(fod="file")

        # open and store contents of file in list
        dependencies = f.open(fp, mode="r", return_type="lines")
        if dependencies[0] == "":
            return False

        # loop through deps file, creating dict structures for each line
        structured_deps = []
        for dep in dependencies:
            cleaned_dep = dep.split()
            structured_dep = {cleaned_dep[0]: cleaned_dep[1]}
            structured_deps.append(structured_dep)

        return structured_deps

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

    def _is_brew_installed(self, os="mac"):
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
            return False

    def has_brew_deps(self, dependencies_fp, os="mac"):
        # 1.
        if not self._is_brew_installed():
            self.io.error_msg(
                status="env.has_brew_deps()", message="check README for requirements"
            )

        # 2.
        dependencies = self.get_requirements_file(dependencies_fp)
        if not dependencies:
            self.io.warning_msg(
                f"no dependencies listed in file: {dependencies_fp}", upper=True
            )
            return True

        # 3.
        brew_list_cmd = self.get_pkg_mgr_list_cmd("brew")

        # 4.
        failed = []
        for dep in dependencies:
            has_dependency = self._check_curr_dep(dep, brew_list_cmd)
            if not has_dependency:
                failed.append(dep)

        # 5.
        if len(failed) == 0:
            self.io.info_msg("all brew dependecies satisified.")
            return True
        else:

            self.io.error_msg(
                f"failed to meet brew dependency requirements for the following brew packages: {failed}",
                status="check_deps() --> has_brew_deps()",
                raise_exception=True,
            )

    def has_pip_deps(self, dependencies_fp, os="mac"):
        # 1.
        dependencies = self.get_requirements_file(dependencies_fp)
        if not dependencies:
            self.io.warning_msg(
                f"no dependencies listed in file: {dependencies_fp}", upper=True
            )
            return True

        # 2.
        pip_list_cmd = self.get_pkg_mgr_list_cmd("pip")

        # 3.
        failed = []
        for dep in dependencies:
            has_dependency = self._check_curr_dep(dep, pip_list_cmd)
            if not has_dependency:
                failed.append(dep)

        # 4.
        if len(failed) == 0:
            self.io.info_msg("all pip dependecies satisified.")
            return True
        else:
            self.io.error_msg(
                f"failed to meet brew dependency requirements for the following pip packages: {failed}",
                status="check_deps() --> has_brew_deps()",
                raise_exception=True,
            )


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
        pass

    def open(self, fp, mode="r", return_type="lines"):
        fs = FsUtils()
        f = FileUtils()
        if fs.is_valid_path(fp, strict="file"):
            with open(fp, mode) as f:
                f_content = f.read()
                if return_type == "lines":
                    lines = f_content.splitlines()
                    return lines
                else:
                    return f_content

        return None
