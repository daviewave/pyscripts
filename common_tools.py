import os, subprocess, sys, shlex, pprint, shutil
from typing_extensions import List, Dict
from os import _Environ
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

    @staticmethod
    def _apply_color(text: str, color: str = None) -> str:
        if color and color in IOUtils.COLORS:
            return IOUtils.COLORS[color] + text + IOUtils.COLORS["RESET"]
        return text

    def start_msg(self, message, curr_status, subfunction=False, prev_line=False):
        if subfunction:
            print(
                f"\t{IOUtils._apply_color(f'({curr_status})', 'purple')} {IOUtils._apply_color(message, 'gray')}... ",
                end="",
            )
        else:
            print(
                f"{IOUtils._apply_color(f'{curr_status}', 'blue')} {IOUtils._apply_color(message, 'black')}... ",
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
        colored_done = IOUtils._apply_color(done, "green")

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
        full_msg = f"{IOUtils._apply_color(msg_pretext, 'orange')} {IOUtils._apply_color(message, 'orange')}"

        if add_spacing:
            full_msg = f"\n{full_msg}\n"

        if prev_line:
            print("")

        print(full_msg)
        if prompt_continue:
            prompt = PromptUtils()
            prompt.continue_prompt()

    def info_msg(self, message, upper=False, add_spacing=False):
        msg_pretext = "INFO:" if upper else "(info) ->"
        full_msg = f"{IOUtils._apply_color(msg_pretext, 'blue')} {IOUtils._apply_color(message, 'gray')}"

        if add_spacing:
            full_msg = f"\n{full_msg}\n"

        print(full_msg)

    def success_msg(self, message, result_var=None):
        msg_pretext = IOUtils._apply_color("success!", "green")
        full_msg = f"{msg_pretext} {IOUtils._apply_color(message, 'green')}"

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
                        return f"-> output:\n {pyaml.dump(result_var)}"
                    else:
                        print("-> output:")
                        pprint.pprint(result_var, indent=4)
                elif type(result_var) == dict:
                    print("-> output:")
                    pprint.pprint(result_var, indent=4)

        print("")
        print(full_msg)
        format_result_output(result_var)
        print("==========================")

    def error_msg(
        self,
        message,
        error=None,
        raise_exception=False,
        prompt_continue=False,
    ):
        # prep message
        upper = True if raise_exception or prompt_continue else False
        msg_pretext = "\nERROR!" if upper else "\n(error) -->"
        full_msg = f"{IOUtils._apply_color(msg_pretext, 'red')} {IOUtils._apply_color(message, 'red')}"

        # print and determine if should exit or not
        print(full_msg)
        if raise_exception:
            raise Exception(error)

        if error:
            redstr = IOUtils._apply_color("--> error:", "red")
            print(f"{redstr} {str(error if error else '')}")
        if prompt_continue:
            input("Do you want to continue? (y/n) ")
            if not input().lower() == "y":
                sys.exit(1)

    def clear_screen(self):
        os.system("clear")


io = IOUtils()


class CmdUtils:
    Result = namedtuple("Result", ["stdout", "stderr", "returncode"])

    def build_result_tuple(self, result):
        return self.Result(
            stdout=result.stdout,
            stderr=result.stderr,
            returncode=result.returncode,
        )

    def run(
        self,
        cmd_list: List[str],
        use_console=False,
        run_from=None,
        time_out_after=None,
        env=None,
        prompt_continue=False,
        raise_exception=False,
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
            )
            return self.build_result_tuple(result)
        except Exception as e:
            io.error_msg(
                "run command failed",
                e,
                raise_exception=raise_exception,
                prompt_continue=prompt_continue,
            )

    def run_str(
        self,
        cmd_str: List[str],
        check=False,
        use_console=False,
        run_from=None,
        time_out_after=None,
        prompt_continue=False,
        env=None,
    ):
        """accepts a string as command argument (not safe), so precautions are taken with shlex.quote()"""
        try:
            secured_cmd = shlex.quote(cmd_str)
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
            io.error_msg(
                "run_str command failed",
                e,
                raise_exception=check,
                prompt_continue=prompt_continue,
            )

    def interactive(
        self,
        cmd_list: List[str],
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
            io.error_msg(
                "run command failed",
                e,
                raise_exception=raise_exception,
                prompt_continue=prompt_continue,
            )

    def call(
        self,
        cmd_list: List[str],
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
            io.error_msg("call command failed", e)

    def check_call(
        self,
        cmd_list: List[str],
        run_from: str,  # dir to execute command
        time_out_after: int,
        env: _Environ[str],
    ):
        """same as call() but returns an Exception (like check arg in run()), runs a command but only the exit code can be returned to a variable"""

        try:
            return_code = subprocess.call(
                cmd_list, cwd=run_from, timeout=time_out_after, env=env
            )
            return return_code
        except Exception as e:
            io.error_msg("check_call command failed", e)

    def grep(self, grep_for: str, cmd_output):
        try:
            cmd = ["grep", grep_for]
            result = subprocess.run(cmd, input=cmd_output)
            return self.build_result_tuple(result)
        except Exception as e:
            io.error_msg(f"grep command '{cmd}' failed", e)

    @staticmethod
    def cmd_has_no_args():
        return len(sys.argv) == 1


class PromptUtils:
    def _is_empty_input(self, input):
        if input == "":
            io.error_msg("input cannot be empty.")
            return True
        return False

    def _is_valid_input(self, input: str, allowed: list) -> bool:
        if input not in allowed:
            io.error_msg(f"input '{input}' not allowed.")
            return False
        return True

    def _is_valid_input_type(self, input: str, allowed_type: type) -> bool:
        if not isinstance(input, allowed_type):
            io.error_msg(f"input '{input}' not allowed type.")
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
            print(f"{IOUtils._apply_color(prompt, 'black')}")
            for i, option in enumerate(options):
                opt_str = f"{i + 1} -> {option}"
                print(f"{IOUtils._apply_color(opt_str, 'gray')}")
            uinput = input("\nEnter number of selection: ")
            if not self._is_empty_input(uinput) and self._is_valid_input(
                uinput, [str(i) for i in range(1, len(options) + 1)]
            ):
                return options[int(uinput) - 1]

    def enter_to_continue(self):
        input("\nPress enter to continue...")

    def overwrite(self, path):
        msg = f"found existing '{path}'"
        io.warning_msg(msg, upper=True, add_spacing=True, prev_line=True)
        yon = self.yes_or_no("Would you like to overwrite the existing? ")
        if yon == "yes":
            return True
        else:
            return False

    def continue_prompt(self):
        yon = self.yes_or_no("Do you want to continue?")
        if yon == "no":
            print("exiting...")
            sys.exit(1)
        return

    def path_prompt(self, must_exist=True, fod=None):
        fs = FsUtils()
        beginning_prompt = f"enter {fod if fod else "valid"} path"
        must_exist_str = "--> must be an existing" if must_exist else ""
        prompt = f"{beginning_prompt} {must_exist_str}"
        
        
        while True:
            path = self.open_ended(prompt)
            if not must_exist:
                return fs.ensure_absolute_path()

            if must_exist or fod == "file":
                if fs.is_valid_path(path):
                    return fs.ensure_absolute_path(path)
            else:
                path = fs.ensure_absolute_path(path)
                fs.create_dir(path)
                return path



class PdfUtils:
    def check_digital_signature(self, pdf_path):
        command = CmdUtils()
        cmd = ["pdfsig", pdf_path]
        command.run(cmd, use_console=True, check=True)


class FsUtils:
    @staticmethod
    def remove_dir(dir):
        shutil.rmtree(dir)

    @staticmethod
    def create_dir(path):
        os.makedirs(path, exist_ok=True)

    
    def exists(self, path):
        return Path(path).exists()
        

    def set_immutable(
        self,
        path,
        append_only=False,
        strict=False,
        user=True,
        system=False,
        enforce_path_type=None,  # can be set to 'file' or 'dir'
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
            io.error_msg(
                f"the path '{path}' is not a valid file",
                raise_exception=raise_exception,
                prompt_continue=prompt_continue,
            )
            return False

    def is_valid_dir(self, path, raise_exception=False, prompt_continue=False):
        if Path(path).is_dir():
            return True
        else:
            io.error_msg(
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

    def prep_output_dir(
        self, path, must_exist=False, saving_a="file", raise_excpeption=False
    ):
        """scenario where the script is creating a new file or directory"""
        if saving_a == "file":
            if not must_exist

            if self.is_valid_path(
                path, strict="dir", raise_exception=raise_excpeption
            ):
                return path

            if not must_exist:
                io.info_msg(f"creating new directory at '{path}'")
                path = self.ensure_absolute_path(path)
                self.create_dir(path)
                return path
            else:
                io.error_msg("the directory must already exist", raise_exception=raise_excpeption)
                return False                        

        # full directory --> never want this to already exist 
        else:
            while True:
                if self.exists(path):
                    prompt = PromptUtils()
                    wants_to_overwrite = prompt.overwrite(path)
                    if wants_to_overwrite:
                        FsUtils.remove_dir(path)
                        FsUtils.create_dir(path)
                        return path
                    else:
                        path = prompt.path_prompt(must_exist=False, fod="dir")
                        

    def handle_symlink(self, fp):
        if Path(fp).is_symlink():
            pass
