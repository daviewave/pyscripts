import os, subprocess, sys, pyaml, shlex, pprint
from typing_extensions import List, Dict
from os import _Environ

from collections import namedtuple


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
        check=False,
        use_console=False,
        run_from=None,
        time_out_after=None,
        env=None,
    ):
        """simple run command with arg options"""
        try:
            result = subprocess.run(
                cmd_list,
                text=True,
                check=check,
                capture_output=not use_console,
                cwd=run_from,
                timeout=time_out_after,
                env=env,
            )
            return self.build_result_tuple(result)
        except Exception as e:
            print(f"run command '{cmd_list}' failed with error:")
            print(str(e))

    def run_str(
        self,
        cmd_str: List[str],
        check=False,
        use_console=False,
        run_from=None,
        time_out_after=None,
        env=None,
    ):
        """accepts a string as command argument (not safe), so precautions are taken with shlex.quote()"""
        try:
            secured_cmd = shlex.quote(cmd_str)
            result = subprocess.run(
                secured_cmd,
                text=True,
                check=check,
                capture_output=not use_console,
                cwd=run_from,
                timeout=time_out_after,
                env=env,
            )
            return self.build_result_tuple(result)

        except Exception as e:
            print(f"run shell command '{cmd_str}' failed with error:")
            print(str(e))

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
            print(f"interactive command '{cmd_list}' failed with error:")
            print(str(e))

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
            print(f"call command '{cmd_list}' failed with error:")
            print(str(e))

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
            print(f"call command '{cmd_list}' failed with error:")
            print(str(e))

    def grep(self, grep_for: str, cmd_output: str):
        try:
            cmd = ["grep", grep_for]
            result = subprocess.run(cmd, input=cmd_output)
            return self.build_result_tuple(result)
        except Exception as e:
            print(f"failed to grep cmd output: '{cmd_output}' with error:")
            print(str(e))

    @staticmethod
    def cmd_has_no_args():
        return len(sys.argv) == 1


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
        "bred": "\033[91m",
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
            input("Do you want to continue? (y/n) ")
            if not input().lower() == "y":
                sys.exit(1)

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
        self, message, error, upper=True, raise_exception=False, prompt_continue=False
    ):
        msg_pretext = "\nERROR!" if upper else "(error) -->"
        full_msg = f"{IOUtils._apply_color(msg_pretext, 'red')} {IOUtils._apply_color(message, 'bred')}"

        print(full_msg)
        if raise_exception:
            raise Exception(error)

        print(f"--> error:{str(error)}")
        if prompt_continue:
            input("Do you want to continue? (y/n) ")
            if not input().lower() == "y":
                sys.exit(1)


# Example usage:
if __name__ == "__main__":
    IOUtils.start_print(1, "Initializing main process")
    IOUtils.info_print("This is an informational message.")
    IOUtils.warning_print("This is a warning!", prompt_continue=True)
    IOUtils.done_print("done", uppercase=True)
    # Demonstrate inline done_print (e.g., updating progress on the same line)
    import time

    for i in range(5):
        IOUtils.done_print(f"Processing step {i+1}/5", inline=True)
        time.sleep(1)
    # End with a newline to ensure subsequent output is not overwritten.
    print()


class PromptUtils:
    pass


class PdfUtils:
    def check_digital_signature(self, pdf_path):
        command = CmdUtils()
        cmd = ["pdfsig", pdf_path]
        command.run(cmd, use_console=True, check=True)


class YamlUtils:
    pass
