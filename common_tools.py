import os, subprocess, sys, pyaml, shlex
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


class PrintUtils:
    pass


class PromptUtils:
    pass


class PdfUtils:
    def check_digital_signature(self, pdf_path):
        command = CmdUtils()
        cmd = ["pdfsig", pdf_path]
        command.run(cmd, use_console=True, check=True)


class YamlUtils:
    pass
