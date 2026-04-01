import argparse, os, sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), os.environ.get("py"))))
from common_tools import AiUtils

def chat(query, interactive=False):
    ai = AiUtils()
    response = ai.query(query, interactive)
    print(response)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="")
    parser.add_argument("-q", "--query", type=str)
    parser.add_argument("-i", "--interactive", action="store_true", help="choose a non default the model for the query")

    args = parser.parse_args()
    query = args.query
    interactive = args.interactive

    chat(query, interactive)
