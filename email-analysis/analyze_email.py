import argparse, os, sys
import email
from email import policy
from email.parser import BytesParser, BytesHeaderParser, BytesFeedParser

import mail-

#== NOTES ==#
# 1. have confirmed CC: None on emails i know were only sent to me versus white space in mass emails


sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), os.environ.get("py"))))
from common_tools import FsUtils 

def open_eml_file(fp):
    with open(fp, "rb") as f:
        email_content = BytesParser(policy=policy.default).parse(f)
        return email_content
    

def extract_metadata(msg_body, to_console=False):
    metadata = {
        "From": msg_body["From"],
        "To": msg_body["To"],
        "CC": msg_body["CC"],
        "BCC": msg_body["BCC"],  
        "Date": msg_body["Date"],
        "Subject": msg_body["Subject"],
        "Message-ID": msg_body["Message-ID"],
        "Received": msg_body.get_all("Received"),
        "X-Originating-IP": msg_body.get("X-Originating-IP"),  
        "SPF": msg_body.get("Received-SPF"),  
        "DKIM": msg_body.get("DKIM-Signature"),
        "DMARC": msg_body.get("Authentication-Results"),  
        "User-Agent": msg_body.get("User-Agent"),  
        "X-Mailer": msg_body.get("X-Mailer"),  
        "Precedence": msg_body.get("Precedence"), 
        "List-Unsubscribe": msg_body.get("List-Unsubscribe"), 
    }

    if to_console:
        for key, value in metadata.items():
            print(f"{key}: {value}")

    return metadata


def get_return_path(email_content):
    # 
    return email_content["Return-Path"]



if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="")
    parser.add_argument("-e", "--email", type=str, help="")
    args = parser.parse_args()
    eml_file = args.email

    fs = FsUtils()
    eml_file = fs.ensure_absolute_path(args.email)

    email_content = open_eml_file(eml_file)
    # print(email_content)
    headers = extract_metadata(email_content, to_console=True)
    # rp = get_return_path(email_content)
    # print(f"rp: {rp}")

