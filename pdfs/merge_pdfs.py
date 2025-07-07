import argparse
from PyPDF2 import PdfMerger

def append_pdfs(base_form, amend_files, output_file):
    merger = PdfMerger()
    merger.append(base_form)
    for amend_file in amend_files.split(','):
        amend_file = amend_file.strip()
        if amend_file:
            merger.append(amend_file)

    with open(output_file, 'wb') as f_out:
        merger.write(f_out)

    merger.close()
    print(f"form & additional pages merged into 1 pdf at: {output_file}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="append additional pdfs to a base pdf form")
    parser.add_argument('-f', '--form', required=True, help="base form pdf path/filename")
    parser.add_argument('-a', '--amend', required=True, help="path of pdf to append to base form")
    parser.add_argument('-o', '--output', required=True, help="output path/filename to place the resulting pdf")
    args = parser.parse_args()
    
    append_pdfs(args.form, args.amend, args.output)
