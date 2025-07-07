import argparse
from reportlab.lib.pagesizes import LETTER
from reportlab.pdfgen import canvas
from reportlab.lib.units import inch

def convert_txt_to_pdf(txt_file, output):
    c = canvas.Canvas(output, pagesize=LETTER)
    width, height = LETTER

    margin = 0.75 * inch
    max_width = width - 1 * margin
    max_height = height - 1 * margin

    with open(txt_file, "r", encoding="utf-8") as file:
        lines = file.readlines()

    y = height - margin
    line_height = 14  # points

    for line in lines:
        line = line.strip()
        if not line:
            y -= line_height  # blank line
            continue

        while line:
            max_chars = int(max_width / 7)  # approx 7 pts per char width
            chunk = line[:max_chars]
            if len(line) > max_chars:
                last_space = chunk.rfind(" ")
                if last_space > 0:
                    chunk = chunk[:last_space]

            c.drawString(margin, y, chunk)
            y -= line_height
            line = line[len(chunk):].lstrip()

            if y < margin:
                c.showPage()
                y = height - margin
    c.save()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='convert a txt file to pdf.')
    parser.add_argument('-t', '--txt', required=True, help='path to the input text file')
    parser.add_argument('-o', '--output', required=True, help='path to the output PDF file')

    args = parser.parse_args()
    convert_txt_to_pdf(args.txt, args.output)
  
