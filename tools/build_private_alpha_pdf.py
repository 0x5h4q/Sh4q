from pathlib import Path

from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import Paragraph, Preformatted, SimpleDocTemplate, Spacer

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "docs/private_alpha_guide.md"
OUTPUT = ROOT / "Sh4q_Private_Alpha_Guide.pdf"


def main():
    styles = getSampleStyleSheet()
    story = []
    in_code = False
    code_lines = []
    for raw in SOURCE.read_text(encoding="utf-8").splitlines():
        line = raw.rstrip()
        if line == "```":
            if in_code:
                story.append(Preformatted("\n".join(code_lines), styles["Code"]))
                story.append(Spacer(1, 0.08 * inch))
                code_lines = []
            in_code = not in_code
            continue
        if in_code:
            code_lines.append(line)
        elif line.startswith("# "):
            story.append(Paragraph(line[2:], styles["Title"]))
        elif line.startswith("## "):
            story.append(Paragraph(line[3:], styles["Heading2"]))
        elif line:
            story.append(Paragraph(line.replace("`", ""), styles["BodyText"]))
            story.append(Spacer(1, 0.06 * inch))
    SimpleDocTemplate(str(OUTPUT), pagesize=LETTER, rightMargin=0.65 * inch, leftMargin=0.65 * inch).build(story)
    print(f"Wrote {OUTPUT}")


if __name__ == "__main__":
    main()
