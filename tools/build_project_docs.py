from pathlib import Path
from zipfile import ZipFile, ZIP_DEFLATED
from xml.sax.saxutils import escape
from xml.etree import ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
W = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
NS = {"w": W}


def paragraphs_from_markdown(path: Path):
    result = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("### "):
            result.append(("Heading3", line[4:]))
        elif line.startswith("## "):
            result.append(("Heading2", line[3:]))
        elif line.startswith("# "):
            result.append(("Heading1", line[2:]))
        elif line.startswith("- "):
            result.append(("ListBullet", line[2:]))
        elif line[:2].isdigit() and line[2:4] == ". ":
            result.append(("ListNumber", line[4:]))
        else:
            result.append(("Normal", line))
    return result


def paragraph(style, text):
    p = ET.Element(f"{{{W}}}p")
    ppr = ET.SubElement(p, f"{{{W}}}pPr")
    ET.SubElement(ppr, f"{{{W}}}pStyle", {f"{{{W}}}val": style})
    r = ET.SubElement(p, f"{{{W}}}r")
    t = ET.SubElement(r, f"{{{W}}}t")
    t.text = text
    return ET.tostring(p, encoding="unicode")


def document_xml(items):
    body = "".join(paragraph(style, text) for style, text in items)
    return f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="{W}"><w:body>{body}<w:sectPr><w:pgSz w:w="12240" w:h="15840"/><w:pgMar w:top="1440" w:right="1440" w:bottom="1440" w:left="1440"/></w:sectPr></w:body></w:document>'''


def styles_xml():
    return f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:styles xmlns:w="{W}">
<w:style w:type="paragraph" w:default="1" w:styleId="Normal"><w:name w:val="Normal"/><w:rPr><w:rFonts w:ascii="Arial" w:hAnsi="Arial"/><w:sz w:val="22"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Heading1"><w:name w:val="heading 1"/><w:basedOn w:val="Normal"/><w:next w:val="Normal"/><w:rPr><w:b/><w:sz w:val="30"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Heading2"><w:name w:val="heading 2"/><w:basedOn w:val="Normal"/><w:next w:val="Normal"/><w:rPr><w:b/><w:sz w:val="26"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Heading3"><w:name w:val="heading 3"/><w:basedOn w:val="Normal"/><w:next w:val="Normal"/><w:rPr><w:b/><w:sz w:val="24"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="ListBullet"><w:name w:val="List Bullet"/><w:basedOn w:val="Normal"/></w:style>
<w:style w:type="paragraph" w:styleId="ListNumber"><w:name w:val="List Number"/><w:basedOn w:val="Normal"/></w:style>
</w:styles>'''


def write_docx(path: Path, items):
    content_types = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/><Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/></Types>'''
    rels = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>'''
    doc_rels = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/></Relationships>'''
    with ZipFile(path, "w", ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", content_types)
        archive.writestr("_rels/.rels", rels)
        archive.writestr("word/document.xml", document_xml(items))
        archive.writestr("word/styles.xml", styles_xml())
        archive.writestr("word/_rels/document.xml.rels", doc_rels)


def append_internal_note(path: Path):
    temp = path.with_suffix(".tmp.docx")
    with ZipFile(path) as source:
        files = {name: source.read(name) for name in source.namelist()}
    root = ET.fromstring(files["word/document.xml"])
    body = root.find(f"{{{W}}}body")
    existing_text = "".join(node.text or "" for node in root.iter(f"{{{W}}}t"))
    if "Updated 2026-08-26: the current Gate 1 safety work" in existing_text:
        return
    note = ET.fromstring(paragraph("Heading2", "Document Maintenance Note"))
    body.insert(len(body) - 1, note)
    text = ET.fromstring(paragraph("Normal", "Updated 2026-08-26: the current Gate 1 safety work, CT reporting changes, HTTP diagnostics, resolved-IP policy correction, and academic-project split are documented in architecture.md and the separate academic draft. This file remains the historical internal engineering record."))
    body.insert(len(body) - 1, text)
    files["word/document.xml"] = ET.tostring(root, encoding="utf-8", xml_declaration=True)
    with ZipFile(temp, "w", ZIP_DEFLATED) as target:
        for name, data in files.items():
            target.writestr(name, data)
    temp.replace(path)


if __name__ == "__main__":
    items = paragraphs_from_markdown(ROOT / "docs/academic_project_outline.md")
    write_docx(ROOT / "Sh4q_Academic_Project_Draft.docx", items)
    append_internal_note(ROOT / "Sh4q_Architecture_Progress_Review.docx")
