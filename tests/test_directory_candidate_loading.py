from pathlib import Path

from sh4q.plugins.directory_discovery import DirectoryCandidateError, load_candidates


def write(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")


root = Path("/tmp/sh4q_directory_candidates")
root.mkdir(exist_ok=True)
candidate_file = root / "candidates.txt"
write(candidate_file, "admin\n/admin\n../secret\n\napi/v1\n")
result = load_candidates(candidate_file)
assert result.accepted == ("/admin", "/api/v1")
assert result.duplicates == 1
assert result.rejected[0][0] == 3

try:
    load_candidates(root / "missing.txt")
except DirectoryCandidateError as error:
    assert "not found" in str(error)
else:
    raise AssertionError("missing candidate file was accepted")

too_many = root / "too-many.txt"
write(too_many, "\n".join(f"path-{index}" for index in range(3)))
try:
    load_candidates(too_many, max_paths=2)
except DirectoryCandidateError as error:
    assert "maximum of 2" in str(error)
else:
    raise AssertionError("candidate limit was not enforced")

invalid = root / "invalid.txt"
invalid.write_bytes(b"/admin\n\xff\xfe")
try:
    load_candidates(invalid)
except DirectoryCandidateError as error:
    assert "UTF-8" in str(error)
else:
    raise AssertionError("invalid encoding was accepted")

print("directory candidate loading tests passed")
