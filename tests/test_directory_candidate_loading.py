import tempfile
import shutil
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



# Wordlists conventionally carry comments. Treating one as a candidate
# produced a "fragments are not allowed" rejection naming the '#' rather than
# the real reason, and wasted a rejection slot per comment line. Found while
# running a real wordlist against an authorised target.
_comments = Path(tempfile.mkdtemp(prefix="sh4q_directory_comments_"))
(_comments / "w.txt").write_text(
    "# api surface\n"
    "   # indented comment\n"
    "admin\n"
    "\n"
    "login\n"
    "real#fragment\n",
    encoding="utf-8",
)
_loaded = load_candidates(_comments / "w.txt")
assert _loaded.accepted == ("/admin", "/login"), _loaded.accepted
assert [reason for _, _, reason in _loaded.rejected] == ["fragments are not allowed"], (
    f"only the genuine fragment should be rejected, got {_loaded.rejected}"
)
assert _loaded.rejected[0][1] == "real#fragment", _loaded.rejected[0]
shutil.rmtree(_comments, ignore_errors=True)

print("directory candidate loading tests passed")
