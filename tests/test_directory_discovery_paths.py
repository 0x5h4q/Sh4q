from sh4q.plugins.directory_discovery import normalize_candidate


assert normalize_candidate("admin").value == "/admin"
assert normalize_candidate("/admin//./panel/").value == "/admin/panel"
assert normalize_candidate("/").value == "/"
assert normalize_candidate("../admin").rejected
assert normalize_candidate("/admin/../../secret").rejected
assert normalize_candidate("https://evil.test/admin").rejected
assert normalize_candidate("//evil.test/admin").rejected
assert normalize_candidate("/admin?debug=1").rejected
assert normalize_candidate("/admin#fragment").rejected
assert normalize_candidate("/admin\n").rejected
assert normalize_candidate("/" + "a" * 512).rejected

normalized = normalize_candidate(" /admin//login/ ")
assert normalized.value == "/admin/login"
assert not normalized.rejected
print("directory discovery path tests passed")
