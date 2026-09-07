from sh4q.dependencies import Dependency, format_missing, missing_dependencies


missing = [Dependency("waybackurls", "waybackurls", "install command")]
message = format_missing(missing)
assert "waybackurls" in message
assert "sh4q doctor" in message
assert "install command" in message

selected = missing_dependencies(subfinder=False, amass=False, httpx=False, url_history=False, katana=False)
assert selected == []
print("dependency diagnostics test passed")
