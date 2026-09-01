from sh4q.fingerprints.normalize import normalize_external_technology


assert normalize_external_technology("WordPress:7.1") == ("wordpress", "7.1", "cms")
assert normalize_external_technology("Elementor:3.33.2") == ("elementor", "3.33.2", "page-builder")
assert normalize_external_technology("HTTP/2") == ("http/2", "", "protocol")
assert normalize_external_technology("parallax.js") == ("parallax.js", "", "")
print("fingerprint normalization test passed")
