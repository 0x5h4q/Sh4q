from sh4q.application.scan_runner import javascript_http_observations


class Evidence:
    def __init__(self, target: str, content: dict):
        self.target = target
        self.content = content


evidence = [
    Evidence(
        "example.com",
        {"final_url": "https://example.com/", "html_sample": "<script src='/app.js'>"},
    ),
    Evidence(
        "admin.example.com",
        {"final_url": "https://admin.example.com/", "html_sample": "<script src='/admin.js'>"},
    ),
    Evidence("api.example.com", {"final_url": "https://api.example.com/"}),
]

observations = javascript_http_observations(evidence)
assert [item["endpoint"] for item in observations] == [
    "https://example.com/",
    "https://admin.example.com/",
]
print("javascript observation source test passed")
