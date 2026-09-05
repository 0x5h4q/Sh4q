from sh4q.cli.main import build_parser


parser = build_parser()
args = parser.parse_args(["scan", "example.com", "--sub"])
assert args.command == "scan"
assert args.target == "example.com"
assert args.sub is True
assert args.amass is False

amass_args = parser.parse_args(["scan", "example.com", "--amass"])
assert amass_args.amass is True
history_args = parser.parse_args(["scan", "example.com", "--url-history"])
assert history_args.url_history is True
javascript_args = parser.parse_args(["scan", "example.com", "--js"])
assert javascript_args.js is True
bundle_args = parser.parse_args(["scan", "example.com", "--js-bundles"])
assert bundle_args.js_bundles is True
javascript_results = parser.parse_args(["results", "--type", "javascript", "--latest"])
assert javascript_results.type == "javascript"
javascript_filter = parser.parse_args(["results", "--type", "javascript", "--js-kind", "script_url", "--source-endpoint", "example.com"])
assert javascript_filter.js_kind == "script_url"
assert javascript_filter.source_endpoint == "example.com"
assert amass_args.sub is False

default_args = parser.parse_args(["scan", "example.com"])
assert default_args.sub is False
assert default_args.amass is False
assert default_args.js is False
print("CLI --sub flag test passed")
