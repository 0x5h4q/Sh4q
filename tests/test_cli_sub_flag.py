from sh4q.cli.main import build_parser


parser = build_parser()
args = parser.parse_args(["scan", "example.com", "--sub"])
assert args.command == "scan"
assert args.target == "example.com"
assert args.sub is True

default_args = parser.parse_args(["scan", "example.com"])
assert default_args.sub is False
print("CLI --sub flag test passed")
