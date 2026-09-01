from sh4q.cli.main import build_parser


parser = build_parser()
args = parser.parse_args(["scan", "example.com", "--sub"])
assert args.command == "scan"
assert args.target == "example.com"
assert args.sub is True
assert args.amass is False

amass_args = parser.parse_args(["scan", "example.com", "--amass"])
assert amass_args.amass is True
assert amass_args.sub is False

default_args = parser.parse_args(["scan", "example.com"])
assert default_args.sub is False
assert default_args.amass is False
print("CLI --sub flag test passed")
