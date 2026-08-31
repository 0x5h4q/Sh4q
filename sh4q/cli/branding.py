"""Small terminal branding used by the interactive scan command."""

SCAN_BANNER = """  ████ █   █ █  █   ███
 █ ░░░░█░  █░█░ █░ █ ░░█
  ███░░█████░█████░█░ ░█░
   ░░█ █░░░█░░░░█░░█░░█ ░░
 ████░░█░░░█░░ ░█░░░██ █ ░
  ░░░░ ░░░  ░░   ░░  ░░ ░
   ░░░░  ░   ░    ░   ░░ ░"""

def render_scan_banner(colored: bool = False) -> str:
    if not colored:
        return SCAN_BANNER
    cyan, green, reset = "\033[36m", "\033[32m", "\033[0m"
    return "\n".join(f"{cyan if i % 2 == 0 else green}{line}{reset}" for i, line in enumerate(SCAN_BANNER.splitlines()))
