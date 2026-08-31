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


def status_line(text: str, status: str = "info") -> str:
    import sys
    marker = {"ok": "[+]", "error": "[-]", "info": "[~]"}.get(status, "[~]")
    if not sys.stdout.isatty():
        return f"{marker} {text}"
    color = {"ok": "\033[32m", "error": "\033[31m", "info": "\033[36m"}.get(status, "\033[36m")
    return f"{color}{marker}\033[0m {text}"
