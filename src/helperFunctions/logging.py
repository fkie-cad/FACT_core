class TerminalColors:
    PURPLE = HEADER = '\033[95m'
    BLUE = OKBLUE = '\033[94m'
    GREEN = OKGREEN = '\033[92m'
    YELLOW = WARNING = '\033[93m'
    RED = FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def color_string(string: str, color: str) -> str:
    return '{color}{s}{end}'.format(color=color, s=string, end=TerminalColors.ENDC)
