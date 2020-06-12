import logging


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


class ColoringFormatter(logging.Formatter):
    LOG_LEVEL_COLORS = [
        ('DEBUG', TerminalColors.PURPLE),
        ('INFO', TerminalColors.BLUE),
        ('WARNING', TerminalColors.YELLOW),
        ('ERROR', TerminalColors.RED),
        ('CRITICAL', TerminalColors.RED + TerminalColors.BOLD),
    ]

    def format(self, record: logging.LogRecord) -> str:
        formatted_text = super().format(record)
        for log_level, color in self.LOG_LEVEL_COLORS:
            log_level_prefix = '[{}]'.format(log_level)
            if log_level_prefix in formatted_text:
                formatted_prefix = '[{}{}{}]'.format(color, log_level, TerminalColors.ENDC)
                formatted_text = formatted_text.replace(log_level_prefix, formatted_prefix)
        return formatted_text
