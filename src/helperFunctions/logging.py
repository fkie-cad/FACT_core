import logging


class TerminalColors:
    '''
    This class contains colors and formatting used for formatting the terminal output. A the terminal output after a
    string from this class will be colored in the respective color. ``ENDC`` must be used to stop formatting the output.
    '''
    PURPLE = HEADER = '\033[95m'
    BLUE = OKBLUE = '\033[94m'
    GREEN = OKGREEN = '\033[92m'
    YELLOW = WARNING = '\033[93m'
    RED = FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def color_string(string: str, color: str) -> str:
    '''
    Format a string in a color from ``TerminalColors`` for terminal output.

    :param string: The string that will be colored.
    :param color: A color from ``TerminalColors`` or any other terminal compatible formatting string.
    :return: The formatted string.
    '''
    return f'{color}{string}{TerminalColors.ENDC}'


class ColoringFormatter(logging.Formatter):
    '''
    A subclass of ``Formatter`` that automatically prints the log level in the respective color.
    '''

    #: A List of Tuples with log levels and colors/formatting.
    LOG_LEVEL_COLORS = [
        ('DEBUG', TerminalColors.PURPLE),
        ('INFO', TerminalColors.BLUE),
        ('WARNING', TerminalColors.YELLOW),
        ('ERROR', TerminalColors.RED),
        ('CRITICAL', TerminalColors.RED + TerminalColors.BOLD),
    ]

    def format(self, record: logging.LogRecord) -> str:
        '''
        Format the specified record as text. The log level is colored in the respective color from ``TerminalColors``
        as defined in ``LOG_LEVEL_COLORS``.
        '''
        formatted_text = super().format(record)
        for log_level, color in self.LOG_LEVEL_COLORS:
            log_level_prefix = f'[{log_level}]'
            if log_level_prefix in formatted_text:
                formatted_prefix = f'[{color}{log_level}{TerminalColors.ENDC}]'
                formatted_text = formatted_text.replace(log_level_prefix, formatted_prefix)
        return formatted_text
