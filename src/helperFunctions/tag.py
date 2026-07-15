from enum import Enum


class TagColor(str, Enum):
    """
    A class containing the different colors the tags may have.
    """

    GRAY = 'secondary'
    BLUE = 'primary'
    GREEN = 'success'
    LIGHT_BLUE = 'info'
    ORANGE = 'warning'
    RED = 'danger'
    LIGHT = 'light'
    DARK = 'dark'

    def __str__(self) -> str:
        return self.value
