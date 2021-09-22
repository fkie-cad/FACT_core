from pathlib import Path

from prompt_toolkit.validation import ValidationError, Validator
from typing import Optional

from prompt_toolkit import PromptSession
from prompt_toolkit import print_formatted_text as print_

SESSION = PromptSession()


class YesNoValidator(Validator):
    def validate(self, document):
        if document.text and document.text not in ['y', 'n']:
            raise ValidationError(message=f'Your input has to either be *y* or *n*. Got {document.text}')


class NumberValidator(Validator):
    def validate(self, document):
        if document.text and not document.text.isdigit():
            raise ValidationError(message=f'Your input has to be a number. Got {document.text}')


class RangeValidator(NumberValidator):
    def __init__(self, input_range):
        super().__init__()
        self.input_range = input_range

    def validate(self, document):
        super().validate(document)
        if document.text and int(document.text) not in self.input_range:
            raise ValidationError(message=f'Your input is out of range {self.input_range}. Got {document.text}.')


class DirectoryValidator(Validator):
    def validate(self, document):
        if document.text:
            path = Path(document.text)
            if not path.exists():
                raise ValidationError(message='Path does not exist.')
            if not path.is_dir():
                raise ValidationError(message='Path must be a directory.')
        else:
            raise ValidationError(message='Please enter a directory path.')


class FileValidator(Validator):
    def validate(self, document):
        if document.text:
            path = Path(document.text)
            if not path.exists():
                raise ValidationError(message='Path does not exist.')
            if not path.is_file():
                raise ValidationError(message='File does not exist.')
            else:
                raise ValidationError(message='Please enter a file path.')


class ActionValidator(Validator):
    def __init__(self, actions: list):
        self.actions = actions

    def validate(self, document):
        if document.text not in self.actions:
            raise ValidationError(message='This is not a valid action.')



def make_decision(question: str, default: Optional[bool] = None) -> bool:
    default_string = f'(default {"y" if default else "n"})' if default is not None else ''

    while True:
        answer = SESSION.prompt(f'{question} [y/n] {default_string}: ', validator=YesNoValidator())
        if answer == 'y':
            return True
        if answer == 'n':
            return False
        if not answer and default is not None:
            return default
        print_(f'Please state your decision as y or n (not {answer}')
