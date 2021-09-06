from pathlib import Path

from prompt_toolkit.validation import ValidationError, Validator


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
