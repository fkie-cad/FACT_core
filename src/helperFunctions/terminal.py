from prompt_toolkit import PromptSession
from prompt_toolkit.validation import ValidationError, Validator

SESSION = PromptSession()


class ActionValidator(Validator):
    def __init__(self, actions: list, message='This is not a valid action.'):
        self.actions = actions
        self.message = message

    def validate(self, document):
        if document.text not in self.actions:
            raise ValidationError(message=self.message)


class ActionValidatorReverse(Validator):
    def __init__(self, actions: list, message='This is not a valid action.'):
        self.actions = actions
        self.message = message

    def validate(self, document):
        if document.text in self.actions:
            raise ValidationError(message=self.message)
