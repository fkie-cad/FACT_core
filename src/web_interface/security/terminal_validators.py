from prompt_toolkit.validation import ValidationError, Validator


class ActionValidator(Validator):
    def __init__(self, accepted_list: list, message='This is not a valid action.'):
        """a Validator class, that looks, if a word is available in the provided list"""
        self.accepted_list = accepted_list
        self.message = message

    def validate(self, document):
        if document.text not in self.accepted_list:
            raise ValidationError(message=self.message)


class ActionValidatorReverse(Validator):
    def __init__(self, denied_list: list, message='This is not a valid action.'):
        """a Validator class, that looks, if a word is absent in the provided list or empty"""
        self.denied_list = [*denied_list, '']
        self.message = message

    def validate(self, document):
        if document.text in self.denied_list:
            raise ValidationError(message=self.message)
