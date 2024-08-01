import pytest
from prompt_toolkit.document import Document
from prompt_toolkit.validation import ValidationError

from fact.web_interface.security.terminal_validators import ActionValidator, ActionValidatorReverse

TEST_LIST = ['foo', 'bar']


def test_validator():
    validator = ActionValidator(TEST_LIST)
    validator.validate(Document(TEST_LIST[0]))
    with pytest.raises(ValidationError):
        validator.validate(Document('some other string'))
    with pytest.raises(ValidationError):
        validator.validate(Document(''))


def test_reverse_validator():
    validator = ActionValidatorReverse(TEST_LIST)
    validator.validate(Document('some other string'))
    with pytest.raises(ValidationError):
        validator.validate(Document(TEST_LIST[0]))
    with pytest.raises(ValidationError):
        validator.validate(Document(''))
