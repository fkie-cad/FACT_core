
class BadRuleError(ValueError):
    pass


class SoftwareRule:
    def __init__(self, score, description, reliability, software, versions=None):
        try:
            self.reliability = int(reliability)
            assert self.reliability in range(0, 101), 'reliability must be between 0 and 100'
            self.reliability = str(reliability)

            self.score = score
            assert self.score in ['low', 'medium', 'high'], ''

            self.description = description
            assert isinstance(self.description, str), 'description must be a string'

        except (AssertionError, ValueError, TypeError) as exception:
            raise BadRuleError(str(exception))

        self.software = software
        self._versions = versions if versions else []

    def is_vulnerable(self, version):
        if not self._versions:
            return True

        if version in self._versions:
            return True
        return False

    def get_dict(self):
        return dict(description=self.description, score=self.score, reliability=self.reliability)


def rules():
    heartbleed = SoftwareRule(score='high', description='The SSL Hearbleed bug allowing buffer overread', reliability='90', software='OpenSSL', versions=['1.0.1{}'.format(minor) for minor in 'abcde'])
    return [heartbleed, ]
