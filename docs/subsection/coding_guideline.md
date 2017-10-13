# Coding Guidelines

* Do not use features above **Python 3.5**
* [PEP8](https://www.python.org/dev/peps/pep-0008/) code style shall be used.
  * Exception: Lines may be as long as needed (--ignore=E501)
* We use pytest for testing. Please use the following pytest config:

```python
[pytest]
addopts = --pep8 -v --cov=./
pep8ignore =
    *.py E501
```
* Test coverage should be as high as possible (at least 95%).
* Do not mix quotation: Use **'**single quotes**'** at all time.
* ```(__main__)``` programs must have a return value: use **sys.exit()**
* ```(__main__)``` programs shall provide *--version* (-v) and *--help* (-h) command line options: use **argparse**
* Dates should be formated according to ISO 8601: **YYYY-MM-DD**
