from re import finditer, match


def analyse_attribute(attribute: str) -> str:
    # a counter is incremented every time an escape character is added because it alters the string length
    counter = 0
    for characters in finditer(r'[^.]((?<!\\)[*?])[^.]|((?<!\\)[^a-zA-Z0-9\s?*_\\])', attribute):
        if -1 == characters.span(1)[0]:
            start = characters.span(2)[0] + counter
        else:
            start = characters.span(1)[0] + counter
        if start:
            attribute = attribute[:start] + '\\' + attribute[start:]
            counter += 1

    return attribute


def unbinding(attributes: list) -> list:
    for idx, attr in enumerate(attributes):
        if attr == '*':
            attributes[idx] = 'ANY'
        elif attr == '-':
            attributes[idx] = 'NA'
        # if there are no non-alphanumeric characters apart from underscore and escaped colon, continue
        elif not match(r'^.*[^a-zA-Z0-9_\\:].*$', attr):
            continue
        else:
            attributes[idx] = analyse_attribute(attr)

    return attributes
