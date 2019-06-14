from helperFunctions.dataConversion import make_unicode_string


def get_matched_strings_dict(matched_string_list):
    '''
    returns a dict {'MATCHED_STRING': [OFFSET_1, OFFSET_2]}
    '''
    string_dict = {}
    for match in matched_string_list:
        current_matched_string = make_unicode_string(match[2])
        current_matched_string = get_save_key_name(current_matched_string)
        if current_matched_string not in string_dict:
            string_dict[current_matched_string] = []
        string_dict[current_matched_string].append(match[0])
    return string_dict


def get_save_key_name(key_name):
    save_key = key_name.replace(".", "\uff0E")
    save_key = save_key.replace("\x00", "")
    if save_key[0] == "$":
        save_key = " {}".format(save_key)
    return save_key


def get_longest_unique_matches(string_match_list):
    longest_none_interfearing_string_matches = []
    while len(string_match_list) > 0:
        current = string_match_list.pop()
        longest_match = True
        for match in string_match_list:
            if matches_overlap(match, current) and match_is_longer(match, current):
                longest_match = False
                break
        if longest_match:
            longest_none_interfearing_string_matches.append(current)
    return longest_none_interfearing_string_matches


def matches_overlap(first, second):
    '''
    returns true if matches overlap
    returns false otherwise
    '''
    first_left, first_right = get_borders(first)
    second_left, second_right = get_borders(second)
    if first_right >= second_left >= first_left:
        return True
    if first_right >= second_right >= first_left:
        return True
    return False


def match_is_longer(first, second):
    '''
    returns true if first match is longer than second
    returns false otherwise
    '''
    return len(first[2]) >= len(second[2])


def get_borders(match):
    '''
    returns borders of match (left, right)
    '''
    begin = match[0]
    return begin, begin + len(match[2])
