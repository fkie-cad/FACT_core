def schedule_dependencys(schedule_list, dependency_list, myself):
    for item in dependency_list:
        if item not in schedule_list:
            schedule_list.append(item)
    return [myself] + schedule_list


def get_unmatched_dependencys(proccesed_list, dependency_list):
    tmp = []
    for item in dependency_list:
        if item not in proccesed_list:
            tmp.append(item)
    return tmp
