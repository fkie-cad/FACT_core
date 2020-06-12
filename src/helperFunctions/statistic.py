from contextlib import suppress


def calculate_total_files(list_of_stat_tuples):
    total_amount_of_files = 0
    for item in list_of_stat_tuples:
        with suppress(IndexError):
            total_amount_of_files += item[0][1]
    return total_amount_of_files
