import os


class CarvedArea:
    def __init__(self, size):
        self.non_carved_areas = [(0, size)]

    def carved(self, carved_area):
        areas = self.non_carved_areas
        self.non_carved_areas = []
        for area in areas:
            if carved_area[0] > area[1] or area[0] > carved_area[1]:
                self.non_carved_areas.append((area[0], area[1]))
            elif area[0] >= carved_area[0] and area[1] <= carved_area[1]:
                pass
            elif area[0] < carved_area[0] and area[1] <= carved_area[1]:
                self.non_carved_areas.append((area[0], carved_area[0] - 1))
            elif area[0] >= carved_area[0] and area[1] > carved_area[1]:
                self.non_carved_areas.append((carved_area[1] + 1, area[1]))
            elif area[0] < carved_area[0] and area[1] > carved_area[1]:
                self.non_carved_areas.append((area[0], carved_area[0] - 1))
                self.non_carved_areas.append((carved_area[1] + 1, area[1]))
            else:
                raise Exception('Carving error')

    def __str__(self):
        ret_val = ''
        for area in self.non_carved_areas:
            ret_val += '({}:{}) '.format(area[0], area[1])

        return ret_val


class Carver:
    def __init__(self, filepath):
        self.filepath = filepath
        self.file_size = os.stat(self.filepath).st_size
        self.carved = CarvedArea(self.file_size)

    def extract_data(self, start, end=-1):
        with open(self.filepath, 'rb') as opened_file:
            opened_file.seek(start)

            if end >= 0:
                self.carved.carved((start, end))
                return opened_file.read(end - start)
            else:
                self.carved.carved((start, self.file_size))
                return opened_file.read()
