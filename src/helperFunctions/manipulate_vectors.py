from math import fabs


def get_distance_3d_vectors(vectorlist, representation_vector):
    ''''
    returns the distance between two 3D vectors
    '''
    distance = (fabs(float(vectorlist[0]) - representation_vector[0]) +
                fabs(float(vectorlist[1]) - representation_vector[1]) +
                fabs(float(vectorlist[2]) - representation_vector[2]))
    return distance


def probability_from_distance(value):
    '''
    returns the probability for a distance, calculation equals 100% minus the distance from the representation vektor times 100 devided by 3 (to account for the 3
    classification directions)
    '''
    new_value = 100 - (float(value) * 100 / 3.0)
    return '{0:.4f}'.format(new_value)
