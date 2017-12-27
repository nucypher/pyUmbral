from functools import reduce
from operator import mul


def lambda_coeff(id_i, selected_ids):
    filtered_list = [x for x in selected_ids if x != id_i]

    map_list = []
    for id_j in filtered_list:
        id_inverse = ~(id_j - id_i)
        map_list.append(id_j * id_inverse)

    return reduce(mul, map_list)


def poly_evail(coeff, x):
    result = coeff[-1]
    for i in range(-2, -len(coeff) - 1, -1):
        result = ((result * x) + coeff[i])

    return result
