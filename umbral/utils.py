def lambda_coeff(id_i, selected_ids):
    ids = [x for x in selected_ids if x != id_i]

    if not ids:
        return None

    div_0 = ~(ids[0] - id_i)
    result = ids[0] * div_0
    for id_j in ids[1:]:
        div_j = ~(id_j - id_i)
        result = result * (id_j * div_j)

    return result

def poly_eval(coeff, x):
    result = coeff[-1]
    for i in range(-2, -len(coeff) - 1, -1):
        result = ((result * x) + coeff[i])

    return result
