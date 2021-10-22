# A substitution - permutation cipher using a symmetric key.
# Contains a Vigenere cipher, Hill cipher, column transposition, \
# chain addition, ADFGVX-type array cipher and other permutation ciphers.

from numpy import array
from secrets import choice
from sympy import Matrix

README = "This is a program designed to encrypt a message of up "\
         "to 10,000 characters using a substitution - permutation\n"\
         "network using a symmetric pass code. All numbers and English" \
         "alphabet characters as well a space and the symbols @#$%^&*()-_ " \
         "can be used. All other characters will be ignored. \n" \
         "You will need to set three pass codes to encrypt the message." \
         "The program can assign a random pass code. /n All lower case" \
         "characters text and codes will be converted to upper case. \n" \
         "The decoded message may contain up to nine random characters" \
         "at the end of the message.\n Just follow the instructions in " \
         "the menu"

HELP = """
Type `encrypt` to encrypt a message.
Type `decrypt` to decrypt a message.
Type `readme` for the instructions.
Type `q` to quit.
"""

HELP_ENCRYPT = """
Type `owncode` to type in your own pass code.
Type `autocode` to generate a random code for the encryption.
Type `b` to go back.
Type `q` to quit.
"""

# Sets lists and matrices
REFERENCE_LIST = [
    "^", "T", "X", "(", "2", "S", "C", "8", "Z", "%",
    "O", "*", "I", "E", "0", "J", "@", "6", "P", "9",
    "F", "Y", "1", "!", "?", "7", "Q", "G", "$", "U",
    "L", "R", "H", "5", "M", "3", "K", "_", ")", "A",
    "V", "4", "N", "#", "-", "D", "W", "&", "B"
]
CODE_LIST = [
    "WN", "MZ", "AN", "MV", "AW", "VA", "NM", "VN",
    "ZW", "VW", "MA", "ZM", "MN", "XM", "AV", "ZA",
    "NX", "NA", "VM", "VV", "WA", "AX", "VX", "WM",
    "ZN", "AZ", "WV", "WW", "MX", "AA", "VZ", "XW",
    "MW", "NW", "WX", "XZ", "NV", "ZZ", "XA", "ZV",
    "MM", "ZX", "XN", "NN", "AM", "NZ", "XV", "WZ", "XX"
]
CODE_LETTER = ["A", "M", "N", "W", "V", "X", "Z"]
REFERENCE_LEN = len(REFERENCE_LIST)
HILL_CODE = array([
    49, 34, 31, 5, 3, 21, 17, 18,
    13, 8, 19, 44, 17, 28, 34, 28
])
HILL_MATRIX = HILL_CODE.reshape(4, 4)
HILL_MATRIX_INV = array(Matrix(HILL_MATRIX).inv_mod(REFERENCE_LEN))


def validate_code(user_defined, used_codes):
    """Validates user input codes."""
    while True:
        error = ""
        code = input(user_defined).strip().upper()
        if len(code) > 12 or len(code) < 6:
            error += "The pass code should be 6 and 12 characters.\n"
        if any([c not in REFERENCE_LIST for c in code]):
            error += "Invalid character used.\n"
        if code in used_codes:
            error += "Code is already used.\n"
        duplicate_check = code[:]
        duplicate_check = sorted(duplicate_check)
        if duplicate_check[0] == duplicate_check[-1]:
            error += "Code cannot consist of only one letter.\n"
        if not error:
            used_codes.append(code)
            return code
        print(error)


def owncode():
    """Prompts for pass codes and validates them."""
    print("\nThe pass code must be between 6 and 12 characters:")
    codes = []
    usedCodes = []
    for i in range(3):
        temp = f"Please type in your pass code {i + 1}: "
        codes.append(validate_code(temp, usedCodes))
        usedCodes.append(codes[-1])
    return codes


def autocode():
    """Generates three private keys, displays and returns them."""
    codes = []
    usedCodes = []
    for _ in range(3):
        codes.append("".join([choice(REFERENCE_LIST) for __ in range(12)]))
        usedCodes.append(codes[-1])
    print("\nYour three code words are:")
    for i, code in enumerate(codes):
        print(f"Pass code {i + 1}: {code}")
    return codes


def setplaintext():
    """Prompts for plaintext and validates it."""
    while True:
        plaintext = input("\nType in message to encrypt (Characters up to "
                          "10,000 with spaces are allowed): ")
        error = ""
        if len(plaintext) > 10000:
            error += "Your message is too long."
        if "?" in plaintext:
            error += "'?' cannot be used"
        if not error:
            return plaintext
        print(error)


def validdate_message(message):
    """
    Checks that the encrypted message is a multiple of 24
    (excluding the added spaces) and only contains valid letters
    """
    added_spaces = len(message) // 6
    if (len(message) - added_spaces) % 24 != 0:
        return False
    for c in message:
        if c not in CODE_LETTER and c != ' ':
            return False
    return True

def _substitute(text, spaces=True):
    """Substitutes spaces and removes invalid characters."""
    ciphertext = ""
    for c in text:
        if c in REFERENCE_LIST:
            cipher_letter = c
        elif c == " " and spaces:
            cipher_letter = "?"
        else:
            cipher_letter = ""
        ciphertext += cipher_letter
    return ciphertext


def _add_random(ciphertext):
    """
    Add random letters to the end of the plaintext until the message
    length is a multiple of 10
    """
    if len(ciphertext) % 10 != 0:
        ciphertext += "?"
    while len(ciphertext) % 10 != 0:
        ciphertext += choice(REFERENCE_LIST)
    return ciphertext


def _add_two_random(ciphertext):
    """Adds two random letters for every 10 characters"""
    temp_word = ""
    for j in range(len(ciphertext) // 10):
        temp_word += ("^" +
                      ciphertext[j * 10: j * 10 + 10] +
                      "^")
    ciphertext = temp_word
    return ciphertext


def _remove_two_random(ciphertext):
    """Removes the two random characts for every twelve characters."""
    temp_word = ""
    for j in range(len(ciphertext) // 12):
        temp_word += ciphertext[j * 12 + 1: j * 12 + 11]
    ciphertext = temp_word
    return ciphertext


def setencryptedtext():
    """Prompts for encrypted text."""
    encrypted = ""
    while not encrypted:
        encrypted = input("\nType in the encrypted message: ")
        if validdate_message(encrypted) is False:
            encrypted = ""
            print("Invalid code, try again")
    return encrypted


def _rearrangement(code1, code2, code3):
    """Rearrangement of code words to form code and code orders."""
    # Ensures that the list lengths will be variable
    # The length of the lists are variable so that it's more difficult \
    # to crack the encrypted message
    c1_len = len(code1) - 6
    c2_len = len(code2) - 6
    c3_len = len(code3) - 6
    extra_len = [2 * c1_len + c2_len + c3_len, 2 * c2_len + c3_len, \
                 2 * c3_len + c1_len + c2_len, 2 * c3_len + c2_len, \
                 2 * c2_len + c3_len + c1_len, 2 * c1_len + c2_len, \
                 3 * c1_len + c2_len, 3 * c3_len + c2_len, \
                 3 * c2_len + c1_len, 3 * c3_len + c1_len, \
                 3 * c1_len + c2_len, 3 * c2_len + c3_len]
    combined = code3 + code1  + code2
    combined = _shift(combined)
    combined = combined[0]
    total_a = sum(combined)
    code = ""

    # Combines the code word into one variable
    # Since code words could be between 6 to 12 characters, 6 letters \
    # are taken from the start of the word and 6 characters are taken from \
    #the end of the word
    # This also makes the length of the combined word the same regardless \
    # of whether the code word was 6 or 12 characters or in between
    for i in range(6):
        temp = code1[i] + code2[-i] + code3[i] + code1[-i] + \
            code2[i] + code3[-i]
        code += temp
    # Duplicates the combined code word so that there is sufficent length
    code = code * 16
    # Converts the code to a number list as per the order of the reference list
    code = _shift(code)
    code = code[0]
    total_b = sum(code)

    # Generates a seemingly  random set of numbers based on the pass codes
    code = _generate_code_list(code, total_a, True)

    # Generates an orthogonal list so that the numbers are created by at \
    # least two separate functions
    extra_list = code3 + code2 + code3 + code1 + code2
    extra_list = _shift(extra_list)
    extra_list = extra_list[0]
    extra_list = [((element + 1) * 103 % \
             REFERENCE_LEN) for element in extra_list]
    extra_list = _generate_code_list(extra_list, total_b)

    # Generates a second orthogonal list.
    # This list ensures that on the exceedingly rare chance that the \
    # numbers in the list are all zeroes, that at least one list will \
    #have non-zeros
    code_reference = []
    code_list = []
    code_list = code[2 * 45 : 2 * 45 + 19 + extra_len[2]]
    temp = []
    for i in range(len(code_list)):
        temp.append(((code[i] + i + 1) * 97) % REFERENCE_LEN)
    code_list = temp
    for i in range(12):
       temp =  code[i * 45 : i * 45 + 19 + extra_len[i]]
       code_reference.append(temp)

    # Inserts the orthogonal lists
    code_reference.insert(4, code_list)
    code_reference.insert(5, extra_list)

    # Finds the order of the numbers in the lists.
    # This is required for many of the permutations
    code_order5 = []
    for i in range(15):
       temp =  _order(code[37 * i : 37 * i + 5])
       code_order5.append(temp)
    code_order6 = []
    for i in range(11):
       temp =  _order((code[19 * i : 19 * i + 6]))
       code_order6.append(temp)
    code_order24 = []
    for i in range(13):
       temp =  _order(code[29 * i : 29 * i + 24])
       code_order24.append(temp)
    # The inverse order is required to reverse the permutations
    code_order5_inv = _get_inv_order(*code_order5)
    code_order6_inv = _get_inv_order(*code_order6)
    code_order24_inv = _get_inv_order(*code_order24)

    # Selects an arbitrary list or number to generate a seemingly random number
    code_a = code_reference[3][10:19]
    code_b = code_reference[7][10:20]
    extra_cycle = code_reference[10][15]

    return code_reference, code_order5, code_order6, code_order24, \
    code_a, code_b, code_order5_inv, code_order6_inv, code_order24_inv, \
    extra_cycle


def _generate_code_list (code, total, first_list=False):
    """Generates a random-like sequence of numbers to be used for the codes"""
    temp = []
    for i in range(len(code)):
        temp.append(((code[i] + i + 1) * 37 + total) % REFERENCE_LEN)
    code = temp
    # All other functions are just permutations, or substitutions by \
    # adding constants or variables
    code = code[::-1]
    temp = []
    for k in range(code[5]):
        temp = []
        for j in range(len(code) // 2):
            temp.append(code[2 * j + 1])
        for j in range(len(code) // 2):
            temp.append(code[2 * j])
        code = temp
    temp = []
    for i in range(len(code)):
        temp.append((code[i] + code[i % 13]) % REFERENCE_LEN)
    code = temp
    temp = [code[-1] % REFERENCE_LEN]
    for i in range(len(code) - 1):
        temp.append((temp[-1] + code[i]) % REFERENCE_LEN)
    code = temp
    code = [((element + code[12] + 55) * 161 % \
             REFERENCE_LEN) for element in code]
    # This ensures again that the main list is processed in a \
    # different way to the orthogonal list
    if first_list:
        temp_word = ""
        for i in range(len(code)):
            temp_word += CODE_LIST[code[i]]
        code_word = ""
        for j in range(len(temp_word) // 2):
            code_word += temp_word[2 * j + 1]
        for j in range(len(temp_word) // 2):
            code_word += temp_word[2 * j]
        temp_word = "".join(reversed(code_word))
        code = ""
        for j in range(len(temp_word) // 2):
            temp = CODE_LIST.index(temp_word[2 * j] + temp_word[2 * j + 1])
            code += REFERENCE_LIST[temp]
        code = _shift(code)
        code = code[0]
    temp = []
    for i in range(len(code)):
        temp.append(((code[i] + i + 1) * 29 + 31) % REFERENCE_LEN)
    code = temp
    code = code[::-1]
    temp = []
    for k in range(code[5]):
        temp = []
        for j in range(len(code) // 2):
            temp.append(code[2 * j + 1])
        for j in range(len(code) // 2):
            temp.append(code[2 * j])
        code = temp
    temp = [code[-1] % REFERENCE_LEN]
    for i in range(len(code) - 1):
        temp.append((temp[-1] + code[i]) % REFERENCE_LEN)
    code = temp
    code = [((element + code[12] + 55) * 87 % \
             REFERENCE_LEN) for element in code]
    temp = []
    for k in range(code[5]):
        temp = []
        for j in range(len(code) // 2):
            temp.append(code[2 * j + 1])
        for j in range(len(code) // 2):
            temp.append(code[2 * j])
        code = temp
    temp = [code[-1] % REFERENCE_LEN]
    for i in range(len(code) - 1):
        temp.append((temp[-1] + code[i]) % REFERENCE_LEN)
    code = temp
    return code


def _order(code):
    """Puts the elements into order and finds to order of the pass code."""
    order = []
    sorted_code = sorted(code)
    for i, c in enumerate(code):
        order.append(sorted_code.index(c))
        sorted_code[order[i]] = "%"
    return order


def _shift(*codes):
    """Finds the shifts needed from the substitution code word."""
    code_numbers = []
    for code in codes:
        code_number = []
        for n in range(len(code)):
            code_number.append(REFERENCE_LIST.index(code[n % len(code)]))
        code_numbers.append(code_number)
    return code_numbers


def _get_inv_order(*orders):
    """Calculates and returns inverse matrix."""
    code = orders[0]
    inv_order = []
    for order in (orders):
        order_inv = [order.index(i) for i, _ in enumerate(code)]

        inv_order.append(order_inv)
    return inv_order


def _adds_spaces(ciphertext):
    """Adds one space for every five characters in the final ciphertext."""
    temp_word = ""
    for j in range(len(ciphertext) // 5):
        temp_word += ciphertext [j * 5 : j * 5 + 5] + " "
    if len(ciphertext) % 5 != 0:
        for k in range (len(ciphertext) % 5):
            temp_word +=  ciphertext[k - len(ciphertext) % 5]
    ciphertext = temp_word
    return ciphertext


def _reinstate_space(ciphertext):
    """Converts the ? back into a space."""
    temp_word = ""
    for c in ciphertext:
        if c == "?":
            cipher_letter = " "
        else:
            cipher_letter = c
        temp_word += cipher_letter
    ciphertext = temp_word
    return ciphertext


def _get_cipher_number(ciphertext):
    """Finds the AMNVWXZ reference number of the array letters."""
    cipher_number = []
    for j in range(len(ciphertext) // 2):
        code = ciphertext[2 * j] + ciphertext[2 * j + 1]
        cipher_number.append(CODE_LIST.index(code))
    return cipher_number


def _vigenere(ciphertext, code_reference, i, cycle, decrypt=False):
    """Encrypts or decrypts using the message Vigenere / Bellaso cipher."""
    temp_word = ""
    code_number = []
    mult = 1
    if decrypt:
        # Multiplying by -1 is needed for the decryption
        mult = -1
        # The order of the list needs to be reverse for decryption
        i = cycle - 1 - i
    for n in range(len(ciphertext)):
        code_number.append(
            mult * code_reference[i % len(code_reference)][n % \
                                len(code_reference[i % len(code_reference)])])
    for j in range(len(ciphertext)):
        index = REFERENCE_LIST.index(
            ciphertext[j]) - code_number[j] % REFERENCE_LEN
        temp_word += REFERENCE_LIST[index]
    ciphertext = temp_word
    return ciphertext


def _bellaso(ciphertext, code_reference, i, cycle, decrypt=False):
    """Encrypts or decrypts using the message Vigenere / Bellaso cipher."""
    temp_word = ""
    cipher_number = _get_cipher_number(ciphertext)
    mult = 1
    if decrypt:
        # Multiplying by -1 is needed for the decryption
        mult = -1
        # The order of the list needs to be reverse for decryption
        i = cycle -1 - i
    # First number the code number is added
    # Second number, the code number is subtracted
    # The opposite occurs for decryption
    # This is to make it harder to determine the length of the code list
    for j in range(len(cipher_number) // 2):
        temp = mult * 37 * code_reference[i % len(code_reference)][\
                        2 * j % len(code_reference[i % len(code_reference)])]
        index1 = (cipher_number[2 * j] + temp) % REFERENCE_LEN
        temp = mult * 37 * code_reference[i % len(code_reference)][\
                    (2 * j + 1) % len(code_reference[i % len(code_reference)])]
        index2 = (cipher_number[2 * j + 1] - temp) % REFERENCE_LEN
        temp_word += CODE_LIST[index1] + CODE_LIST[index2]
    ciphertext = temp_word
    return ciphertext


def _2D_array(ciphertext):
    """ Converts the letters to a 2D array as per the code list."""
    # The letters are converted as per an array but rather by the index \
    # of the code list constant
    temp_word = ""
    for j in range(len(ciphertext)):
        temp = REFERENCE_LIST.index(ciphertext[j])
        temp_word += CODE_LIST[temp]
    ciphertext = temp_word
    return ciphertext


def _retrun_from_array(ciphertext):
    """ Converts the back to single letters as per the reference list."""
    temp_word = ""
    for j in range(len(ciphertext) // 2):
        temp = CODE_LIST.index(ciphertext[2 * j] + ciphertext[2 * j + 1])
        temp_word += REFERENCE_LIST[temp]
    ciphertext = temp_word
    return ciphertext


def _chain_addition(ciphertext, code_a, code_b, i, array_letter=False):
    """
    Adds the value of the current letter
    with the value of the last letter in the new word.
    """
    temp_word = ""
    cipher_number = []
    if array_letter:
        cipher_number = _get_cipher_number(ciphertext)
    else:
        for j in range(len(ciphertext)):
            code = ciphertext[j]
            cipher_number.append(REFERENCE_LIST.index(code))
    # The first number is taken from a code list
    # All other numbers taken from the message
    cipher_number2 = [(code_a[i % len(code_a)] + 1 + \
                       cipher_number[0]) % REFERENCE_LEN]
    for j in range(len(cipher_number) - 1):
        temp = cipher_number2[-1] + cipher_number[j + 1]
        cipher_number2.append(temp % REFERENCE_LEN)
    # Once the numbers have been added from start to the end of the message,
    # The numbers are added again from the end of the message to the start
    # Adding numbers form both ends means that any one character difference \
    # in the message would effect all characters
    temp = code_b[i % len(code_b)] + cipher_number2[len(cipher_number2) - 1]
    cipher_number3 = [temp % REFERENCE_LEN]
    for j in range(len(cipher_number2) - 1):
        temp = cipher_number3[0] + cipher_number2[len(cipher_number2) - 2 - j]
        cipher_number3.insert(0, temp % REFERENCE_LEN)
    if array_letter:
        for j in range(len(cipher_number3)):
            index = CODE_LIST[cipher_number3[j]]
            temp_word += index
    else:
        for j in range(len(cipher_number3)):
            index = REFERENCE_LIST[cipher_number3[j]]
            temp_word += index
    ciphertext = temp_word
    return ciphertext


def _chain_sub(ciphertext, code_a, code_b, i, cycle, array_letter= False):
    """
    Subtracts the value of the current letter
    with the value of the last letter in the new word.
    """
    codelist1 = []
    codelist2 = []
    codelist3 = []
    i = cycle - 1 - i
    if array_letter:
        codelist1 = _get_cipher_number(ciphertext)
    else:
        for j in range(len(ciphertext)):
            codelist1.append(REFERENCE_LIST.index(ciphertext[j]))
    # Subtracts The first number by the second number
    # The the resulting number by the thrid number and so forth
    for j in range(len(codelist1) - 1):
        difference = codelist1[j] - codelist1[j + 1]
        if difference >= 0:
            value = difference
        else:
            value = codelist1[j] + (REFERENCE_LEN - codelist1[j + 1])
        codelist2.append(value)
    # The last number is subtracted by the code list number
    # The remaining number is eliminated as this number was from the code list
    difference = codelist1[j + 1] - code_b[i % len(code_b)]
    if difference >= 0:
        value = difference
    else:
        value = codelist1[j + 1] + (REFERENCE_LEN - code_b[i % len(code_b)])
    codelist2.append(value)
    # The process repeats going from the other end of the message
    # Subtracts The last number by the second last number
    # The the resulting number by the thrid last number and so forth
    for j in range(len(codelist2) - 1):
        difference = codelist2[-1 - j] - codelist2[-2 - j]
        if difference >= 0:
            value = difference
        else:
            value = codelist2[-1 - j] + (REFERENCE_LEN - codelist2[-2 - j])
        codelist3.insert(0, value)
    # The first number is subtracted by the code list number
    # The remaining number is eliminated as this number was from the code list
    difference = codelist2[0] - code_a[i % len(code_a)] - 1
    if difference >= 0:
        value = difference
    else:
        value = codelist2[0] + (REFERENCE_LEN - code_a[i % len(code_a)] - 1)
    codelist3.insert(0, value)
    temp_word = ""
    if array_letter:
        for j in range(len(codelist3)):
            temp_word += CODE_LIST[codelist3[j]]
    else:
        for j in range(len(codelist3)):
            temp_word += REFERENCE_LIST[codelist3[j]]
    ciphertext = temp_word
    return ciphertext


def _get_matrix(cipher_number, hill_matrix, cycle_number):
    """Takes a fragment of the number list and multiples by the
    inverse mod Hill matrix, then adds the product into a new list."""
    code_matrix = []
    # Multiplies the matrices together mean that the value of the is a \
    # function of the number, its three adjacent numbers and its position \
    # in the 1D matrix
    for n in range(cycle_number):
        fragment = cipher_number[n * 4 : n * 4 + 4]
        fragment = (hill_matrix.dot(fragment) % REFERENCE_LEN).tolist()
        for frag in fragment:
            code_matrix.append(frag)
    return code_matrix


def _hill_function(ciphertext, decrypt=False):
    """Multiples a letter by a matrix function."""
    cipher_number = _get_cipher_number(ciphertext)
    cycle = len(cipher_number) // 4
    if decrypt:
        code_matrix = _get_matrix(cipher_number, HILL_MATRIX_INV, cycle)
    else:
        code_matrix = _get_matrix(cipher_number, HILL_MATRIX, cycle)
    temp_word = ""
    for code in code_matrix:
        temp_word = temp_word + CODE_LIST[code]
    ciphertext = temp_word
    return ciphertext


def _odds_evens(ciphertext, code_reference, i):
    """Groups the odd and even letters numerous times as per the code list."""
    # Since the letters are from a 2D array, rearranging the order will \
    # result in different code list index numbers
    for k in range(code_reference[i % (len(code_reference))] + 1):
        temp_word = ""
        for j in range(len(ciphertext) // 2):
            temp_word += ciphertext[2 * j + 1]
        for j in range(len(ciphertext) // 2):
            temp_word += ciphertext[2 * j]
        ciphertext = temp_word
    return ciphertext


def _back_odd_evens(ciphertext, code_reference, i, cycle):
    """
    Groups back the odd and even letters numerous times
    as dictated by the code list.
    """
    i = cycle - 1 - i
    for k in range(code_reference[i % (len(code_reference))] + 1):
        temp_word = ""
        for j in range(len(ciphertext) // 2):
            temp_word += ciphertext[len(ciphertext) // 2 + j] + ciphertext[j]
        ciphertext = temp_word
    return ciphertext


def _reversal(ciphertext):
    """Reverse the order of the text."""
    # Since the letters are from a 2D array, rearranging the order will \
    # result in different code list index numbers
    temp_word = "".join(reversed(ciphertext))
    ciphertext = temp_word
    return ciphertext


def _rearrange(ciphertext, order_code, i, cycle, decrypt=False):
    """Rearranges a section of letters."""
    # Since the letters are from a 2D array, rearranging the order will \
    # result in different code list index numbers
    temp_word = ""
    code_len = len(order_code[i % len(order_code)])
    if decrypt:
        i = cycle - 1 - i
    for j in range(len(ciphertext) // code_len):
        for k in range(code_len):
            temp = order_code[i % len(order_code)][k % code_len]
            temp_word += ciphertext[temp + j * code_len]
    ciphertext = temp_word
    return ciphertext


def _group_rearrange(ciphertext, order_code, i):
    """Rarranges sections of letters."""
    # Since the letters are from a 2D array, rearranging the order will \
    # result in different code list index numbers
    temp_word = ""
    section_len = len(ciphertext) // len(order_code[i % len(order_code)])
    code_len = len(order_code[i % len(order_code)])
    for k in range(code_len):
        a = section_len * order_code[i % len(order_code)][k]
        b = section_len * order_code[i % len(order_code)][k] + section_len
        temp_word += ciphertext[a:b]
    ciphertext = temp_word
    return ciphertext


def _group_back(ciphertext, inv_matrix, i, cycle):
    """Returns sections of letters back to original position."""
    temp_word = ""
    i = cycle - 1 - i
    section_len = len(ciphertext) // len(inv_matrix[i % len(inv_matrix)])
    for k in range(len(inv_matrix[i % len(inv_matrix)])):
        temp_word += ciphertext[
            section_len * inv_matrix[i % len(inv_matrix)][k]: section_len * \
                inv_matrix[i % len(inv_matrix)][k] + section_len]
    ciphertext = temp_word
    return ciphertext


def _transposition(ciphertext, code_order, i, cycle):
    """Tranposes the text."""
    # Since the letters are from a 2D array, rearranging the order will \
    # result in different code list index numbers
    temp_word = ""
    code_len = len(code_order[i % len(code_order)])
    rows = len(ciphertext) // code_len
    for k in range(code_len):
        for j in range(rows):
            temp = j * code_len + code_order[i % len(code_order)].index(k)
            temp_word += ciphertext[temp]
    ciphertext = temp_word
    return ciphertext


def _back_transposition(ciphertext, code_order, i, cycle):
    """Transposes the letters back to the original position."""
    temp_word = ""
    code_len = len(code_order[(i) % len(code_order)])
    rows = len(ciphertext) // code_len
    i = cycle - 1 - i
    for j in range(rows):
        for k in range(code_len):
            temp_word += ciphertext[j + code_order[
                i % len(code_order)][k] * rows]
    ciphertext = temp_word
    return ciphertext


def encrypt(codes, plaintext):
    """Encrypts the given plaintext with the given codes."""
    # Initialises codes
    code1, code2, code3 = codes
    code_reference, code_order5, code_order6, code_order24, \
    code_a, code_b, code_order5_inv, code_order6_inv, code_order24_inv, \
    extra_cycle = _rearrangement(code1, code2, code3)
    # The cycle number is varailbe with a numer between 12 and 60
    # The cycle number is variable so that thelst last code reference used \
    # in the cipher is not known
    cycle = 12 + extra_cycle

    # Converts to uppercase, substitutes spaces and removes invalid characters
    ciphertext = plaintext.upper()
    ciphertext = _substitute(ciphertext)

    # Adds a space character and then random characters as needed until
    # there is a multiple of 10 characters
    ciphertext = _add_random(ciphertext)

    for i in range(cycle):
        # A. Performs a Vigenere / Bellaso cipher
        ciphertext = _vigenere(ciphertext, code_reference, i, cycle)

        # B. Rearranges a group of letters
        ciphertext = _rearrange(ciphertext, code_order5, i, cycle)

        # C. Groups odd and even letters
        ciphertext = _odds_evens(ciphertext, code_a, i)

        # D. Adds adjacent letters
        ciphertext = _chain_addition(ciphertext, code_b, code_a, i)

        # E. Reversal of word
        ciphertext = _reversal(ciphertext)

        # F. Rearranges sections
        ciphertext = _group_rearrange(ciphertext, code_order5, i)

    # G. Adds 2 random characters for every 10 charactrs in the message
    ciphertext = _add_two_random(ciphertext)

    # H. Converts message into the 2D AMNVWXZ array letters
    ciphertext = _2D_array(ciphertext)

    for i in range(cycle):

        # I. Transposition with rearrangement of columns
        ciphertext = _transposition(ciphertext, code_order6, i, cycle)

        # J. Reversal of word
        ciphertext = _reversal(ciphertext)

        # K. Peferms a Hill function
        ciphertext = _hill_function(ciphertext)

        # L. Rearranges a group of letters
        ciphertext = _rearrange(ciphertext, code_order6, i, cycle)

        # M. Rearranges sections
        ciphertext = _group_rearrange(ciphertext, code_order24, i)

        # N. Adds adjacent letters
        ciphertext = _chain_addition(ciphertext, code_a, code_b, i, True)

        # O. Groups odd and even letters
        ciphertext = _odds_evens(ciphertext, code_a, i)

        # P. Rearranges a group of letters
        ciphertext = _rearrange(ciphertext, code_order24, i, cycle)

        # Q. Rearranges sections
        ciphertext = _group_rearrange(ciphertext, code_order6, i)

        # R. Performs a Vigenere / Bellaso cipher
        ciphertext = _bellaso(ciphertext, code_reference, i, cycle)

    # S. Adds one space for every five characters
    ciphertext = _adds_spaces(ciphertext)

    return ciphertext


def decrypt(codes, ciphertext):
    """Decrypts the given ciphertext with the given codes."""
    # Initialises codes
    code1, code2, code3 = codes
    code_reference, code_order5, code_order6, code_order24, \
    code_a, code_b, code_order5_inv, code_order6_inv, code_order24_inv, \
    extra_cycle = _rearrangement(code1, code2, code3)
    cycle = 12 + extra_cycle

    # S. Removes spaces from encypted message
    ciphertext = _substitute(ciphertext, spaces=False)

    for i in range(cycle):

        # R. Performs a Vigenere / Bellaso cipher
        ciphertext = _bellaso(ciphertext, code_reference, i, cycle, True)

        # Q. Rearranges sections
        ciphertext = _group_back(ciphertext, code_order6_inv, i, cycle)

        # P. Rearranges a group of letters
        ciphertext = _rearrange(ciphertext, code_order24_inv, i, cycle, True)

        # O. Groups back odd and even letters
        ciphertext = _back_odd_evens(ciphertext, code_a, i, cycle)

        # N. Subtracts adjacent letters
        ciphertext = _chain_sub(ciphertext, code_a, code_b, i, cycle, True)

        # M. Rearranges a group of letters
        ciphertext = _group_back(ciphertext, code_order24_inv, i, cycle)

        # L. Rearranges a group of letters
        ciphertext = _rearrange(ciphertext, code_order6_inv, i, cycle, True)

        # K. Performs an inverse Hill function
        ciphertext = _hill_function(ciphertext, True)

        # J. Reversal of word
        ciphertext = _reversal(ciphertext)

        # I. Transposition with rearrangement of columns
        ciphertext = _back_transposition(ciphertext, code_order6, i, cycle)

    # H. Returns message from 2D array AMNVWXZ letters
    ciphertext = _retrun_from_array(ciphertext)

    # G. Removes added random letters
    ciphertext = _remove_two_random(ciphertext)

    for i in range(cycle):

        # F. Rearranges a group of letters
        ciphertext = _group_back(ciphertext, code_order5_inv, i, cycle)

        # E. Reversal of word
        ciphertext = _reversal(ciphertext)

        # D. Subtracts adjacent letters
        ciphertext = _chain_sub(ciphertext, code_b, code_a, i, cycle)

        # C. Groups back odd and even letters
        ciphertext = _back_odd_evens(ciphertext, code_a, i, cycle)

        # B. Rearranges a group of letters
        ciphertext = _rearrange(ciphertext, code_order5_inv, i, cycle, True)

        # A. Performs a Vigenere / Bellaso cipher
        ciphertext = _vigenere(ciphertext, code_reference, i, cycle, True)

    # Converts space character for a space again
    ciphertext = _reinstate_space(ciphertext)
    plaintext = ciphertext

    return plaintext


def test():
    """Automatically checks whether the program is working correctly"""
    # Use autocode or input your own code
    codes = autocode()
    #codes = ["^^^^^^^^^^^T", "^^^^^^^^^^T^", "^^^^^^^^^T^^"]
    # Only use valid uppercase characters for this test
    plaintext = 'HELLO WORLD!'
    ciphertext = encrypt(codes, plaintext)
    decrypted_plaintext = decrypt(codes, ciphertext)
    print(decrypted_plaintext)
    decrypted_plaintext = decrypted_plaintext[:len(plaintext)]
    if plaintext == decrypted_plaintext:
        print("Correct encryption")
    else:
        print("Wrong encryption")


def main():
    """The starting point of the program."""
    # Unblock the test() function, to quickly check the program
    #test()
    #return

    # Runs the main menu
    while True:
        print(HELP)
        user_input = input().strip().lower()
        if user_input == "encrypt":
            while True:
                print(HELP_ENCRYPT)
                user_input_second = input().lower()
                if user_input_second == "autocode":
                    encrypted = encrypt(autocode(), setplaintext())
                    print(f"\nYour encrypted message is:\n{encrypted}")
                    break
                elif user_input_second == "owncode":
                    encrypted = encrypt(owncode(), setplaintext())
                    print(f"\nYour encrypted message is:\n{encrypted}")
                    break
                elif user_input_second == "b":
                    break
                elif user_input_second == "q":
                    return
                else:
                    print("\nInvalid syntax.")
        elif user_input == "decrypt":
            decrypted = decrypt(owncode(), setencryptedtext())
            print(f"Your decrypted message is:\n{decrypted}")
        elif user_input == "readme":
            print(README)
        elif user_input == "q":
            break
        else:
            print("\nInvalid syntax.")


if __name__ == "__main__":
    main()