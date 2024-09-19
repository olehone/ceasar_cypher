import matplotlib.pyplot as plt
import pandas as pd


def caesar_shift(char, shift):
    ukr_alphabet = list("абвгґдеєжзиіїйклмнопрстуфхцчшщьюя")
    char = char.lower()
    if "a" <= char <= "z":
        base = ord("a")
        return chr((ord(char) - base + shift) % 26 + base)

    elif char in ukr_alphabet:
        idx = ukr_alphabet.index(char)
        new_idx = (idx + shift) % len(ukr_alphabet)
        return ukr_alphabet[new_idx]

    return char


def encrypt_block(text_block, shift):
    return [caesar_shift(char, shift) for char in text_block]


def decrypt_block(text_block, shift):
    return [caesar_shift(char, -shift) for char in text_block]


def process_file(
    input_file,
    output_file,
    shifts,
    chunk_size,
    is_encrypt=True,
    as_codes=False,
):
    try:
        with open(input_file, "r", encoding="utf-8") as f_in, open(
            output_file, "w", encoding="utf-8"
        ) as f_out:
            shift_index = 0

            while True:
                text_block = f_in.read(chunk_size)
                if not text_block:
                    break

                current_shift = shifts[shift_index % len(shifts)]
                shift_index += 1

                if is_encrypt:
                    processed_block = encrypt_block(text_block, current_shift)
                else:
                    processed_block = decrypt_block(text_block, current_shift)

                if as_codes:
                    processed_block = [str(ord(c)) for c in processed_block]
                    f_out.write(" ".join(processed_block) + " ")
                else:
                    f_out.write("".join(processed_block))
    except IOError as e:
        print(f"Помилка при роботі з файлами: {e}")


def calculate_probabilities_from_file(file_path, is_only_alpha=True):
    total_chars = 0
    char_count = {}
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            while True:
                char = f.read(1).lower()
                if not char:
                    break
                if is_only_alpha and not char.isalpha():
                    continue
                total_chars += 1
                if char in char_count:
                    char_count[char] += 1
                else:
                    char_count[char] = 1
    except IOError as e:
        print(f"Помилка при читанні файлу: {e}")
        return {}

    probabilities = {char: count / total_chars for char, count in char_count.items()}
    return probabilities


def compare_distributions_from_files(original_file, encrypted_file, is_only_alpha=True):
    original_probs = calculate_probabilities_from_file(original_file, is_only_alpha)
    encrypted_probs = calculate_probabilities_from_file(encrypted_file, is_only_alpha)

    # Створюємо заголовок
    title = "Порівняння розподілу ймовірностей"
    separator = "-" * len(title)

    print(f"{title}\n{separator}")

    all_chars = sorted(set(original_probs.keys()).union(set(encrypted_probs.keys())))

    # Створюємо повну таблицю з усіма символами
    df = pd.DataFrame(
        {
            "Original": [original_probs.get(char, 0) for char in all_chars],
            "Encrypted": [encrypted_probs.get(char, 0) for char in all_chars],
        },
        index=all_chars,
    )

    # Виводимо таблицю у текстовій формі
    print(df)

    # Відмальовуємо графік
    fig, ax = plt.subplots(figsize=(12, 6))
    df.plot(kind="bar", ax=ax)

    plt.title(title)
    plt.xlabel("Символи")
    plt.ylabel("Ймовірність")
    plt.xticks(rotation=90)
    plt.tight_layout()
    plt.show()


def encrypt_file(input_file, output_file, shifts, chunk_size, as_codes=False):
    process_file(
        input_file, output_file, shifts, chunk_size, is_encrypt=True, as_codes=as_codes
    )


def decrypt_file(input_file, output_file, shifts, chunk_size, as_codes=False):
    process_file(
        input_file, output_file, shifts, chunk_size, is_encrypt=False, as_codes=as_codes
    )


def main():
    # if shifts a less than lenght of text
    # divided by chunk size it will go in loop
    shifts = [
        2,
        12,
        15,
        1,
        4,
        6,
        13,
        4,
        23,
        64,
        4,
        3,
        23,
        32,
        32,
        12,
        2,
        13,
        5,
        11,
        5,
        23,
        4,
        52,
        3,
        23,
        4,
        1,
        23,
        21,
        1,
        2,
        3,
        13,
        21,
        2,
        12,
        3,
        23,
        5,
        3,
        54,
        65,
        3,
        45,
        5,
    ]
    chunk_size = 32
    is_only_alpha = True
    input_file = "lorem.txt"
    encrypted_file = f"{input_file}_encrypted.txt"
    decrypted_file = f"{input_file}_decrypted.txt"

    encrypt_file(input_file, encrypted_file, shifts, chunk_size, as_codes=False)
    decrypt_file(encrypted_file, decrypted_file, shifts, chunk_size, as_codes=False)

    compare_distributions_from_files(input_file, encrypted_file, is_only_alpha)


if __name__ == "__main__":
    main()
