# -*- coding: utf-8 -*-

# короче тут описан весь процесс как работает шифрование сети фестеля:
# 1. берем текст, дополняем пробелами чтоб его длина делилась на 8 байт (64 бита)
# 2. каждый кусок переводим в 64-битное число и делим его на две половины по 32 бита: левую (L) и правую (R)
# 3. запускаем раунды (обычно их несколько):
#    - берем правую часть R, делаем циклический сдвиг влево на 3 бита и xor-им с раундовым ключом (это раундовая функция)
#    - результат этой функции xor-им с левой частью L, получаем новую правую часть
#    - а старая правая часть становится новой левой частью
# 4. если включен режим сбс (cbc), то перед шифрованием каждый блок xor-ится с предыдущим зашифрованным блоком (или с начальным вектором iv)
# 5. после всех раундов делаем финальный swap (меняем местами L и R) и собираем кусок обратно в 64-битный блок

BLOCK_SIZE_BITS = 64     # общий размер блока (64 бита = 8 байт)
HALF_BLOCK_BITS = 32     # половина блока для фестеля (32 бита)
NUM_ROUNDS = 4           # количество раундов шифрования
MASK_32 = 0xFFFFFFFF     # маска чтобы обрезать всё до 32 бит
IV_DEFAULT = 0x123456789ABCDEF0  # дефолтный вектор инициализации для сбс режима


# вспомогательные штуки для сети фестеля

def cyclic_shift_left_32(val: int, shift: int = 3) -> int:
    # циклический сдвиг 32-битного числа влево
    shift %= 32
    return ((val << shift) | (val >> (32 - shift))) & MASK_32

def round_function_feistel(r: int, k: int) -> int:
    # раундовая функция f(r, k): сдвигаем r влево и делаем xor с ключом раунда
    return cyclic_shift_left_32(r, 3) ^ k

def generate_round_keys_feistel(master_key: int, num_rounds: int) -> list[int]:
    # генерация ключей для каждого раунда через xor с номером раунда
    return [(master_key ^ i) & MASK_32 for i in range(1, num_rounds + 1)]


# ядро сети фестеля (разбито на части римскими цифрами)

def feistel_process_block(block: int, round_keys: list[int]) -> int:
    # прогоняем один 64-битный блок через сеть фестеля
    
    # часть I: разделение блока на левую (L) и правую (R) половины по 32 бита
    l = (block >> HALF_BLOCK_BITS) & MASK_32
    r = block & MASK_32

    # часть II: основной цикл раундов сети фестеля
    # здесь правая часть проходит через раундовую функцию и смешивается с левой
    for k in round_keys:
        next_l = r
        next_r = l ^ round_function_feistel(r, k)
        l, r = next_l, next_r

    # часть III: финальная перестановка (swap) и сборка половин обратно в единый блок
    final_block = (r << HALF_BLOCK_BITS) | l
    return final_block

def feistel_cipher(data_blocks: list[int], master_key: int, mode: str = 'encrypt', cbc_mode: bool = False) -> list[int]:
    # шифруем или расшифровываем список блоков (поддерживает обычный режим и сбс)
    keys = generate_round_keys_feistel(master_key, NUM_ROUNDS)
    if mode == 'decrypt' and not cbc_mode:
        keys = keys[::-1]

    processed_blocks = []
    current_iv = IV_DEFAULT

    if mode == 'encrypt':
        for block in data_blocks:
            target_block = block ^ current_iv if cbc_mode else block
            enc_block = feistel_process_block(target_block, keys)
            processed_blocks.append(enc_block)
            if cbc_mode:
                current_iv = enc_block
    else:
        if cbc_mode:
            keys_dec = keys[::-1]
            for block in data_blocks:
                dec_block = feistel_process_block(block, keys_dec)
                plain_block = dec_block ^ current_iv
                processed_blocks.append(plain_block)
                current_iv = block
        else:
            for block in data_blocks:
                processed_blocks.append(feistel_process_block(block, keys))

    return processed_blocks


# спн (сеть подстановок-перестановок)

S_BOX = [0xE, 0x4, 0xD, 0x1, 0x2, 0xF, 0xB, 0x8, 0x3, 0xA, 0x6, 0xC, 0x5, 0x9, 0x0, 0x7]
INV_S_BOX = [S_BOX.index(i) for i in range(16)]

P_BOX = [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15]
INV_P_BOX = [P_BOX.index(i) for i in range(16)]

def apply_sbox(block: int, sbox: list[int]) -> int:
    # применяем s-блок к нибблам
    res = 0
    for i in range(16):
        nibble = (block >> (4 * (15 - i))) & 0xF
        subbed = sbox[nibble]
        res = (res << 4) | subbed
    return res

def apply_pbox(block: int, pbox: list[int]) -> int:
    # делаем перестановку нибблов по p-блоку
    nibbles = [(block >> (4 * (15 - i))) & 0xF for i in range(16)]
    res = 0
    for i in range(16):
        target_idx = pbox[i]
        res = (res << 4) | nibbles[target_idx]
    return res

def generate_round_keys_spn(master_key: int, num_rounds: int) -> list[int]:
    # генеряем ключи для спн
    keys = []
    for i in range(num_rounds + 1):
        k = ((master_key << (i * 3)) | (master_key >> (64 - (i * 3)))) & 0xFFFFFFFFFFFFFFFF
        keys.append(k)
    return keys

def spn_process_block(block: int, round_keys: list[int], mode: str = 'encrypt') -> int:
    # обрабатываем блок через спн
    num_rounds = len(round_keys) - 1

    if mode == 'encrypt':
        curr = block
        for r in range(num_rounds - 1):
            curr ^= round_keys[r]
            curr = apply_sbox(curr, S_BOX)
            curr = apply_pbox(curr, P_BOX)
        curr ^= round_keys[num_rounds - 1]
        curr = apply_sbox(curr, S_BOX)
        curr ^= round_keys[num_rounds]
        return curr
    else:
        keys_dec = round_keys[::-1]
        curr = block ^ keys_dec[0]
        curr = apply_sbox(curr, INV_S_BOX)
        curr ^= keys_dec[1]
        for r in range(1, num_rounds - 1):
            curr = apply_pbox(curr, INV_P_BOX)
            curr = apply_sbox(curr, INV_S_BOX)
            curr ^= keys_dec[r + 1]
        curr = apply_pbox(curr, INV_P_BOX)
        curr = apply_sbox(curr, INV_S_BOX)
        curr ^= keys_dec[num_rounds]
        return curr

def spn_cipher(data_blocks: list[int], master_key: int, mode: str = 'encrypt', cbc_mode: bool = False) -> list[int]:
    # шифрование список блоков для спн
    keys = generate_round_keys_spn(master_key, NUM_ROUNDS)
    processed_blocks = []
    current_iv = IV_DEFAULT

    if mode == 'encrypt':
        for block in data_blocks:
            target_block = block ^ current_iv if cbc_mode else block
            enc_block = spn_process_block(target_block, keys, mode='encrypt')
            processed_blocks.append(enc_block)
            if cbc_mode:
                current_iv = enc_block
    else:
        if cbc_mode:
            for block in data_blocks:
                dec_block = spn_process_block(block, keys, mode='decrypt')
                plain_block = dec_block ^ current_iv
                processed_blocks.append(plain_block)
                current_iv = block
        else:
            for block in data_blocks:
                processed_blocks.append(spn_process_block(block, keys, mode='decrypt'))

    return processed_blocks


# вспомогательные функции для текста и паддинга

def pad(text: str, block_size_bytes: int = 8) -> str:
    # добиваем строку пробелами до кратного размера
    pad_len = (block_size_bytes - len(text) % block_size_bytes) % block_size_bytes
    return text + (' ' * pad_len)

def unpad(text: str) -> str:
    # убираем лишние пробелы в конце
    return text.rstrip(' ')

def text_to_blocks(text: str) -> list[int]:
    # превращаем текст в блоки чисел
    padded = pad(text, 8)
    blocks = []
    for i in range(0, len(padded), 8):
        chunk = padded[i:i+8]
        block_int = int.from_bytes(chunk.encode('utf-8'), byteorder='big')
        blocks.append(block_int)
    return blocks

def blocks_to_text(blocks: list[int]) -> str:
    # собираем блоки обратно в текстовую строку
    chars = []
    for block in blocks:
        block_bytes = block.to_bytes(8, byteorder='big')
        chars.append(block_bytes.decode('utf-8', errors='ignore'))
    return "".join(chars)


# консольный интерфейс

def main():
    print("privet, eto laba po blochnym shifram")
    print(f"tut blok = {BLOCK_SIZE_BITS} bit, raundov = {NUM_ROUNDS}\n")

    print("vyberi algoritm:")
    print("1 - set feystelya")
    print("2 - spn")
    algo_choice = input("nomer: ").strip()

    if algo_choice not in ('1', '2'):
        print("oshibka, takogo net")
        return

    print("\nvyberi rezhim raboty:")
    print("1 - ecb (prostoy)")
    print("2 - sbs / cbc (so stsepleniem blokov)")
    mode_choice = input("nomer: ").strip()

    if mode_choice not in ('1', '2'):
        print("nevernyy rezhim")
        return
    cbc_flag = (mode_choice == '2')

    mode_op = input("\nchto delaem? (1 - shifrovat, 2 - rasshifrovat): ").strip()
    master_key_input = input("vvedi chislovoy klyuch (naprimer 12345): ").strip()
    
    try:
        master_key = int(master_key_input)
    except ValueError:
        print("oshibka: klyuch dolzhen byt tsifroy!")
        return

    if mode_op == '1':
        text = input("vvedite tekst dlya shifra: ")
        blocks = text_to_blocks(text)
        
        if algo_choice == '1':
            encrypted_blocks = feistel_cipher(blocks, master_key, mode='encrypt', cbc_mode=cbc_flag)
        else:
            encrypted_blocks = spn_cipher(blocks, master_key, mode='encrypt', cbc_mode=cbc_flag)
        
        hex_output = "".join([f"{b:016x}" for b in encrypted_blocks])
        print(f"\nvot chto poluchilos v hex:\n{hex_output}")

    elif mode_op == '2':
        hex_input = input("vvedite hex stroku dlya rasshifrovki: ").strip()
        
        try:
            blocks = [int(hex_input[i:i+16], 16) for i in range(0, len(hex_input), 16)]
        except ValueError:
            print("oshibka v hex stroke!")
            return

        if algo_choice == '1':
            decrypted_blocks = feistel_cipher(blocks, master_key, mode='decrypt', cbc_mode=cbc_flag)
        else:
            decrypted_blocks = spn_cipher(blocks, master_key, mode='decrypt', cbc_mode=cbc_flag)

        decrypted_text = unpad(blocks_to_text(decrypted_blocks))
        print(f"\nrasshifrovannyy tekst:\n{decrypted_text}")

    else:
        print("neponyatnoe deystvie")

if __name__ == "__main__":
    main()