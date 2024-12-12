from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os

# Функція для шифрування даних за допомогою AES у режимі GCM
def encrypt_file(input_file, output_file, password):
    # Перевіряємо наявність вхідного файлу
    if not os.path.exists(input_file):
        raise FileNotFoundError(f"Вхідний файл {input_file} не знайдено. Перевірте шлях до файлу.")

    # Зчитуємо дані з текстового файлу
    with open(input_file, 'r', encoding='utf-8') as f:
        plaintext = f.read().encode('utf-8')

    # Генеруємо випадковий IV (ініціалізаційний вектор)
    iv = os.urandom(12)  # Рекомендований розмір IV для GCM

    # Генеруємо ключ із паролю
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode('utf-8'))

    # Створюємо об'єкт шифрування AES-GCM
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Шифруємо текст
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    # Отримуємо тег автентифікації
    tag = encryptor.tag

    # Зберігаємо шифротекст і метадані у двійковий файл
    with open(output_file, 'wb') as f:
        f.write(salt)      # Зберігаємо сіль для відновлення ключа
        f.write(iv)        # Зберігаємо IV
        f.write(tag)       # Зберігаємо тег автентифікації
        f.write(ciphertext)  # Зберігаємо шифротекст

    print(f"Дані успішно зашифровані та збережені у файл: {output_file}")

# Використання програми
if __name__ == "__main__":
    input_file = "input.txt"   # Ім'я вхідного текстового файлу
    output_file = "encrypted.bin"  # Ім'я файлу з шифротекстом
    password = "securepassword"  # Пароль для шифрування

    try:
        encrypt_file(input_file, output_file, password)
    except FileNotFoundError as e:
        print(e)




