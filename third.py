from cryptography.fernet import Fernet
import argparse

#Kryptering och dekryptering med Cryptography-Fernet
def generate_key():
    return Fernet.generate_key()

def encrypt_data(data, key):
    try:
        fernet = Fernet(key)
        encrypted = fernet.encrypt(data.encode())
        return encrypted.decode('utf-8')
    except Exception as e:
        print(f"Kryptering misslyckades! {e}")
        return None

def decrypt_data(encrypted_data, key):
    try:
        fernet = Fernet(key)
        decrypted = fernet.decrypt(encrypted_data.encode())
        return decrypted.decode('utf-8')
    except Exception as e:
        print(f"Dykryptering misslyckades! {e}")
        return None

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Kryptering och dekryptering")
    parser.add_argument("-e", "--encrypt", type=str, help="Ange data för att kryptera")
    parser.add_argument("-d", "--decrypt", type=str, help="Ange data för att dekryptera")
    parser.add_argument("-k", "--key", type=str, help="Säkerhetsnyckel för att kryptera eller dekryptera")
    parser.add_argument("--g-k", action="store_true", help="Generera ny säkerhetsnyckel")
    args = parser.parse_args()

    # Generera nyckel
    if args.g_k:
        key = generate_key()
        print(f"Säkerhetsnyckel: {key.decode('utf-8')}")

    # Kryptera data
    if args.encrypt and args.key:
        encrypted_data = encrypt_data(args.encrypt, args.key.encode())
        if encrypted_data:
            print(f"Encrypted Data: {encrypted_data}")
        else:
            print("Kryptering misslykades. Försök igen(Obs:Säkerhetsnyckel och inmatning)")

    # Dekryptera data
    if args.decrypt and args.key:
        decrypted_data = decrypt_data(args.decrypt, args.key.encode())
        if decrypted_data:
            print(f"Dekrypterad information: {decrypted_data}")
        else:
            print("Dekryptering misslykades! försök igen (Obs:Säkerhetsnyckel och inmatning)")

