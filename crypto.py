import os
import hashlib
import hmac
import getpass
from pathlib import Path

NONCE_SIZE = 16  
MAC_SIZE = 32    


def derive_master_key(password: str, nonce: bytes) -> bytes:
    material = password.encode("utf-8") + nonce
    for _ in range(100_000):
        material = hashlib.sha256(material).digest()
    return material


def generate_keystream(master_key: bytes, length: int) -> bytes:
    chunks = []
    counter = 0
    total_bytes = 0

    while total_bytes < length:
        block = hashlib.sha256(master_key + counter.to_bytes(8, "big")).digest()
        chunks.append(block)
        total_bytes += len(block)  
        counter += 1
        
    return b"".join(chunks)[:length]


def xor_bytes(data: bytes, keystream: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(data, keystream))


def encrypt_file(file_path: Path, password: str):
    plaintext = file_path.read_bytes()
    nonce = os.urandom(NONCE_SIZE)
    
    master_key = derive_master_key(password, nonce)
    keystream = generate_keystream(master_key, len(plaintext))
    ciphertext = xor_bytes(plaintext, keystream)

    mac = hmac.new(master_key, nonce + ciphertext, hashlib.sha256).digest()

    out_path = file_path.with_suffix(file_path.suffix + ".enc")
    out_path.write_bytes(nonce + mac + ciphertext)
    print(f"加密完成: {out_path.name}")
    print(f"    文件头写入的 Nonce (Hex): {nonce.hex()}")


def decrypt_file(enc_path: Path, password: str):
    raw = enc_path.read_bytes()

    nonce = raw[:NONCE_SIZE]
    saved_mac = raw[NONCE_SIZE : NONCE_SIZE + MAC_SIZE]
    ciphertext = raw[NONCE_SIZE + MAC_SIZE :]

    master_key = derive_master_key(password, nonce)

    expected_mac = hmac.new(master_key, nonce + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(expected_mac, saved_mac):
        raise ValueError("解密失败 密码错误或加密文件已被篡改")

    keystream = generate_keystream(master_key, len(ciphertext))
    plaintext = xor_bytes(ciphertext, keystream)

    out_path = enc_path.with_name("decrypted_" + enc_path.stem)
    out_path.write_bytes(plaintext)
    print(f"解密成功: {out_path.name}")


if __name__ == "__main__":
    choice = input("请选择操作 (1 = 加密文件, 2 = 解密文件): ").strip()
    path_input = input("请输入文件路径（可直接把文件拖进终端）: ").strip().strip('"').strip("'")
    target = Path(path_input)

    if not target.exists():
        print("[-] 文件不存在，请检查路径。")
        exit(1)

    pwd = getpass.getpass("请输入密码: ")

    if choice == "1":
        encrypt_file(target, pwd)
    elif choice == "2":
        decrypt_file(target, pwd)