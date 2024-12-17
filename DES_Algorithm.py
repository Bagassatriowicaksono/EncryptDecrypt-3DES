#  ==========================================================================
#  Name           : 3DES_Algorithm
#  Description    : 3DES Encryption and Decryption Algorithm
#  ============================================================================

from tkinter import *
from tkinter.scrolledtext import ScrolledText

def DES_encrypt(message, key):
    """ Basic DES Encryption function using the existing logic. """
    # Simulate DES encryption (replace with actual DES logic from Encrypt)
    return message[::-1]  # Placeholder: Reverse the message for demonstration

def DES_decrypt(cipher, key):
    """ Basic DES Decryption function using the existing logic. """
    # Simulate DES decryption (replace with actual DES logic from Decrypt)
    return cipher[::-1]  # Placeholder: Reverse back for demonstration

# GUI Configuration
T = Tk()
T.geometry("940x700")
T.title("3DES Algorithm")
T.configure(background="lightblue")

plainText = StringVar()
cipherText = StringVar()
key1 = StringVar()
key2 = StringVar()
key3 = StringVar()

def clear_plain():
    plainText.delete(1.0, END)

def clear_cipher():
    cipherText.delete(1.0, END)

def Encrypt_3DES():
    message = plainText.get(1.0, END).strip()
    k1, k2, k3 = key1.get().strip(), key2.get().strip(), key3.get().strip()

    # Validasi input
    if not message or any(not k for k in [k1, k2, k3]):
        print("Error: Please provide all keys and message.")
        return

    if len(message) != 8 or any(len(k) != 8 for k in [k1, k2, k3]):
        print("Error: Message and keys must be 8 bytes (64 bits).")
        return

    # Proses 3DES: Encrypt → Decrypt → Encrypt
    cipher1 = DES_encrypt(message, k1)
    cipher2 = DES_decrypt(cipher1, k2)
    final_cipher = DES_encrypt(cipher2, k3)

    cipherText.delete(1.0, END)
    cipherText.insert(INSERT, final_cipher)
    print("Encrypted Cipher Text:", final_cipher)

def Decrypt_3DES():
    cipher = cipherText.get(1.0, END).strip()
    k1, k2, k3 = key1.get().strip(), key2.get().strip(), key3.get().strip()

    # Validasi input
    if not cipher or any(not k for k in [k1, k2, k3]):
        print("Error: Please provide all keys and cipher text.")
        return

    if len(cipher) != 8 or any(len(k) != 8 for k in [k1, k2, k3]):
        print("Error: Cipher text and keys must be 8 bytes (64 bits).")
        return

    # Proses 3DES: Decrypt → Encrypt → Decrypt
    plain1 = DES_decrypt(cipher, k3)
    plain2 = DES_encrypt(plain1, k2)
    final_plain = DES_decrypt(plain2, k1)

    plainText.delete(1.0, END)
    plainText.insert(INSERT, final_plain)
    print("Decrypted Plain Text:", final_plain)

# GUI Widgets
Label(T, text="Key 1", font="Calibri", bg="lightblue").place(x=60, y=60)
Entry(T, textvariable=key1, font="Calibri", width="50").place(x=60, y=80)

Label(T, text="Key 2", font="Calibri", bg="lightblue").place(x=60, y=110)
Entry(T, textvariable=key2, font="Calibri", width="50").place(x=60, y=130)

Label(T, text="Key 3", font="Calibri", bg="lightblue").place(x=60, y=160)
Entry(T, textvariable=key3, font="Calibri", width="50").place(x=60, y=180)

Label(T, text="Plain Text", font="Calibri", bg="lightblue").place(x=140, y=220)
plainText = ScrolledText(T, height=5, width=40)
plainText.place(x=60, y=250)
Button(T, text="Clear", width=8, command=clear_plain).place(x=180, y=400)

Label(T, text="Cipher Text", font="Calibri", bg="lightblue").place(x=560, y=220)
cipherText = ScrolledText(T, height=5, width=40)
cipherText.place(x=540, y=250)
Button(T, text="Clear", width=8, command=clear_cipher).place(x=670, y=400)

Button(T, text="Encrypt 3DES", width=12, command=Encrypt_3DES).place(x=435, y=310)
Button(T, text="Decrypt 3DES", width=12, command=Decrypt_3DES).place(x=435, y=350)

T.mainloop()
