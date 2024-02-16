from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
from tkinter import ttk, messagebox
import tkinter
import base64
import os

root = tkinter.Tk()
root.title("Gizli Notlar")
root.config(padx=30, pady=30)
style = ttk.Style()

dic_list = {}


def combo_update():
    global dic_list
    mode = 'r' if os.path.isfile('secret.txt') else 'w'
    with open("secret.txt", mode) as f:
        x = ""
        y = ""
        if os.stat('secret.txt').st_size != 0:
            for row, line in enumerate(f):
                if row % 2 == 0:
                    x = line
                else:
                    y = line
                dic_list[x.strip()] = y.strip()

    title_entry.config(values=[x for x in dic_list.keys()])


def encrpt_key(cipher):
    password = cipher.encode()
    mysalt = b'\x88\xe1\xc5\x96\x10\xfdW\xee\xdc\xebK\xaf\xf9\xf1\xaf\x05'
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=mysalt,
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password))


def center_window(width, height):
    x = root.winfo_screenwidth() / 2 - width / 2
    y = root.winfo_screenheight() / 2 - height / 2
    root.geometry("%dx%d+%d+%d" % (width, height, x, y))


def encrypt():
    global dic_list
    data = note.get(0.0, 'end')
    key = encrpt_key(key_entry.get())

    cipher = Fernet(key)
    encrypted = cipher.encrypt(data.encode())
    note.delete(0.0, 'end')
    note.insert(0.0, encrypted)

    with open('secret.txt', 'a') as f:
        f.write(title_entry.get() + '\n' + encrypted.decode() + '\n')

    combo_update()
    title_entry.delete(0, 'end')
    note.delete(0.0, 'end')
    key_entry.delete(0, 'end')
    # encrypt_button['state'] = 'disable'


def get_notes(event):
    global dic_list
    c_name = title_entry.get()

    for x, y in dic_list.items():
        if c_name == x:
            note.delete(0.0, 'end')
            note.insert(0.0, y)


def decrypt():
    try:
        key = encrpt_key(key_entry.get())
        cipher = Fernet(key)
        encrypted_data = note.get(0.0, 'end')
        decrypted_data = cipher.decrypt(encrypted_data)
        note.delete(0.0, 'end')
        note.insert(0.0, decrypted_data.decode())
    except Exception:
        tkinter.messagebox.showerror("Hata", "Şifre hatalı")


def form_entry_area(event):
    head_area = 'true' if title_entry.index(tkinter.INSERT) == 0 else 'false'
    text_area = 'true' if note.index(tkinter.INSERT) == '1.0' else 'false'
    key_area = 'true' if key_entry.index(tkinter.INSERT) == 0 else 'false'

    control = note.get(0.0, 'end')

    if not control.startswith('gAAAAABl'):
        if title_entry.get() in dic_list.keys() and head_area == 'false':
            encrypt_button['state'] = 'disable'
            decrypt_button['state'] = 'disable'
        elif head_area and text_area and key_area == 'true':
            encrypt_button['state'] = 'disable'
            decrypt_button['state'] = 'disable'
        elif head_area and text_area and key_area == 'false':
            encrypt_button['state'] = 'normal'
            decrypt_button['state'] = 'disable'
    else:
        if title_entry.get() in dic_list.keys() and key_area == 'false':
            encrypt_button['state'] = 'disable'
            decrypt_button['state'] = 'normal'
        else:
            encrypt_button['state'] = 'disable'
            decrypt_button['state'] = 'disable'


center_window(400, 650)

img_path = tkinter.PhotoImage(file=r"C:\Users\2256220\PycharmProjects\SecretNotes\TopScret100x100.png")
img = tkinter.Label(root, image=img_path)
img.pack()

space = tkinter.Label()
space.pack()

title_label = tkinter.Label(root)
title_label.config(text="Notunuzun başlığını yazınız", font=('Arial', 11, 'bold'))
title_label.pack(pady=5)

title_list = [y for x, y in dic_list.items() if int(x) % 2 == 1]

title_entry = ttk.Combobox(root)
title_entry.config(width=60, font=('Arial', 10))

# aşağıdakiler Liste Kutusunu değiştirir
root.option_add('*TCombobox*Listbox*Background', 'light blue')
# root.option_add('*TCombobox*Listbox*Foreground', fg)
# root.option_add('*TCombobox*Listbox*selectBackground', fg)
# root.option_add('*TCombobox*Listbox*selectForeground', ebg)

style.theme_use('clam')
style.configure("TCombobox", fieldbackground="light blue", background="white")
title_entry.pack(ipady=2)
combo_update()

title_entry.bind('<<ComboboxSelected>>', get_notes)

space = tkinter.Label(root)
space.pack()

note_label = tkinter.Label(root)
note_label.config(text="Şifrelenecek notunuzu giriniz", font=('Arial', 11, 'bold'))
note_label.pack(pady=5)

note = tkinter.Text(width=60, height=10, bg='light blue', font=('Arial', 10))
note.pack(expand=True, ipady=2)
# note.bind("<ButtonRelease-1>", text_state)

space = tkinter.Label(root)
space.pack(pady=5)

key_label = tkinter.Label(root)
key_label.config(text="Şifrenezi giriniz", font=('Arial', 11, 'bold'))
key_label.pack(pady=5)

key_entry = tkinter.Entry(root, show='*')
key_entry.config(width=25, bg='light blue', font=('Arial', 10))
key_entry.pack(ipady=2)
# key_entry.bind("<ButtonRelease-1>", key_state)

space = tkinter.Label(root)
space.pack()

encrypt_button = tkinter.Button(text="Sakla & Şifrele", font=('Arial', 10, 'bold'), bg='pink', command=encrypt)
encrypt_button.pack()

decrypt_button = tkinter.Button(text="Şifre çöz", font=('Arial', 10, 'bold'), bg='light green', command=decrypt)
decrypt_button.pack(pady=5)

head_area = 'true' if title_entry.index(tkinter.INSERT) == 0 else 'false'
text_area = 'true' if note.index(tkinter.INSERT) == '1.0' else 'false'
key_area = 'true' if key_entry.index(tkinter.INSERT) == 0 else 'false'

if head_area and text_area and key_area == 'true':
    encrypt_button['state'] = 'disable'
    decrypt_button['state'] = 'disable'
else:
    encrypt_button['state'] = 'normal'
    decrypt_button['state'] = 'normal'

root.bind('<Leave>', form_entry_area)

root.mainloop()
