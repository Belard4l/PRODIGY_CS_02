from tkinter import *
from tkinter import filedialog, messagebox
from PIL import Image, ImageTk
import numpy as np
from io import BytesIO
import hashlib

MAGIC_HEADER = b'ENCRYPTED'

def load_image():
    file_path = filedialog.askopenfilename(filetypes=[("All Files", "*.*")])
    if file_path:
        try:
            with open(file_path, "rb") as f:
                header = f.read(len(MAGIC_HEADER))
                f.seek(0)
                if header != MAGIC_HEADER:
                    img = Image.open(file_path)
                    img.thumbnail((250, 250))
                    img = ImageTk.PhotoImage(img)
                    label_img.config(image=img)
                    label_img.image = img
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load image: {e}")
        entry_file_path.delete(0, END)
        entry_file_path.insert(0, file_path)

def encrypt_image():
    file_path = entry_file_path.get()
    if not file_path:
        messagebox.showerror("Error", "Please select an image first.")
        return
    try:
        key = int(entry_key.get())
    except ValueError:
        messagebox.showerror("Error", "Please enter a valid integer key.")
        return

    try:
        img = Image.open(file_path)
        img_array = np.array(img)

        # Perform pixel swapping and add key
        encrypted_array = np.copy(img_array)
        for i in range(img_array.shape[0]):
            for j in range(0, img_array.shape[1], 2):
                if j + 1 < img_array.shape[1]:
                    encrypted_array[i, j], encrypted_array[i, j + 1] = encrypted_array[i, j + 1], encrypted_array[i, j]
                encrypted_array[i, j] = (encrypted_array[i, j] + key) % 256
                if j + 1 < img_array.shape[1]:
                    encrypted_array[i, j + 1] = (encrypted_array[i, j + 1] + key) % 256

        # Convert the encrypted array back to an image
        enc_img = Image.fromarray(encrypted_array.astype('uint8'))

        # Save the image with a magic header and hash of the key
        key_hash = hashlib.sha256(str(key).encode()).digest()
        with open(file_path, "wb") as f:
            f.write(MAGIC_HEADER)
            f.write(key_hash)
            enc_img.save(f, format='PNG')

        messagebox.showinfo("Success", "Image encrypted.")

    except Exception as e:
        messagebox.showerror("Error", f"Failed to encrypt image: {e}")

def decrypt_image():
    file_path = entry_file_path.get()
    if not file_path:
        messagebox.showerror("Error", "Please select an image first.")
        return
    try:
        key = int(entry_key.get())
    except ValueError:
        messagebox.showerror("Error", "Please enter a valid integer key.")
        return

    try:
        with open(file_path, "rb") as f:
            header = f.read(len(MAGIC_HEADER))
            if header != MAGIC_HEADER:
                messagebox.showerror("Error", "The selected file is not encrypted.")
                return
            stored_key_hash = f.read(32)  # SHA-256 hash length is 32 bytes
            provided_key_hash = hashlib.sha256(str(key).encode()).digest()
            if stored_key_hash != provided_key_hash:
                messagebox.showerror("Error", "The provided key is incorrect.")
                return
            img_data = f.read()
            img = Image.open(BytesIO(img_data))
            img_array = np.array(img)
    except Exception as e:
        messagebox.showerror("Error", f"Failed to open encrypted image: {e}")
        return

    # Subtract key and reverse pixel swapping
    decrypted_array = np.copy(img_array)
    for i in range(img_array.shape[0]):
        for j in range(0, img_array.shape[1], 2):
            decrypted_array[i, j] = (decrypted_array[i, j] - key) % 256
            if j + 1 < img_array.shape[1]:
                decrypted_array[i, j + 1] = (decrypted_array[i, j + 1] - key) % 256
                decrypted_array[i, j], decrypted_array[i, j + 1] = decrypted_array[i, j + 1], decrypted_array[i, j]

    dec_img = Image.fromarray(decrypted_array.astype('uint8'))
    
    # Save the decrypted image to the same file
    with open(file_path, "wb") as f:
        dec_img.save(f, format='PNG')
    
    messagebox.showinfo("Success", "Image decrypted.")

# GUI Setup
root = Tk()
root.geometry("400x400")
root.title("Image Encryption Tool")

Label(root, text="Image File Path:").place(x=50, y=20)
entry_file_path = Entry(root, width=50)
entry_file_path.place(x=150, y=20)

button_load = Button(root, text="Load Image", command=load_image)
button_load.place(x=50, y=60)

Label(root, text="Enter Key:").place(x=50, y=100)
entry_key = Entry(root, width=10)
entry_key.place(x=150, y=100)

button_encrypt = Button(root, text="Encrypt Image", command=encrypt_image)
button_encrypt.place(x=50, y=140)

button_decrypt = Button(root, text="Decrypt Image", command=decrypt_image)
button_decrypt.place(x=150, y=140)

label_img = Label(root)
label_img.place(x=50, y=180)

root.mainloop()
