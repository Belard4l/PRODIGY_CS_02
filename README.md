# Image Encryption Tool

This is a simple GUI tool for encrypting and decrypting images using a key-based pixel swapping and modification technique. The application is built using Python with the Tkinter library for the GUI, PIL (Pillow) for image processing, and NumPy for handling image data arrays.

## Features

- Load and display images from your local filesystem.
- Encrypt images using a user-provided key.
- Decrypt images using the same key.
- Encrypted images include a magic header and a hash of the encryption key for verification.

## Requirements

- Python 3.x
- Tkinter (usually included with Python)
- Pillow (`pip install pillow`)
- NumPy (`pip install numpy`)

## Usage

### 1. Load an Image

1. Click the "Load Image" button.
2. Select an image file from the file dialog.

### 2. Encrypt the Image

1. Enter an integer key in the "Enter Key" field.
2. Click the "Encrypt Image" button.

### 3. Decrypt the Image

1. Enter the same integer key used for encryption in the "Enter Key" field.
2. Click the "Decrypt Image" button.

# Screenshot

![Screenshot (197)](https://github.com/Belard4l/PRODIGY_CS_02/assets/123712274/470a122e-c3f8-498f-a6ee-b73d5b9fb1d9)


## Constraints

### Image Loading
- Only files with headers not matching `MAGIC_HEADER` are allowed to be loaded as new images.

### Encryption
- User must enter a valid integer key.
- The image is encrypted by swapping adjacent pixels and adding the key value to pixel values.
- The encrypted image file includes a magic header `MAGIC_HEADER` and a SHA-256 hash of the key.

### Decryption
- User must enter the correct integer key used for encryption.
- The application checks if the selected file has the `MAGIC_HEADER`.
- The application verifies the key by comparing its SHA-256 hash with the stored hash in the file.
- The image is decrypted by reversing the pixel swapping and subtracting the key value from pixel values.

