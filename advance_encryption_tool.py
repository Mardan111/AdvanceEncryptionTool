import os
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import scrypt as crypto_scrypt

# --- Cryptographic Functions ---

def generate_key_from_password(password, kdf_salt=None):
    """
    Derives a 256-bit AES encryption key from a password using Scrypt.
    If no salt is provided, a new one is generated.
    """
    if kdf_salt is None:
        kdf_salt = get_random_bytes(16)
    
    key = crypto_scrypt(password, kdf_salt, 32, N=2**14, r=8, p=1)
    return key, kdf_salt

def encrypt_aes_gcm(file_path, output_path, password):
    """Encrypts a file using AES-256 in GCM mode and saves it."""
    try:
        key, kdf_salt = generate_key_from_password(password.encode())
        
        # Create AES cipher with GCM mode
        cipher = AES.new(key, AES.MODE_GCM)
        
        with open(file_path, 'rb') as f_in:
            file_content = f_in.read()
            ciphertext, auth_tag = cipher.encrypt_and_digest(file_content)
        
        # Write all encrypted data and metadata to a single output file
        with open(output_path, 'wb') as f_out:
            f_out.write(kdf_salt)
            f_out.write(cipher.nonce)
            f_out.write(auth_tag)
            f_out.write(ciphertext)

        return True
    except FileNotFoundError:
        return f"Error: The file '{file_path}' was not found."
    except Exception as e:
        return f"An error occurred during encryption: {e}"

def decrypt_aes_gcm(encrypted_file_path, output_path, password):
    """Decrypts an AES-GCM encrypted file and saves it."""
    try:
        with open(encrypted_file_path, 'rb') as f_in:
            kdf_salt = f_in.read(16)
            nonce = f_in.read(16)
            auth_tag = f_in.read(16)
            ciphertext = f_in.read()

        key, _ = generate_key_from_password(password.encode(), kdf_salt)
        
        cipher = AES.new(key, AES.MODE_GCM, nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, auth_tag)
        
        with open(output_path, 'wb') as f_out:
            f_out.write(plaintext)

        return True
    except FileNotFoundError:
        return f"Error: The file '{encrypted_file_path}' was not found."
    except ValueError:
        return "Error: Decryption failed. Incorrect password or corrupted data."
    except Exception as e:
        return f"An error occurred during decryption: {e}"


# --- GUI Application ---

class EncryptionApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Advance Encryption Tool")
        self.root.geometry("500x300")
        self.root.resizable(False, False)

        style = ttk.Style()
        style.configure("TFrame", padding=10)
        style.configure("TButton", padding=5)

        # Main frame
        main_frame = ttk.Frame(root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # File selection frame
        file_frame = ttk.Frame(main_frame)
        file_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(file_frame, text="File:").pack(side=tk.LEFT, padx=5)
        self.file_path_entry = ttk.Entry(file_frame)
        self.file_path_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(file_frame, text="Browse", command=self.browse_file).pack(side=tk.LEFT, padx=5)

        # Password frame
        pass_frame = ttk.Frame(main_frame)
        pass_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(pass_frame, text="Password:").pack(side=tk.LEFT, padx=5)
        self.password_entry = ttk.Entry(pass_frame, show="*")
        self.password_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # Action buttons frame
        action_frame = ttk.Frame(main_frame)
        action_frame.pack(pady=10)
        
        ttk.Button(action_frame, text="Encrypt", command=self.perform_encryption).pack(side=tk.LEFT, padx=10)
        ttk.Button(action_frame, text="Decrypt", command=self.perform_decryption).pack(side=tk.LEFT, padx=10)
        
    def browse_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            self.file_path_entry.delete(0, tk.END)
            self.file_path_entry.insert(0, file_path)

    def perform_encryption(self):
        file_path = self.file_path_entry.get()
        password = self.password_entry.get()
        
        if not all([file_path, password]):
            messagebox.showerror("Error", "File path and password are required.")
            return
        
        output_path = file_path + ".enc"
        result = encrypt_aes_gcm(file_path, output_path, password)
        
        if result is True:
            messagebox.showinfo("Success", f"File successfully encrypted to {output_path}")
        else:
            messagebox.showerror("Error", result)

    def perform_decryption(self):
        file_path = self.file_path_entry.get()
        password = self.password_entry.get()
        
        if not all([file_path, password]):
            messagebox.showerror("Error", "File path and password are required.")
            return
            
        if not file_path.endswith(".enc"):
            messagebox.showerror("Error", "Selected file does not have a '.enc' extension.")
            return

        base_name = os.path.basename(file_path)
        default_output_name = base_name.replace('.enc', '', 1) if base_name.endswith('.enc') else base_name
        
        # Prompt user to choose the output path for decryption
        output_path = filedialog.asksaveasfilename(
            initialfile=default_output_name,
            filetypes=[("All files", "*.*")]
        )

        result = decrypt_aes_gcm(file_path, output_path, password)
        
        if result is True:
            messagebox.showinfo("Success", f"File successfully decrypted to {output_path}")
        else:
            messagebox.showerror("Error", result)

if __name__ == "__main__":
    root = tk.Tk()
    app = EncryptionApp(root)
    root.mainloop()
