import tkinter as tk
from tkinter import messagebox
import pyperclip  
import base64

# Ana pencere
root = tk.Tk()
root.title("Binary Encoder & Decoder")
root.geometry("800x500")
BG_COLOR = "#2C2F33"
BUTTON_COLOR_1 = "#7289DA"
BUTTON_COLOR_2 = "#43B581"
BUTTON_COLOR_3 = "#FF5555"
BUTTON_COLOR_4 = "#FAA61A"

root.configure(bg=BG_COLOR)

def clear_all_widgets():

    for widget in root.winfo_children():
        widget.destroy()



def main_buttons():
    clear_all_widgets()  #tüm bileşenleri temizleme işlemi

    imza = tk.Label(root, text=" By Wexter ",font=("Arial", 18, "bold"), fg="red", bg=BG_COLOR)
    imza.pack(side="bottom")
    
    main_label = tk.Label(root, text="(:<  KULLANACAĞINIZ İŞLEMİ SEÇİN  >:)", font=("Arial", 12, "bold"), fg="white", bg=BG_COLOR)
    main_label.pack(pady=25)

    # 1. satır
    button_frame1 = tk.Frame(root, bg=BG_COLOR)
    button_frame1.pack(pady=10)

    binary_button = tk.Button(button_frame1, text="Binary İşlemi", command=binary_main_button, width=20, height=2, 
                              bg=BUTTON_COLOR_1, fg="white", font=("Arial", 12, "bold"))
    binary_button.grid(row=0, column=0, padx=10, pady=10)

    hexadecimal_button = tk.Button(button_frame1, text="Hexadeecimal İşlemi", command=hexadecimal_main_buttons, width=20, height=2, 
                                   bg=BUTTON_COLOR_1, fg="white", font=("Arial", 12, "bold"))
    hexadecimal_button.grid(row=0, column=1, padx=10, pady=10)

    sezar_button = tk.Button(button_frame1, text="Sezar İşlemi", command=sezar_main_buttons, width=20, height=2, 
                                   bg=BUTTON_COLOR_1, fg="white", font=("Arial", 12, "bold"))
    sezar_button.grid(row=0, column=2, padx=10, pady=10)

    # 2. satır
    button_frame2 = tk.Frame(root, bg=BG_COLOR)
    button_frame2.pack(pady=10)

    morse_button = tk.Button(button_frame2, text="Morse İşlemi",command=morse_main_button, width=20, height=2, 
                                   bg=BUTTON_COLOR_1, fg="white", font=("Arial", 12, "bold"))
    morse_button.grid(row=1, column=0, padx=10, pady=10)

    base64_button = tk.Button(button_frame2, text="Base64 İşlemi",command=base64_main_buttons, width=20, height=2, 
                                   bg=BUTTON_COLOR_1, fg="white", font=("Arial", 12, "bold"))
    base64_button.grid(row=1, column=1, padx=10, pady=10)

    xor_button = tk.Button(button_frame2, text="Xor İşlemi",command=xor_main_buttons, width=20, height=2, 
                                   bg=BUTTON_COLOR_1, fg="white", font=("Arial", 12, "bold"))
    xor_button.grid(row=1, column=2, padx=10, pady=10)

    # 3. satır
    button_frame3 = tk.Frame(root, bg=BG_COLOR)
    button_frame3.pack(pady=10)

    rot47_button = tk.Button(button_frame3, text="Rot-47 İşlemi",command=rot47_main_buttons, width=20, height=2, 
                                   bg=BUTTON_COLOR_1, fg="white", font=("Arial", 12, "bold"))
    rot47_button.grid(row=2, column=0, padx=10, pady=10)

    rot5_button = tk.Button(button_frame3, text="Rot-5 İşlemi",command=rot5_main_buttons, width=20, height=2, 
                                   bg=BUTTON_COLOR_1, fg="white", font=("Arial", 12, "bold"))
    rot5_button.grid(row=2, column=1, padx=10, pady=10)

    rail_fence_button = tk.Button(button_frame3, text="Rail Fence İşlemi",command=railfence_main_buttons, width=20, height=2, 
                                   bg=BUTTON_COLOR_1, fg="white", font=("Arial", 12, "bold"))
    rail_fence_button.grid(row=2, column=2, padx=10, pady=10)

    # 4. satır
    button_frame4 = tk.Frame(root, bg=BG_COLOR)
    button_frame4.pack(pady=10)

    atbash_button = tk.Button(button_frame4, text="Atbash İşlemi",command=atbash_main_buttons, width=20, height=2, 
                                   bg=BUTTON_COLOR_1, fg="white", font=("Arial", 12, "bold"))
    atbash_button.grid(row=3, column=0, padx=10, pady=10)

    reverse_button = tk.Button(button_frame4, text="Reverse İşlemi",command=reverse_main_buttons, width=20, height=2, 
                                   bg=BUTTON_COLOR_1, fg="white", font=("Arial", 12, "bold"))
    reverse_button.grid(row=3, column=1, padx=10, pady=10)

    vigenere_button = tk.Button(button_frame4, text="Vigenère İşlemi",command=vigenere_main_buttons, width=20, height=2, 
                                   bg=BUTTON_COLOR_1, fg="white", font=("Arial", 12, "bold"))
    vigenere_button.grid(row=3, column=2, padx=10, pady=10)

    
    

def binary_main_button():
    clear_all_widgets()
    
    label_bin = tk.Label(root, text="Binary İşlemleri:", font=("Arial", 12, "bold"), fg="white", bg=BG_COLOR)
    label_bin.pack(pady=5)

    encode_button = tk.Button(root, text="Encode", command=encode, width=20, height=2, 
                              bg=BUTTON_COLOR_1, fg="white", font=("Arial", 12, "bold"))
    encode_button.pack(pady=10)

    decode_button = tk.Button(root, text="Decode", command=decode, width=20, height=2, 
                              bg=BUTTON_COLOR_2, fg="white", font=("Arial", 12, "bold"))
    decode_button.pack(pady=10)

    back_button = tk.Button(root, text="Ana Menüye Dön", command=main_buttons, 
                            bg=BUTTON_COLOR_4, fg="white", font=("Arial", 10, "bold"))
    back_button.pack(pady=5)

def hexadecimal_main_buttons():
    clear_all_widgets()

    label_hex = tk.Label(root, text="Hexadecimal İşlemleri:", font=("Arial", 12, "bold"), fg="white", bg=BG_COLOR)
    label_hex.pack(pady=5)

    hex_encode_button = tk.Button(root, text="Hex Encode", command=hex_encode, width=20, height=2, 
                                  bg=BUTTON_COLOR_1, fg="white", font=("Arial", 12, "bold"))
    hex_encode_button.pack(pady=10)

    hex_decode_button = tk.Button(root, text="Hex Decode", command=hex_decode, width=20, height=2, 
                                  bg=BUTTON_COLOR_2, fg="white", font=("Arial", 12, "bold"))
    hex_decode_button.pack(pady=10)

    back_button = tk.Button(root, text="Ana Menüye Dön", command=main_buttons, 
                            bg=BUTTON_COLOR_4, fg="white", font=("Arial", 10, "bold"))
    back_button.pack(pady=5)

def show_result(result_text):
    clear_all_widgets()

    label = tk.Label(root, text="Sonuç:", font=("Arial", 12, "bold"), fg="white", bg=BG_COLOR)
    label.pack(pady=5)

    result_label = tk.Entry(root, width=50, font=("Arial", 12), justify="center")
    result_label.pack(pady=5)
    result_label.insert(0, result_text)
    result_label.config(state="readonly")

    def copy_to_clipboard():
        pyperclip.copy(result_text)
        messagebox.showinfo("Başarılı", "Sonuç kopyalandı!")

    copy_button = tk.Button(root, text="Kopyala", command=copy_to_clipboard, bg=BUTTON_COLOR_3, fg="white", font=("Arial", 10, "bold"))
    copy_button.pack(pady=5)

    back_button = tk.Button(root, text="Ana Menüye Dön", command=main_buttons, bg=BUTTON_COLOR_4, fg="white", font=("Arial", 10, "bold"))
    back_button.pack(pady=5)

def hex_encode():
    clear_all_widgets()
    
    label = tk.Label(root, text="Metni girin:", font=("Arial", 12, "bold"), fg="white", bg=BG_COLOR)
    label.pack(pady=5)

    entry = tk.Entry(root, width=40, font=("Arial", 12))
    entry.pack(pady=5)

    def convert():
        text = entry.get()
        if text:
            show_result(text.encode("utf-8").hex())
        else:
            messagebox.showerror("Hata", "Lütfen bir metin girin!")

    convert_button = tk.Button(root, text="Dönüştür", command=convert, bg=BUTTON_COLOR_2, fg="white", font=("Arial", 10, "bold"))
    convert_button.pack(pady=5)

def hex_decode():
    clear_all_widgets()

    label = tk.Label(root, text="Hexadecimal kodunu girin:", font=("Arial", 12, "bold"), fg="white", bg=BG_COLOR)
    label.pack(pady=5)

    entry = tk.Entry(root, width=40, font=("Arial", 12))
    entry.pack(pady=5)

    def convert():
        try:
            show_result(bytes.fromhex(entry.get()).decode("utf-8"))
        except ValueError:
            messagebox.showerror("Hata", "Geçersiz hexadecimal kodu!")

    convert_button = tk.Button(root, text="Çöz", command=convert, bg=BUTTON_COLOR_2, fg="white", font=("Arial", 10, "bold"))
    convert_button.pack(pady=5)

def encode(): #sadece binary için 
    clear_all_widgets()

    label = tk.Label(root, text="Metin girin:", font=("Arial", 12, "bold"), fg="white", bg=BG_COLOR)
    label.pack(pady=5)

    entry = tk.Entry(root, width=40, font=("Arial", 12))
    entry.pack(pady=5)

    def convert():
        text = entry.get()
        if text:
            show_result(' '.join(format(ord(char), '08b') for char in text))
        else:
            messagebox.showerror("Hata", "Lütfen bir metin girin!")

    convert_button = tk.Button(root, text="Dönüştür", command=convert, bg=BUTTON_COLOR_2, fg="white", font=("Arial", 10, "bold"))
    convert_button.pack(pady=5)

def decode():
    clear_all_widgets()

    label = tk.Label(root, text="Binary kodunu girin:", font=("Arial", 12, "bold"), fg="white", bg=BG_COLOR)
    label.pack(pady=5)

    entry = tk.Entry(root, width=40, font=("Arial", 12))
    entry.pack(pady=5)

    def convert():
        try:
            show_result(''.join(chr(int(b, 2)) for b in entry.get().split()))
        except ValueError:
            messagebox.showerror("Hata", "Geçersiz binary kodu!")

    convert_button = tk.Button(root, text="Çöz", command=convert, bg=BUTTON_COLOR_2, fg="white", font=("Arial", 10, "bold"))
    convert_button.pack(pady=5)


#sezar
def sezar_main_buttons():
    
    clear_all_widgets()
    label_sez = tk.Label(root, text="Sezar İşlemleri: ", font=("Arial", 12, "bold"), fg="white", bg=BG_COLOR)
    label_sez.pack(pady=5)
    
    encode_button = tk.Button(root, text="Encode",command=sezar_encode , width=20, height=2, 
                              bg=BUTTON_COLOR_1, fg="white", font=("Arial", 12, "bold"))
    encode_button.pack(pady=10)    

    decode_button = tk.Button(root, text="Decode",command=sezar_decode, width=20, height=2, 
                              bg=BUTTON_COLOR_2, fg="white", font=("Arial", 12, "bold"))
    decode_button.pack(pady=10)
    
    back_button = tk.Button(root, text="Ana Menüye Dön", command=main_buttons, 
                            bg=BUTTON_COLOR_4, fg="white", font=("Arial", 10, "bold"))
    back_button.pack(pady=5)
    
def sezar_encode():
    clear_all_widgets()
        
    label = tk.Label(root, text="Metin girin:", font=("Arial", 12, "bold"), fg="white", bg=BG_COLOR)
    label.pack(pady=5)
    entry = tk.Entry(root, width=40, font=("Arial", 12))
    entry.pack(pady=5)
        
    key_label = tk.Label(root, text="Anahtar değerini girin(sadece sayı girilebilir):", font=("Arial", 12, "bold"), fg="white", bg=BG_COLOR)
    key_label.pack(pady=5)
    key_entry = tk.Entry(root, width=40, font=("Arial", 12))
    key_entry.pack(pady=5)
        
    def convert():
        sifrelenecek_metin = entry.get()
        anahtar = key_entry.get()

        if not sifrelenecek_metin:
            messagebox.showerror("Hata", "Lütfen geçerli bir metin girin!")
            return

        if not anahtar.isdigit():
            messagebox.showerror("Hata", "Anahtar sadece sayı olmalıdır!")
            return

        anahtar = int(anahtar)  # Anahtarı integer'a çeviriyoruz

        sifrelenmis_metin = ''.join(chr(ord(i) + anahtar) for i in sifrelenecek_metin)
        show_result(sifrelenmis_metin)

    convert_button = tk.Button(root, text="Dönüştür", command=convert, bg=BUTTON_COLOR_2, fg="white", font=("Arial", 10, "bold"))
    convert_button.pack(pady=5)

    back_button = tk.Button(root, text="Ana Menüye Dön", command=main_buttons, bg=BUTTON_COLOR_4, fg="white", font=("Arial", 10, "bold"))
    back_button.pack(pady=5)


def sezar_decode():
    clear_all_widgets()

    label = tk.Label(root, text="Şifreli metni girin:", font=("Arial", 12, "bold"), fg="white", bg=BG_COLOR)
    label.pack(pady=5)
    entry = tk.Entry(root, width=40, font=("Arial", 12))
    entry.pack(pady=5)

    key_label = tk.Label(root, text="Anahtar değerini girin (sadece sayı girilebilir):", font=("Arial", 12, "bold"), fg="white", bg=BG_COLOR)
    key_label.pack(pady=5)
    key_entry = tk.Entry(root, width=40, font=("Arial", 12))
    key_entry.pack(pady=5)

    def convert():
        sifreli_metin = entry.get()
        anahtar = key_entry.get()
        
        if not sifreli_metin:
            messagebox.showerror("Hata", "Lütfen geçerli bir metin girin!")
            return

        if not anahtar.isdigit():
            messagebox.showerror("Hata", "Anahtar değeri sayı olmalıdır!")
            return

        anahtar = int(anahtar)
        cozulmus_metin = ''.join(chr(ord(char) - anahtar) for char in sifreli_metin)
        show_result(cozulmus_metin)

    convert_button = tk.Button(root, text="Çöz", command=convert, bg=BUTTON_COLOR_2, fg="white", font=("Arial", 10, "bold"))
    convert_button.pack(pady=5)

    back_button = tk.Button(root, text="Ana Menüye Dön", command=main_buttons, bg=BUTTON_COLOR_4, fg="white", font=("Arial", 10, "bold"))
    back_button.pack(pady=5)

#morse
def morse_main_button():
    clear_all_widgets()
    
    label_morse = tk.Label(root, text="Morse İşlemleri:", font=("Arial", 12, "bold"), fg="white", bg=BG_COLOR)
    label_morse.pack(pady=5)
    
    encode_button = tk.Button(root, text="Encode",command=morse_encode, width=20, height=2, 
                              bg=BUTTON_COLOR_1, fg="white", font=("Arial", 12, "bold"))
    encode_button.pack(pady=10)

    decode_button = tk.Button(root, text="Decode", width=20, height=2,command=morse_decode,
                              bg=BUTTON_COLOR_2, fg="white", font=("Arial", 12, "bold"))
    decode_button.pack(pady=10)

    back_button = tk.Button(root, text="Ana Menüye Dön", command=main_buttons, 
                            bg=BUTTON_COLOR_4, fg="white", font=("Arial", 10, "bold"))
    back_button.pack(pady=5)
    
def morse_encode():
    clear_all_widgets()    
    
    label = tk.Label(root, text="Metni girin:", font=("Arial", 12, "bold"), fg="white", bg=BG_COLOR)
    label.pack(pady=5)

    entry = tk.Entry(root, width=40, font=("Arial", 12))
    entry.pack(pady=5)
    
    message = entry.get()

    def convert():
        text =entry.get()
        if text:
            message = text
            morse_code = {
                'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.', 'F': '..-.', 'G': '--.', 'H': '....',
                'I': '..', 'J': '.---', 'K': '-.-', 'L': '.-..', 'M': '--', 'N': '-.', 'O': '---', 'P': '.--.',
                'Q': '--.-', 'R': '.-.', 'S': '...', 'T': '-', 'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-',
                'Y': '-.--', 'Z': '--..', '0': '-----', '1': '.----', '2': '..---', '3': '...--', '4': '....-',
                '5': '.....', '6': '-....', '7': '--...', '8': '---..', '9': '----.'
            }

            encoded_message = []
            for char in message.upper():
                if char in morse_code:
                    encoded_message.append(morse_code[char])
            show_result(' '.join(encoded_message))
        
        else:
            messagebox.showerror("Hata", "Lütfen geçerli bir metin girin!")
    
    convert_button = tk.Button(root, text="Dönüştür", command=convert, bg=BUTTON_COLOR_2, fg="white", font=("Arial", 10, "bold"))
    convert_button.pack(pady=5)
    
    back_button = tk.Button(root, text="Ana Menüye Dön", command=main_buttons, bg=BUTTON_COLOR_4, fg="white", font=("Arial", 10, "bold"))
    back_button.pack(pady=5)

    

def morse_decode():
    clear_all_widgets()    
    
    label = tk.Label(root, text="Metni girin:", font=("Arial", 12, "bold"), fg="white", bg=BG_COLOR)
    label.pack(pady=5)

    entry = tk.Entry(root, width=40, font=("Arial", 12))
    entry.pack(pady=5)
    

    def convert():
        text =entry.get()
        
        if text:
            message = text
            morse_code = {
            '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E', '..-.': 'F', '--.': 'G', '....': 'H',
            '..': 'I', '.---': 'J', '-.-': 'K', '.-..': 'L', '--': 'M', '-.': 'N', '---': 'O', '.--.': 'P',
            '--.-': 'Q', '.-.': 'R', '...': 'S', '-': 'T', '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X',
            '-.--': 'Y', '--..': 'Z', '-----': '0', '.----': '1', '..---': '2', '...--': '3', '....-': '4',
            '.....': '5', '-....': '6', '--...': '7', '---..': '8', '----.': '9'
            }

            morse_list = message.split(' ')
            decoded_message = ''
            for morse_char in morse_list:
                if morse_char in morse_code:
                    decoded_message += morse_code[morse_char]
            show_result(decoded_message)        
        
        else:
            messagebox.showerror("Hata", "Lütfen geçerli bir metin girin!")
    
    convert_button = tk.Button(root, text="Dönüştür", command=convert, bg=BUTTON_COLOR_2, fg="white", font=("Arial", 10, "bold"))
    convert_button.pack(pady=5)
    
    back_button = tk.Button(root, text="Ana Menüye Dön", command=main_buttons, bg=BUTTON_COLOR_4, fg="white", font=("Arial", 10, "bold"))
    back_button.pack(pady=5)

     

def base64_main_buttons():
    
    clear_all_widgets()
    
    label_bin = tk.Label(root, text="Base64 İşlemleri:", font=("Arial", 12, "bold"), fg="white", bg=BG_COLOR)
    label_bin.pack(pady=5)

    encode_button = tk.Button(root, text="Encode",command=base64_encode, width=20, height=2, 
                              bg=BUTTON_COLOR_1, fg="white", font=("Arial", 12, "bold"))
    encode_button.pack(pady=10)

    decode_button = tk.Button(root, text="Decode", command=base64_decode, width=20, height=2, 
                              bg=BUTTON_COLOR_2, fg="white", font=("Arial", 12, "bold"))
    decode_button.pack(pady=10)

    back_button = tk.Button(root, text="Ana Menüye Dön", command=main_buttons, 
                            bg=BUTTON_COLOR_4, fg="white", font=("Arial", 10, "bold"))
    back_button.pack(pady=5)

    

def base64_encode():
    clear_all_widgets()
    
    label = tk.Label(root, text="Metni girin:", font=("Arial", 12, "bold"), fg="white", bg=BG_COLOR)
    label.pack(pady=5)

    entry = tk.Entry(root, width=40, font=("Arial", 12))
    entry.pack(pady=5)

    def convert():
        text = entry.get()
        if text:
            encoded_bytes = base64.b64encode(text.encode('utf-8'))
            show_result(encoded_bytes.decode('utf-8'))

        else:
            messagebox.showerror("Hata", "Lütfen Geçerli bir metin girin!")

    convert_button = tk.Button(root, text="Dönüştür", command=convert, bg=BUTTON_COLOR_2, fg="white", font=("Arial", 10, "bold"))
    convert_button.pack(pady=5)

    back_button = tk.Button(root, text="Ana Menüye Dön", command=main_buttons, bg=BUTTON_COLOR_4, fg="white", font=("Arial", 10, "bold"))
    back_button.pack(pady=5)

    
def base64_decode():
    clear_all_widgets()

    label = tk.Label(root, text="Base64 kodunu girin:", font=("Arial", 12, "bold"), fg="white", bg=BG_COLOR)
    label.pack(pady=5)

    entry = tk.Entry(root, width=40, font=("Arial", 12))
    entry.pack(pady=5)

    def convert():
        text = entry.get()
        try:
            decoded_bytes = base64.b64decode(text.encode('utf-8'))
            show_result(decoded_bytes.decode('utf-8'))
            
        except ValueError:
            messagebox.showerror("Hata", "Geçersiz hexadecimal kodu!")

    convert_button = tk.Button(root, text="Çöz", command=convert, bg=BUTTON_COLOR_2, fg="white", font=("Arial", 10, "bold"))
    convert_button.pack(pady=5)

    back_button = tk.Button(root, text="Ana Menüye Dön", command=main_buttons, bg=BUTTON_COLOR_4, fg="white", font=("Arial", 10, "bold"))
    back_button.pack(pady=5)

    
def xor_main_buttons():
    clear_all_widgets()

    label_xor = tk.Label(root, text="Xor İşlemleri:", font=("Arial", 12, "bold"), fg="white", bg=BG_COLOR)
    label_xor.pack(pady=5)

    xor_encode_button = tk.Button(root, text="Xor Encode", command=xor_encode, width=20, height=2, 
                                  bg=BUTTON_COLOR_1, fg="white", font=("Arial", 12, "bold"))
    xor_encode_button.pack(pady=10)

    xor_decode_button = tk.Button(root, text="Xor Decode", command=xor_decode, width=20, height=2, 
                                  bg=BUTTON_COLOR_2, fg="white", font=("Arial", 12, "bold"))
    xor_decode_button.pack(pady=10)

    back_button = tk.Button(root, text="Ana Menüye Dön", command=main_buttons, 
                            bg=BUTTON_COLOR_4, fg="white", font=("Arial", 10, "bold"))
    back_button.pack(pady=5)
    
def xor_encode():
    clear_all_widgets()
    
    label = tk.Label(root, text=" Metni girin:", font=("Arial", 12, "bold"), fg="white", bg=BG_COLOR)
    label.pack(pady=5)
    entry = tk.Entry(root, width=40, font=("Arial", 12))
    entry.pack(pady=5)

    key_label = tk.Label(root, text="Anahtar değerini girin (sayı ve string değeri girilebilir):", font=("Arial", 12, "bold"), fg="white", bg=BG_COLOR)
    key_label.pack(pady=5)
    key_entry = tk.Entry(root, width=40, font=("Arial", 12))
    key_entry.pack(pady=5)

    def convert():
        sifrelenecek_metin = entry.get()
        key = key_entry.get()
        
        if not sifrelenecek_metin:
            messagebox.showerror("Hata", "Lütfen geçerli bir metin girin!")
            return
        
        if not key:
            messagebox.showerror("Hata", "Lütfen bir anahtar girin!")
            return

        # XOR şifreleme işlemi
        encrypted_message = ""
        for i in range(len(sifrelenecek_metin)):
            encrypted_message += chr(ord(sifrelenecek_metin[i]) ^ ord(key[i % len(key)]))

        show_result(encrypted_message)
        
    convert_button = tk.Button(root, text="Dönüştür", command=convert, bg=BUTTON_COLOR_2, fg="white", font=("Arial", 10, "bold"))
    convert_button.pack(pady=5)
    
    back_button = tk.Button(root, text="Ana Menüye Dön", command=main_buttons, bg=BUTTON_COLOR_4, fg="white", font=("Arial", 10, "bold"))
    back_button.pack(pady=5)

def xor_decode():
    clear_all_widgets()
    
    label = tk.Label(root, text="Şifreli metni girin:", font=("Arial", 12, "bold"), fg="white", bg=BG_COLOR)
    label.pack(pady=5)
    entry = tk.Entry(root, width=40, font=("Arial", 12))
    entry.pack(pady=5)

    key_label = tk.Label(root, text="Anahtar değerini girin (sayı ve string değeri girilebilir):", font=("Arial", 12, "bold"), fg="white", bg=BG_COLOR)
    key_label.pack(pady=5)
    key_entry = tk.Entry(root, width=40, font=("Arial", 12))
    key_entry.pack(pady=5)

    def convert():
        sifreli_metin = entry.get()
        key = key_entry.get()
        
        if not sifreli_metin:
            messagebox.showerror("Hata", "Lütfen geçerli bir şifreli metin girin!")
            return
        
        if not key:
            messagebox.showerror("Hata", "Lütfen bir anahtar girin!")
            return

        # XOR çözme işlemi
        decrypted_message = ""
        for i in range(len(sifreli_metin)):
            decrypted_message += chr(ord(sifreli_metin[i]) ^ ord(key[i % len(key)]))

        # Çözülen metni göster
        show_result(decrypted_message)
        
    convert_button = tk.Button(root, text="Çöz", command=convert, bg=BUTTON_COLOR_2, fg="white", font=("Arial", 10, "bold"))
    convert_button.pack(pady=5)
    
    back_button = tk.Button(root, text="Ana Menüye Dön", command=main_buttons, bg=BUTTON_COLOR_4, fg="white", font=("Arial", 10, "bold"))
    back_button.pack(pady=5)



def rot47_main_buttons():
    clear_all_widgets()

    label_xor = tk.Label(root, text= "Rot-47 İşlemleri:", font=("Arial", 12, "bold"), fg="white", bg=BG_COLOR)
    label_xor.pack(pady=5)

    rot47_encode_button = tk.Button(root, text="Encode",command=rot47_encode , width=20, height=2, 
                                  bg=BUTTON_COLOR_1, fg="white", font=("Arial", 12, "bold"))
    rot47_encode_button.pack(pady=10)

    rot47_decode_button = tk.Button(root, text="Decode",command=rot47_decode, width=20, height=2, 
                                  bg=BUTTON_COLOR_2, fg="white", font=("Arial", 12, "bold"))
    rot47_decode_button.pack(pady=10)

    back_button = tk.Button(root, text="Ana Menüye Dön", command=main_buttons, 
                            bg=BUTTON_COLOR_4, fg="white", font=("Arial", 10, "bold"))
    back_button.pack(pady=5)




def rot47_encode():
    clear_all_widgets()
    
    label = tk.Label(root, text="Metni girin:", font=("Arial", 12, "bold"), fg="white", bg=BG_COLOR)
    label.pack(pady=5)
    entry = tk.Entry(root, width=40, font=("Arial", 12))
    entry.pack(pady=5)

    def convert():
        metin = entry.get()
        
        if not metin:
            messagebox.showerror("Hata", "Lütfen geçerli bir metin girin!")
            return

        # ROT-47 şifreleme işlemi
        encrypted_message = "".join(
            chr(33 + ((ord(c) - 33 + 47) % 94)) if 33 <= ord(c) <= 126 else c for c in metin
        )

        # Şifrelenmiş metni göster
        show_result(encrypted_message)
        
    convert_button = tk.Button(root, text="Şifrele", command=convert, bg=BUTTON_COLOR_2, fg="white", font=("Arial", 10, "bold"))
    convert_button.pack(pady=5)
    
    back_button = tk.Button(root, text="Ana Menüye Dön", command=main_buttons, bg=BUTTON_COLOR_4, fg="white", font=("Arial", 10, "bold"))
    back_button.pack(pady=5)

def rot47_decode():
    clear_all_widgets()
    
    label = tk.Label(root, text="Şifreli metni girin:", font=("Arial", 12, "bold"), fg="white", bg=BG_COLOR)
    label.pack(pady=5)
    entry = tk.Entry(root, width=40, font=("Arial", 12))
    entry.pack(pady=5)

    def convert():
        sifreli_metin = entry.get()
        
        if not sifreli_metin:
            messagebox.showerror("Hata", "Lütfen geçerli bir şifreli metin girin!")
            return

        # ROT-47 çözme işlemi (şifreleme ile aynı işlem)
        decrypted_message = "".join(
            chr(33 + ((ord(c) - 33 + 47) % 94)) if 33 <= ord(c) <= 126 else c for c in sifreli_metin
        )

        # Çözülen metni göster
        show_result(decrypted_message)
        
    convert_button = tk.Button(root, text="Çöz", command=convert, bg=BUTTON_COLOR_2, fg="white", font=("Arial", 10, "bold"))
    convert_button.pack(pady=5)
    
    back_button = tk.Button(root, text="Ana Menüye Dön", command=main_buttons, bg=BUTTON_COLOR_4, fg="white", font=("Arial", 10, "bold"))
    back_button.pack(pady=5)


def rot5_main_buttons():
    clear_all_widgets()

    label_rot = tk.Label(root, text= "Rot-5 İşlemleri:", font=("Arial", 12, "bold"), fg="white", bg=BG_COLOR)
    label_rot.pack(pady=5)

    rot5_encode_button = tk.Button(root, text="Encode",command=rot5_encode , width=20, height=2, 
                                  bg=BUTTON_COLOR_1, fg="white", font=("Arial", 12, "bold"))
    rot5_encode_button.pack(pady=10)

    rot5_decode_button = tk.Button(root, text="Decode",command=rot5_decode, width=20, height=2, 
                                  bg=BUTTON_COLOR_2, fg="white", font=("Arial", 12, "bold"))
    rot5_decode_button.pack(pady=10)

    back_button = tk.Button(root, text="Ana Menüye Dön", command=main_buttons, 
                            bg=BUTTON_COLOR_4, fg="white", font=("Arial", 10, "bold"))
    back_button.pack(pady=5)



def rot5_encode():
    clear_all_widgets()
    
    label = tk.Label(root, text="Sayısal(int) metni girin:", font=("Arial", 12, "bold"), fg="white", bg=BG_COLOR)
    label.pack(pady=5)
    entry = tk.Entry(root, width=40, font=("Arial", 12))
    entry.pack(pady=5)

    def convert():
        metin = entry.get()
        
        if not metin.isdigit():
            messagebox.showerror("Hata", "Lütfen sadece rakam içeren bir metin girin!")
            return

        # ROT-5 şifreleme işlemi
        encrypted_message = "".join(
            chr(((ord(c) - ord('0') + 5) % 10) + ord('0')) if '0' <= c <= '9' else c for c in metin
        )

        # Şifrelenmiş metni göster
        show_result(encrypted_message)
        
    convert_button = tk.Button(root, text="Şifrele", command=convert, bg=BUTTON_COLOR_2, fg="white", font=("Arial", 10, "bold"))
    convert_button.pack(pady=5)
    
    back_button = tk.Button(root, text="Ana Menüye Dön", command=main_buttons, bg=BUTTON_COLOR_4, fg="white", font=("Arial", 10, "bold"))
    back_button.pack(pady=5)

def rot5_decode():
    clear_all_widgets()
    
    label = tk.Label(root, text="Şifreli sayısal metni girin:", font=("Arial", 12, "bold"), fg="white", bg=BG_COLOR)
    label.pack(pady=5)
    entry = tk.Entry(root, width=40, font=("Arial", 12))
    entry.pack(pady=5)

    def convert():
        sifreli_metin = entry.get()
        
        if not sifreli_metin.isdigit():
            messagebox.showerror("Hata", "Lütfen sadece rakam içeren bir şifreli metin girin!")
            return

        # ROT-5 çözme işlemi (şifreleme ile aynı işlem)
        decrypted_message = "".join(
            chr(((ord(c) - ord('0') + 5) % 10) + ord('0')) if '0' <= c <= '9' else c for c in sifreli_metin
        )

        # Çözülen metni göster
        show_result(decrypted_message)
        
    convert_button = tk.Button(root, text="Çöz", command=convert, bg=BUTTON_COLOR_2, fg="white", font=("Arial", 10, "bold"))
    convert_button.pack(pady=5)
    
    back_button = tk.Button(root, text="Ana Menüye Dön", command=main_buttons, bg=BUTTON_COLOR_4, fg="white", font=("Arial", 10, "bold"))
    back_button.pack(pady=5)




def railfence_main_buttons():
    clear_all_widgets()

    label_rail = tk.Label(root, text= "Rail Fence İşlemleri:", font=("Arial", 12, "bold"), fg="white", bg=BG_COLOR)
    label_rail.pack(pady=5)

    rail_encode_button = tk.Button(root, text="Encode",command=rail_fence_encode , width=20, height=2, 
                                  bg=BUTTON_COLOR_1, fg="white", font=("Arial", 12, "bold"))
    rail_encode_button.pack(pady=10)

    rail_decode_button = tk.Button(root, text="Decode",command=rail_fence_decode, width=20, height=2, 
                                  bg=BUTTON_COLOR_2, fg="white", font=("Arial", 12, "bold"))
    rail_decode_button.pack(pady=10)

    back_button = tk.Button(root, text="Ana Menüye Dön", command=main_buttons, 
                            bg=BUTTON_COLOR_4, fg="white", font=("Arial", 10, "bold"))
    back_button.pack(pady=5)




def rail_fence_encode():
    clear_all_widgets()
    
    label = tk.Label(root, text="Metni girin:", font=("Arial", 12, "bold"), fg="white", bg=BG_COLOR)
    label.pack(pady=5)
    entry = tk.Entry(root, width=40, font=("Arial", 12))
    entry.pack(pady=5)

    rail_label = tk.Label(root, text="Ray sayısını girin:", font=("Arial", 12, "bold"), fg="white", bg=BG_COLOR)
    rail_label.pack(pady=5)
    rail_entry = tk.Entry(root, width=10, font=("Arial", 12))
    rail_entry.pack(pady=5)

    def convert():
        metin = entry.get()
        try:
            rails = int(rail_entry.get())
            if rails < 2:
                raise ValueError
        except ValueError:
            messagebox.showerror("Hata", "Lütfen geçerli bir ray sayısı girin (en az 2)!")
            return
        
        rail_fence = ["" for _ in range(rails)]
        index, step = 0, 1
        
        for char in metin:
            rail_fence[index] += char
            if index == 0:
                step = 1
            elif index == rails - 1:
                step = -1
            index += step
        
        encrypted_message = "".join(rail_fence)
        show_result(encrypted_message)
        
    convert_button = tk.Button(root, text="Şifrele", command=convert, bg=BUTTON_COLOR_2, fg="white", font=("Arial", 10, "bold"))
    convert_button.pack(pady=5)
    
    back_button = tk.Button(root, text="Ana Menüye Dön", command=main_buttons, bg=BUTTON_COLOR_4, fg="white", font=("Arial", 10, "bold"))
    back_button.pack(pady=5)

def rail_fence_decode():
    clear_all_widgets()
    
    label = tk.Label(root, text="Şifreli metni girin:", font=("Arial", 12, "bold"), fg="white", bg=BG_COLOR)
    label.pack(pady=5)
    entry = tk.Entry(root, width=40, font=("Arial", 12))
    entry.pack(pady=5)

    rail_label = tk.Label(root, text="Ray sayısını girin:", font=("Arial", 12, "bold"), fg="white", bg=BG_COLOR)
    rail_label.pack(pady=5)
    rail_entry = tk.Entry(root, width=10, font=("Arial", 12))
    rail_entry.pack(pady=5)

    def convert():
        sifreli_metin = entry.get()
        try:
            rails = int(rail_entry.get())
            if rails < 2:
                raise ValueError
        except ValueError:
            messagebox.showerror("Hata", "Lütfen geçerli bir ray sayısı girin (en az 2)!")
            return
        
        rail_pattern = [0] * len(sifreli_metin)
        index, step = 0, 1
        
        for i in range(len(sifreli_metin)):
            rail_pattern[i] = index
            if index == 0:
                step = 1
            elif index == rails - 1:
                step = -1
            index += step
        
        rail_fence = ["" for _ in range(rails)]
        pos = 0
        
        for r in range(rails):
            for i in range(len(sifreli_metin)):
                if rail_pattern[i] == r:
                    rail_fence[r] += sifreli_metin[pos]
                    pos += 1
        
        result = ["" for _ in range(len(sifreli_metin))]
        index = 0
        
        for i in range(len(sifreli_metin)):
            result[i] = rail_fence[rail_pattern[i]][0]
            rail_fence[rail_pattern[i]] = rail_fence[rail_pattern[i]][1:]
        
        decrypted_message = "".join(result)
        show_result(decrypted_message)
        
    convert_button = tk.Button(root, text="Çöz", command=convert, bg=BUTTON_COLOR_2, fg="white", font=("Arial", 10, "bold"))
    convert_button.pack(pady=5)
    
    back_button = tk.Button(root, text="Ana Menüye Dön", command=main_buttons, bg=BUTTON_COLOR_4, fg="white", font=("Arial", 10, "bold"))
    back_button.pack(pady=5)



def atbash_main_buttons():
    
    clear_all_widgets()
    
    label_bin = tk.Label(root, text="Atbash İşlemleri:", font=("Arial", 12, "bold"), fg="white", bg=BG_COLOR)
    label_bin.pack(pady=5)

    encode_button = tk.Button(root, text="Encode",command=atbash_encode, width=20, height=2, 
                              bg=BUTTON_COLOR_1, fg="white", font=("Arial", 12, "bold"))
    encode_button.pack(pady=10)

    decode_button = tk.Button(root, text="Decode", command=atbash_decode, width=20, height=2, 
                              bg=BUTTON_COLOR_2, fg="white", font=("Arial", 12, "bold"))
    decode_button.pack(pady=10)

    back_button = tk.Button(root, text="Ana Menüye Dön", command=main_buttons, 
                            bg=BUTTON_COLOR_4, fg="white", font=("Arial", 10, "bold"))
    back_button.pack(pady=5)

    

def atbash_encode():
    clear_all_widgets()
    
    label = tk.Label(root, text="Metni girin:", font=("Arial", 12, "bold"), fg="white", bg=BG_COLOR)
    label.pack(pady=5)
    entry = tk.Entry(root, width=40, font=("Arial", 12))
    entry.pack(pady=5)

    def convert():
        metin = entry.get()
        
        if not metin:
            messagebox.showerror("Hata", "Lütfen geçerli bir metin girin!")
            return
        
        encrypted_message = "".join(
            chr(155 - ord(char)) if 'A' <= char <= 'Z' else chr(219 - ord(char)) if 'a' <= char <= 'z' else char
            for char in metin
        )
        
        show_result(encrypted_message)
        
    convert_button = tk.Button(root, text="Şifrele", command=convert, bg=BUTTON_COLOR_2, fg="white", font=("Arial", 10, "bold"))
    convert_button.pack(pady=5)
    
    back_button = tk.Button(root, text="Ana Menüye Dön", command=main_buttons, bg=BUTTON_COLOR_4, fg="white", font=("Arial", 10, "bold"))
    back_button.pack(pady=5)

def atbash_decode():
    clear_all_widgets()
    
    label = tk.Label(root, text="Şifreli metni girin:", font=("Arial", 12, "bold"), fg="white", bg=BG_COLOR)
    label.pack(pady=5)
    entry = tk.Entry(root, width=40, font=("Arial", 12))
    entry.pack(pady=5)

    def convert():
        sifreli_metin = entry.get()
        
        if not sifreli_metin:
            messagebox.showerror("Hata", "Lütfen geçerli bir şifreli metin girin!")
            return
        
        decrypted_message = "".join(
            chr(155 - ord(char)) if 'A' <= char <= 'Z' else chr(219 - ord(char)) if 'a' <= char <= 'z' else char
            for char in sifreli_metin
        )
        
        show_result(decrypted_message)
        
    convert_button = tk.Button(root, text="Çöz", command=convert, bg=BUTTON_COLOR_2, fg="white", font=("Arial", 10, "bold"))
    convert_button.pack(pady=5)
    
    back_button = tk.Button(root, text="Ana Menüye Dön", command=main_buttons, bg=BUTTON_COLOR_4, fg="white", font=("Arial", 10, "bold"))
    back_button.pack(pady=5)



def reverse_main_buttons():
    
    clear_all_widgets()
    
    label_bin = tk.Label(root, text="Reverse İşlemleri:", font=("Arial", 12, "bold"), fg="white", bg=BG_COLOR)
    label_bin.pack(pady=5)

    encode_button = tk.Button(root, text="Encode",command=reverse_encode, width=20, height=2, 
                              bg=BUTTON_COLOR_1, fg="white", font=("Arial", 12, "bold"))
    encode_button.pack(pady=10)

    decode_button = tk.Button(root, text="Decode", command=reverse_decode, width=20, height=2, 
                              bg=BUTTON_COLOR_2, fg="white", font=("Arial", 12, "bold"))
    decode_button.pack(pady=10)

    back_button = tk.Button(root, text="Ana Menüye Dön", command=main_buttons, 
                            bg=BUTTON_COLOR_4, fg="white", font=("Arial", 10, "bold"))
    back_button.pack(pady=5)




def reverse_encode():
    clear_all_widgets()
    
    label = tk.Label(root, text="Metni girin:", font=("Arial", 12, "bold"), fg="white", bg=BG_COLOR)
    label.pack(pady=5)
    entry = tk.Entry(root, width=40, font=("Arial", 12))
    entry.pack(pady=5)

    def convert():
        metin = entry.get()
        
        if not metin:
            messagebox.showerror("Hata", "Lütfen geçerli bir metin girin!")
            return
        
        encrypted_message = metin[::-1]
        
        show_result(encrypted_message)
        
    convert_button = tk.Button(root, text="Şifrele", command=convert, bg=BUTTON_COLOR_2, fg="white", font=("Arial", 10, "bold"))
    convert_button.pack(pady=5)
    
    back_button = tk.Button(root, text="Ana Menüye Dön", command=main_buttons, bg=BUTTON_COLOR_4, fg="white", font=("Arial", 10, "bold"))
    back_button.pack(pady=5)

def reverse_decode():
    clear_all_widgets()
    
    label = tk.Label(root, text="Şifreli metni girin:", font=("Arial", 12, "bold"), fg="white", bg=BG_COLOR)
    label.pack(pady=5)
    entry = tk.Entry(root, width=40, font=("Arial", 12))
    entry.pack(pady=5)

    def convert():
        sifreli_metin = entry.get()
        
        if not sifreli_metin:
            messagebox.showerror("Hata", "Lütfen geçerli bir şifreli metin girin!")
            return
        
        decrypted_message = sifreli_metin[::-1]
        
        show_result(decrypted_message)
        
    convert_button = tk.Button(root, text="Çöz", command=convert, bg=BUTTON_COLOR_2, fg="white", font=("Arial", 10, "bold"))
    convert_button.pack(pady=5)
    
    back_button = tk.Button(root, text="Ana Menüye Dön", command=main_buttons, bg=BUTTON_COLOR_4, fg="white", font=("Arial", 10, "bold"))
    back_button.pack(pady=5)




def vigenere_main_buttons():
    
    clear_all_widgets()
    
    label_bin = tk.Label(root, text="Vigenère İşlemleri:", font=("Arial", 12, "bold"), fg="white", bg=BG_COLOR)
    label_bin.pack(pady=5)

    encode_button = tk.Button(root, text="Encode",command=vigenere_encode, width=20, height=2, 
                              bg=BUTTON_COLOR_1, fg="white", font=("Arial", 12, "bold"))
    encode_button.pack(pady=10)

    decode_button = tk.Button(root, text="Decode", command=vigenere_decode, width=20, height=2, 
                              bg=BUTTON_COLOR_2, fg="white", font=("Arial", 12, "bold"))
    decode_button.pack(pady=10)

    back_button = tk.Button(root, text="Ana Menüye Dön", command=main_buttons, 
                            bg=BUTTON_COLOR_4, fg="white", font=("Arial", 10, "bold"))
    back_button.pack(pady=5)







def vigenere_encode():
    clear_all_widgets()
    
    label = tk.Label(root, text="Metni girin:", font=("Arial", 12, "bold"), fg="white", bg=BG_COLOR)
    label.pack(pady=5)
    entry = tk.Entry(root, width=40, font=("Arial", 12))
    entry.pack(pady=5)
    
    key_label = tk.Label(root, text="Anahtar kelimeyi girin:", font=("Arial", 12, "bold"), fg="white", bg=BG_COLOR)
    key_label.pack(pady=5)
    key_entry = tk.Entry(root, width=40, font=("Arial", 12))
    key_entry.pack(pady=5)
    
    def convert():
        metin = entry.get()
        key = key_entry.get()
        
        if not metin or not key:
            messagebox.showerror("Hata", "Lütfen geçerli bir metin ve anahtar girin!")
            return
        
        encrypted_message = ""
        key_length = len(key)
        
        for i, char in enumerate(metin):
            if char.isalpha():
                shift = ord(key[i % key_length].lower()) - ord('a')
                if char.islower():
                    encrypted_message += chr((ord(char) - ord('a') + shift) % 26 + ord('a'))
                else:
                    encrypted_message += chr((ord(char) - ord('A') + shift) % 26 + ord('A'))
            else:
                encrypted_message += char
        
        show_result(encrypted_message)
        
    convert_button = tk.Button(root, text="Şifrele", command=convert, bg=BUTTON_COLOR_2, fg="white", font=("Arial", 10, "bold"))
    convert_button.pack(pady=5)
    
    back_button = tk.Button(root, text="Ana Menüye Dön", command=main_buttons, bg=BUTTON_COLOR_4, fg="white", font=("Arial", 10, "bold"))
    back_button.pack(pady=5)

def vigenere_decode():
    clear_all_widgets()
    
    label = tk.Label(root, text="Şifreli metni girin:", font=("Arial", 12, "bold"), fg="white", bg=BG_COLOR)
    label.pack(pady=5)
    entry = tk.Entry(root, width=40, font=("Arial", 12))
    entry.pack(pady=5)
    
    key_label = tk.Label(root, text="Anahtar kelimeyi girin:", font=("Arial", 12, "bold"), fg="white", bg=BG_COLOR)
    key_label.pack(pady=5)
    key_entry = tk.Entry(root, width=40, font=("Arial", 12))
    key_entry.pack(pady=5)
    
    def convert():
        sifreli_metin = entry.get()
        key = key_entry.get()
        
        if not sifreli_metin or not key:
            messagebox.showerror("Hata", "Lütfen geçerli bir şifreli metin ve anahtar girin!")
            return
        
        decrypted_message = ""
        key_length = len(key)
        
        for i, char in enumerate(sifreli_metin):
            if char.isalpha():
                shift = ord(key[i % key_length].lower()) - ord('a')
                if char.islower():
                    decrypted_message += chr((ord(char) - ord('a') - shift) % 26 + ord('a'))
                else:
                    decrypted_message += chr((ord(char) - ord('A') - shift) % 26 + ord('A'))
            else:
                decrypted_message += char
        
        show_result(decrypted_message)
        
    convert_button = tk.Button(root, text="Çöz", command=convert, bg=BUTTON_COLOR_2, fg="white", font=("Arial", 10, "bold"))
    convert_button.pack(pady=5)
    
    back_button = tk.Button(root, text="Ana Menüye Dön", command=main_buttons, bg=BUTTON_COLOR_4, fg="white", font=("Arial", 10, "bold"))
    back_button.pack(pady=5)




main_buttons()
root.mainloop()
