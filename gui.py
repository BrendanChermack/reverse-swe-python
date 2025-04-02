import json
import tkinter as tk
from tkinter import filedialog, ttk

def upload_file():
    file_path = filedialog.askopenfilename()
    if file_path:
        with open(file_path, 'r') as file:
            try:
                data = json.load(file)
                display_json_data(data)
            except json.JSONDecodeError:
                label.config(text="Invalid JSON file")

def display_json_data(data):
    attributes = data.get("data", {}).get("attributes", {})
    stats = attributes.get("results", {}).get("stats", {})
    sh_key = attributes.get("id", "N/A")
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    undetected = stats.get("undetected", 0)
    
    label.config(text=f"SH Key: {sh_key}\nMalicious: {malicious}\nSuspicious: {suspicious}\nUndetected: {undetected}")

def on_button_click():
    print("Button Clicked!")

# Create the main window
root = tk.Tk()
root.title("File Upload GUI")
root.geometry("450x300")
root.configure(bg="#f0f0f0")

# Styling
style = ttk.Style()
style.configure("TButton", font=("Arial", 12), padding=10)
style.configure("TLabel", font=("Arial", 11), background="#f0f0f0")

# Upload Button
upload_btn = ttk.Button(root, text="Upload File", command=upload_file)
upload_btn.pack(pady=15)

# Label to show selected file
label = ttk.Label(root, text="No file selected", wraplength=400)
label.pack(pady=10)

# Another Button
action_btn = ttk.Button(root, text="Click Me", command=on_button_click)
action_btn.pack(pady=10)

# Run the application
root.mainloop()
