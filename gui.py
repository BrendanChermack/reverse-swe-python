import json
import tkinter as tk
from tkinter import scrolledtext, filedialog
from mal_input import mal_uploader, sha256_input
from url_scanner import url_scanning


def select_file():
    file_path = filedialog.askopenfilename()
    if file_path:
        file_entry.delete(0, tk.END)
        file_entry.insert(0, file_path)
        print("Selected file:", file_path)

def submit_credentials():
    file_path = file_entry.get()
    password = password_entry.get()
    process_credentials(file_path, password)

def process_credentials(file_path, password):
    print("File Path: ", file_path)
    print("Password: ", password)

    json_malware_data = json.loads(mal_uploader(file_path, password))
    stats = json_malware_data["data"]["attributes"]["stats"]
    results = json_malware_data["data"]["attributes"]["results"]
    sh_key = json_malware_data["meta"]["file_info"].get("sha256", "N/A")
    
    # Display stats
    tk.Label(root, text="VirusTotal Scan Summary", font=("Arial", 14, "bold")).pack()
    tk.Label(root, text=f"SH Key: {sh_key}", font=("Arial", 10, "bold")).pack(pady=5)
    tk.Label(root, text=f"Harmless: {stats['harmless']}").pack()
    tk.Label(root, text=f"Malicious: {stats['malicious']}").pack()
    tk.Label(root, text=f"Suspicious: {stats['suspicious']}").pack()
    tk.Label(root, text=f"Undetected: {stats['undetected']}").pack()
    tk.Label(root, text=f"Failures: {stats['failure']}").pack()

    # Display detailed results
    text_area = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=60, height=10)
    text_area.pack(pady=10)
    text_area.insert(tk.INSERT, "Antivirus Scan Results:\n\n")
    for engine, result in results.items():
        text_area.insert(tk.INSERT, f"{engine}: {result['result']} ({result['category']})\n")
    text_area.config(state=tk.DISABLED)  # Make text area read-only

    
    print(json_malware_data)

def submit_sha():
    sha = sha_entry.get()
    process_sha(sha)


def process_sha(sha):
    print("SHA256: ", sha)
    json_malware_data = json.loads(sha256_input(sha))
    print(json.dumps(json_malware_data, indent=4))
    sh_attributes = json_malware_data["data"]["attributes"]
    sh_stats = json_malware_data["data"]["attributes"]["last_analysis_stats"]
    sh_results = json_malware_data["data"]["attributes"]["last_analysis_results"]
    
    # Display stats
    tk.Label(root, text="VirusTotal Scan Summary", font=("Arial", 14, "bold")).pack()
    tk.Label(root, text=f"SH Key: {sha}", font=("Arial", 10, "bold")).pack(pady=5)
    tk.Label(root, text=f"Names: {sh_attributes['names']}").pack()
    tk.Label(root, text=f"Type_tags: {sh_attributes['type_tags']}").pack()
    tk.Label(root, text=f"Names: {sh_stats['harmless']}").pack()
    tk.Label(root, text=f"Malicious: {sh_stats['malicious']}").pack()
    tk.Label(root, text=f"Suspicious: {sh_stats['suspicious']}").pack()
    tk.Label(root, text=f"Undetected: {sh_stats['undetected']}").pack()
    tk.Label(root, text=f"Failures: {sh_stats['failure']}").pack()

    # Display detailed scan results in a scrolled text area
    text_area = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=60, height=10)
    text_area.pack(pady=10)
    text_area.insert(tk.INSERT, "Antivirus Scan Results:\n\n")
    
    for engine, result in sh_results.items():
        detection = result.get("result", "No detection")
        category = result.get("category", "N/A")
        text_area.insert(tk.INSERT, f"{engine}: {detection} ({category})\n")
    
    text_area.config(state=tk.DISABLED)  # Make text area read-only
    
    print(json_malware_data)

def submit_url():
    url = url_entry.get()
    process_url(url)

def process_url(url):
    print("URL:", url)
    
    # Load data
    json_malware_data = json.loads(url_scanning(url))
    print(json.dumps(json_malware_data, indent=4))
    
    # Extract stats
    url_stats = json_malware_data["data"]["attributes"]["stats"]
    
    # GUI output
    tk.Label(root, text="VirusTotal Scan Summary", font=("Arial", 14, "bold")).pack()
    tk.Label(root, text=f"URL: {url}", font=("Arial", 10, "bold")).pack(pady=5)
    tk.Label(root, text="Stats:").pack(pady=5)
    tk.Label(root, text=f"Malicious: {url_stats['malicious']}").pack()
    tk.Label(root, text=f"Suspicious: {url_stats['suspicious']}").pack()
    tk.Label(root, text=f"Undetected: {url_stats['undetected']}").pack()
    tk.Label(root, text=f"Harmless: {url_stats['harmless']}").pack()
    tk.Label(root, text=f"Timeout: {url_stats['timeout']}").pack()

    print(json_malware_data)

# Create GUI window
root = tk.Tk()
root.title("VirusTotal Scan Results")
root.geometry("900x700")

# Button to select file
select_button = tk.Button(root, text="Select File", command=select_file)
select_button.pack(pady=5)

# Entry field to display file path
file_entry = tk.Entry(root, width=50)
file_entry.pack(pady=5)

# Password entry field
tk.Label(root, text="Enter Password:").pack()
password_entry = tk.Entry(root, width=50, show="*")
password_entry.pack(pady=5)

def print_password():
    print("Entered Password:", password_entry.get())

# Submit button
password_button = tk.Button(root, text="Submit Password", command=submit_credentials)
password_button.pack(pady=5)


# SHA256 entry field
tk.Label(root, text="Enter SHA256:").pack()
sha_entry = tk.Entry(root, width=50)
sha_entry.pack(pady=5)

# Submit button
sha_button = tk.Button(root, text="Submit SHA256", command=submit_sha)
sha_button.pack(pady=5)


# SHA256 entry field
tk.Label(root, text="Enter Url:").pack()
url_entry = tk.Entry(root, width=50)
url_entry.pack(pady=5)

# Submit button
url_button = tk.Button(root, text="Submit Url", command=submit_url)
url_button.pack(pady=5)


# Run GUI
root.mainloop()
