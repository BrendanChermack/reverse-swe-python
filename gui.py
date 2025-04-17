import json
import tkinter as tk
from tkinter import scrolledtext, filedialog
from mal_input import mal_uploader, sha256_input
from url_scanner import url_scanning

# ---------- helpers ----------
def select_file():
    file_path = filedialog.askopenfilename()
    if file_path:
        file_entry.delete(0, tk.END)
        file_entry.insert(0, file_path)

def clear_results():
    for w in results_frame.winfo_children():
        w.destroy()

# ---------- FILE + PASSWORD ----------
def submit_credentials():
    process_credentials(file_entry.get(), password_entry.get())

def process_credentials(file_path, password):
    clear_results()
    data    = json.loads(mal_uploader(file_path, password))
    stats   = data["data"]["attributes"]["stats"]
    results = data["data"]["attributes"]["results"]
    sh_key  = data["meta"]["file_info"].get("sha256", "N/A")

    tk.Label(results_frame, text="VirusTotal Scan Summary",
             font=("Arial", 14, "bold")).pack(anchor="center")
    tk.Label(results_frame, text=f"SHA‑256: {sh_key}",
             font=("Arial", 10, "bold")).pack(anchor="center", pady=5)

    for k in ['harmless', 'malicious', 'suspicious', 'undetected', 'failure']:
        tk.Label(results_frame, text=f"{k.capitalize()}: {stats[k]}")\
            .pack(anchor="center")

    ta = scrolledtext.ScrolledText(results_frame, wrap=tk.WORD,
                                   width=75, height=12)
    ta.pack(anchor="center", pady=10)
    ta.insert(tk.END, "Antivirus Scan Results:\n\n")
    for engine, res in results.items():
        ta.insert(tk.END, f"{engine}: {res['result']} ({res['category']})\n")
    ta.config(state=tk.DISABLED)

# ---------- SHA256 ----------
def submit_sha():
    process_sha(sha_entry.get())

def process_sha(sha):
    clear_results()
    data    = json.loads(sha256_input(sha))
    attrs   = data["data"]["attributes"]
    stats   = attrs["last_analysis_stats"]
    results = attrs["last_analysis_results"]

    tk.Label(results_frame, text="Scan Summary",
             font=("Arial", 14, "bold")).pack(anchor="center")
    tk.Label(results_frame, text=f"SHA‑256: {sha}",
             font=("Arial", 10, "bold")).pack(anchor="center", pady=5)
    tk.Label(results_frame, text=f"Names: {attrs['names']}")\
        .pack(anchor="center")
    tk.Label(results_frame, text=f"Type tags: {attrs['type_tags']}")\
        .pack(anchor="center")

    for k in ['harmless', 'malicious', 'suspicious', 'undetected', 'failure']:
        tk.Label(results_frame, text=f"{k.capitalize()}: {stats[k]}")\
            .pack(anchor="center")

    ta = scrolledtext.ScrolledText(results_frame, wrap=tk.WORD,
                                   width=75, height=12)
    ta.pack(anchor="center", pady=10)
    ta.insert(tk.END, "Antivirus Scan Results:\n\n")
    for engine, res in results.items():
        det = res.get("result", "No detection")
        cat = res.get("category", "N/A")
        ta.insert(tk.END, f"{engine}: {det} ({cat})\n")
    ta.config(state=tk.DISABLED)

# ---------- URL ----------
def submit_url():
    process_url(url_entry.get())

def process_url(url):
    clear_results()
    data  = json.loads(url_scanning(url))
    stats = data["data"]["attributes"]["stats"]

    tk.Label(results_frame, text="Scan Summary",
             font=("Arial", 14, "bold")).pack(anchor="center")
    tk.Label(results_frame, text=f"URL: {url}",
             font=("Arial", 10, "bold")).pack(anchor="center", pady=5)

    for k in ['malicious', 'suspicious', 'undetected', 'harmless', 'timeout']:
        tk.Label(results_frame, text=f"{k.capitalize()}: {stats[k]}")\
            .pack(anchor="center")

# ---------- GUI ----------
root = tk.Tk()
root.title("VirusTotal Scan Results")
root.geometry("920x720")

# Controls -------------------------------------------------
tk.Button(root, text="Select File", command=select_file).pack(pady=5)
file_entry = tk.Entry(root, width=60)
file_entry.pack(pady=5)

tk.Label(root, text="Enter Password:").pack()
password_entry = tk.Entry(root, width=60, show="*")
password_entry.pack(pady=5)
tk.Button(root, text="Submit Password", command=submit_credentials).pack(pady=5)

tk.Label(root, text="Enter SHA256:").pack()
sha_entry = tk.Entry(root, width=60)
sha_entry.pack(pady=5)
tk.Button(root, text="Submit SHA256", command=submit_sha).pack(pady=5)

tk.Label(root, text="Enter URL:").pack()
url_entry = tk.Entry(root, width=60)
url_entry.pack(pady=5)
tk.Button(root, text="Submit URL", command=submit_url).pack(pady=5)

tk.Button(root, text="Clear Results", command=clear_results).pack(pady=10)

# Frame that will hold all result widgets (centered) -------
results_frame = tk.Frame(root)
results_frame.pack(pady=5, anchor="center")   # <‑‑ centered container

root.mainloop()
