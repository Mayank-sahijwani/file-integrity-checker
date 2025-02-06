# file-integrity-checker
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import hashlib
import os
import json

# Calculate hash of a file
def calculate_hash(file_path, algorithm="sha256"):
    try:
        hash_func = hashlib.new(algorithm)
        with open(file_path, "rb") as f:
            while True:
                chunk = f.read(4096)
                if not chunk:
                    break
                hash_func.update(chunk)
        return hash_func.hexdigest()
    except Exception as e:
        messagebox.showerror("Error", f"Error calculating hash: {e}")
        return None

# Save hashes to a file
def save_hashes(hashes, filename):
    try:
        with open(filename, "w") as f:
            json.dump(hashes, f)
    except Exception as e:
        messagebox.showerror("Error", f"Error saving hashes: {e}")

# Load hashes from a file
def load_hashes(filename):
    try:
        if os.path.exists(filename):
            with open(filename, "r") as f:
                return json.load(f)
        return {}
    except Exception as e:
        messagebox.showerror("Error", f"Error loading hashes: {e}")
        return {}

# Add file to list
def add_file():
    file_path = filedialog.askopenfilename()
    if file_path and file_path not in file_list.get(0, tk.END):
        file_list.insert(tk.END, file_path)

# Remove selected file
def remove_file():
    selected_items = file_list.curselection()
    for item in reversed(selected_items):
        file_list.delete(item)

# Monitor files for changes
def monitor_files():
    selected_files = file_list.get(0, tk.END)
    if not selected_files:
        messagebox.showwarning("No Files", "Please add files to monitor.")
        return

    stored_hashes = load_hashes("hashes.json")
    current_hashes = {}
    results = []

    for file_path in selected_files:
        current_hash = calculate_hash(file_path, algorithm=hash_algorithm.get())
        if current_hash:
            current_hashes[file_path] = current_hash
            if file_path in stored_hashes:
                if stored_hashes[file_path] != current_hash:
                    results.append(f"[CHANGED] {file_path}")
                else:
                    results.append(f"[UNCHANGED] {file_path}")
            else:
                results.append(f"[NEW FILE] {file_path}")

    save_hashes(current_hashes, "hashes.json")
    result_box.delete(0, tk.END)
    for result in results:
        result_box.insert(tk.END, result)
    messagebox.showinfo("Monitoring Complete", "File monitoring finished!")

# GUI setup
def create_gui():
    global file_list, result_box, hash_algorithm

    root = tk.Tk()
    root.title("File Integrity Checker")
    root.geometry("600x400")

    # File selection frame
    frame_files = ttk.LabelFrame(root, text="Files to Monitor")
    frame_files.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    file_list = tk.Listbox(frame_files, height=10, selectmode=tk.MULTIPLE)
    file_list.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)

    file_scroll = ttk.Scrollbar(frame_files, orient=tk.VERTICAL, command=file_list.yview)
    file_scroll.pack(side=tk.RIGHT, fill=tk.Y)
    file_list.config(yscrollcommand=file_scroll.set)

    frame_buttons = ttk.Frame(root)
    frame_buttons.pack(pady=5)

    btn_add = ttk.Button(frame_buttons, text="Add File", command=add_file)
    btn_add.pack(side=tk.LEFT, padx=5)

    btn_remove = ttk.Button(frame_buttons, text="Remove File", command=remove_file)
    btn_remove.pack(side=tk.LEFT, padx=5)

    # Hash algorithm selection
    frame_algorithm = ttk.Frame(root)
    frame_algorithm.pack(pady=5)

    ttk.Label(frame_algorithm, text="Select Hash Algorithm:").pack(side=tk.LEFT, padx=5)

    hash_algorithm = tk.StringVar(value="sha256")
    algo_dropdown = ttk.Combobox(
        frame_algorithm,
        textvariable=hash_algorithm,
        values=["md5", "sha1", "sha256", "sha512"],
        state="readonly",
    )
    algo_dropdown.pack(side=tk.LEFT, padx=5)

    # Monitor and Results section
    frame_monitor = ttk.Frame(root)
    frame_monitor.pack(pady=10)

    btn_monitor = ttk.Button(frame_monitor, text="Monitor Files", command=monitor_files)
    btn_monitor.pack(side=tk.LEFT, padx=5)

    # Results display
    result_box = tk.Listbox(root, height=10)
    result_box.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    root.mainloop()

if __name__ == "__main__":
    create_gui()


    #  file-integrity-checker
    **company**: CODTECH IT SOLUTIONS
    **NAME**: MAYANK
    **INTERN ID**: CT12JMA
    **DOMAIN**:cyber-security & Ethical hacking
    **BATCH **:january 5th,2025 to march 5th,2025
    **mentor name**:NEELA SANTHOSH

