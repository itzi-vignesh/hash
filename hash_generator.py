import os
import sys
import threading
import io
import hashlib
import pyperclip
import json
import time
import stat
import ctypes
from tkinter import filedialog, Label, Entry, Button, StringVar, messagebox, ttk, Frame, Listbox, Menu
from html import escape
import bleach
from concurrent.futures import ThreadPoolExecutor, as_completed
from weasyprint import HTML
from PyPDF2 import PdfReader, PdfWriter

# Get the absolute path to fonts.conf
fontconfig_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "fontconfig", "fonts.conf"))

# Set FONTCONFIG_FILE environment variable
os.environ["FONTCONFIG_FILE"] = fontconfig_path

# Add DLLs folder to PATH
dll_path = os.path.join(os.path.dirname(sys.executable), "dlls")
os.environ["PATH"] += os.pathsep + dll_path

# 🔹 Prevent hashing of excessively large files (>2GB)
MAX_FILE_SIZE = 2 * 1024 * 1024 * 1024  # 2GB limit

# 🔹 Prevent access to restricted directories
RESTRICTED_DIRECTORIES = [
    "/root", "/etc", "/bin", "/usr/sbin",
    "C:\\Windows", "C:\\Program Files", "C:\\System32"
]

# --- NEW: Flatten and Parallelize File Hashing ---

def hash_directory_flat(directory_path, results, progress_callback, update_listbox):
    """
    Gather all files in the directory tree, compute their SHA-512 hashes in parallel,
    then reassemble the results into a nested tree structure with directory hashes.
    """
    file_list = []
    # Walk the directory and collect files along with their relative paths.
    for root, dirs, files in os.walk(directory_path):
        for file in files:
            full_path = os.path.join(root, file)
            rel_path = os.path.relpath(full_path, directory_path)
            file_list.append((rel_path, full_path))
    total_files = len(file_list)
    processed_files = 0
    file_hashes = {}
    
    CHUNK_SIZE = 1_048_576  # 1MB chunks

    def compute_file_hash(file_full):
        try:
            if os.path.getsize(file_full) > MAX_FILE_SIZE:
                return "⚠ Warning: File too large to hash"
            hash_obj = hashlib.sha512()
            with open(file_full, 'rb') as f:
                while True:
                    chunk = f.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    hash_obj.update(chunk)
            return hash_obj.hexdigest()
        except Exception as e:
            return f"⚠ Warning: {e}"
    
    # Use a single ThreadPoolExecutor for all files
    with ThreadPoolExecutor(max_workers=os.cpu_count()) as executor:
        future_to_rel = {executor.submit(compute_file_hash, full): rel for rel, full in file_list}
        for future in as_completed(future_to_rel):
            rel = future_to_rel[future]
            file_hash = future.result()
            file_hashes[rel] = file_hash
            processed_files += 1
            progress_callback(processed_files, total_files)
            update_listbox(f"📄 {rel} -- {file_hash}")
    
    # Build a nested dictionary (tree) from the flat file hash mapping.
    tree = {}
    for rel, file_hash in file_hashes.items():
        parts = rel.split(os.sep)
        d = tree
        for part in parts[:-1]:
            d = d.setdefault(part, {})
        d[parts[-1]] = file_hash

    # Recursively compute directory hash for each directory node.
    def compute_dir_hash(d):
        dir_hash = hashlib.sha512()
        for key in sorted(d.keys()):
            if isinstance(d[key], dict):
                sub_hash = compute_dir_hash(d[key])
                # Store the subdirectory's directory hash
                d[key]["Directory Hash"] = sub_hash
                dir_hash.update(sub_hash.encode('utf-8'))
            else:
                dir_hash.update(d[key].encode('utf-8'))
        return dir_hash.hexdigest()
    
    root_dir_hash = compute_dir_hash(tree)
    base_name = os.path.basename(os.path.abspath(directory_path))
    results[base_name] = tree
    results[base_name]["Directory Hash"] = root_dir_hash

# --- End of Flattening Function ---

# Function to format the nested results tree into a list of strings for display
def format_results_tree(results, prefix=""):
    lines = []
    for key, value in results.items():
        if isinstance(value, dict):
            directory_hash = value.get("Directory Hash", "⚠ Warning: Hash unavailable")
            lines.append(f"{prefix} 📁{key} -- {directory_hash}")
            sub_results = {k: v for k, v in value.items() if k != "Directory Hash"}
            lines.extend(format_results_tree(sub_results, prefix + "      "))
        else:
            lines.append(f"{prefix}📄 {key} -- {value}")
    return lines

def save_results_to_file(results, output_file, file_type):
    """Save hash results in TXT, JSON, HTML, or PDF format."""
    formatted_results = "\n".join(format_results_tree(results))

    if file_type == "txt":
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write("SHA-512 HASH GENERATOR\n")
            f.write("=" * 50 + "\n")
            f.write("HASH REPORT\n".center(50, " ") + "\n")
            f.write("=" * 50 + "\n\n")
            f.write(formatted_results + "\n\n")
            f.write("=" * 50 + "\n")
            f.write("Powered By CYBERNERDS SOLUTIONS".rjust(100) + "\n")
        return True

    elif file_type == "json":
        results_with_metadata = {
            "Header": "SHA-512 HASH GENERATOR",
            "Report_Title": "HASH REPORT",
            "Results": formatted_results,
            "Footer": "Powered By CYBERNERDS SOLUTIONS"
        }
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(results_with_metadata, f, indent=4)
        return True

    elif file_type == "html":
        sanitized_results = bleach.clean(formatted_results, tags=['pre', 'h1', 'h2', 'footer'], strip=True)
        html_template = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <title>SHA-512 HASH GENERATOR</title>
            <style>
                body {{
                    font-family: 'Noto Sans', sans-serif;
                    font-size: 14px;
                    margin: 20px;
                }}
                h1, h2 {{
                    text-align: center;
                }}
                pre {{
                    font-size: 12px;
                    white-space: pre-wrap;
                    word-wrap: break-word;
                    background: #f4f4f4;
                    padding: 10px;
                    border-radius: 5px;
                }}
            </style>
        </head>
        <body>
            <h1>SHA-512 HASH GENERATOR</h1>
            <h2>HASH REPORT</h2>
            <pre>{escape(sanitized_results)}</pre>
        </body>
        </html>
        """
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_template)
        return True

    elif file_type == "pdf":
        # Generate PDF in a separate thread to avoid UI freezing
        def generate_pdf_thread():
            try:
                sanitized_html = bleach.clean(formatted_results, tags=['pre', 'h1', 'h2', 'footer'], strip=True)
                pdf_metadata = {
                    "title": "SHA-512 HASH REPORT",
                    "author": "CyberNerds Solutions",
                    "subject": "SHA-512 Integrity Verification Report",
                    "keywords": "SHA-512, Integrity, Hash"
                }
                html_template = f"""
                <!DOCTYPE html>
                <html lang="en">
                <head>
                    <meta charset="UTF-8">
                    <title>SHA-512 HASH GENERATOR</title>
                    <style>
                        @page {{
                            size: A4;
                            margin: 20mm 2mm 20mm 2mm;
                            @top-center {{
                                content: "SHA-512 HASH GENERATOR";
                                font-size: 14px;
                                font-weight: bold;
                            }}
                            @bottom-right {{
                                content: "Powered By CYBERNERDS SOLUTIONS";
                                font-size: 8px;
                                color: grey;
                                margin-right: 7mm;
                            }}
                            @bottom-left {{
                                content: "Page " counter(page) " of " counter(pages);
                                font-size: 8px;
                                color: grey;
                                margin-left: 7mm;
                            }}
                        }}
                        body {{
                            font-family: 'Noto Sans', sans-serif;
                            font-size: 12px;
                            margin: 5mm 5mm;
                        }}
                        pre {{
                            max-width: 250ch;
                            line-height: 1.5;
                            white-space: pre-wrap;
                            word-wrap: break-word;
                            font-family: 'Noto Sans', sans-serif;
                            font-size: 8px;
                        }}
                    </style>
                </head>
                <body>
                    <h1 style="text-align: center;">HASH REPORT</h1>
                    <pre>{escape(sanitized_html)}</pre>
                </body>
                </html>
                """
                # Generate PDF using WeasyPrint
                HTML(string=html_template).write_pdf(output_file)
                return True
            except Exception as e:
                print(f"Error generating PDF: {e}")
                return False

        # Start PDF generation in a separate thread
        import threading
        pdf_thread = threading.Thread(target=generate_pdf_thread)
        pdf_thread.start()
        return True

    return False

# --- GUI Application Class ---
class HashGenerator:
    def __init__(self, parent):
        self.frame = parent
        self.create_widgets()
        self.results = {}
        self.progress_var = tk.DoubleVar()
        self.status_var = tk.StringVar(value="Ready")

    def create_widgets(self):
        Label(self.frame, text="🔐 HASH GENERATOR", font=("Helvetica", 20, "bold")).pack(pady=10)

        self.directory_path = StringVar()
        path_frame = Frame(self.frame)
        path_frame.pack(pady=5, padx=20, fill="x")
        Label(path_frame, text="📁 Select Directory:").pack(side="left", padx=5)
        Entry(path_frame, textvariable=self.directory_path, width=50).pack(side="left", padx=5, fill="x")
        Button(path_frame, text="Browse", command=self.browse_directory).pack(side="left", padx=5)

        self.output_file_name = StringVar(value="hash_results")
        file_frame = Frame(self.frame)
        file_frame.pack(pady=5, padx=20, fill="x")
        Label(file_frame, text="📄 Output File Name:").pack(side="left", padx=5)
        Entry(file_frame, textvariable=self.output_file_name, width=50).pack(side="left", padx=5, fill="x")

        self.progress = ttk.Progressbar(self.frame, maximum=100)
        self.progress.pack(pady=10, padx=15, fill="x")

        # Search and Listbox Frame
        search_frame = Frame(self.frame)
        search_frame.pack(pady=5, padx=20, fill="x")
        Label(search_frame, text="🔍 Search:").pack(side="left", padx=5)
        self.search_var = StringVar()
        Entry(search_frame, textvariable=self.search_var, width=40).pack(side="left", padx=5, fill="x")

        listbox_frame = Frame(self.frame)
        listbox_frame.pack(pady=10, padx=20, fill="both", expand=True)
        self.hash_listbox = Listbox(listbox_frame, width=90, height=10, selectmode="extended")
        self.hash_listbox.pack(side="left", fill="both", expand=True)
        self.hash_listbox.bind("<Button-3>", self.show_context_menu)
        self.context_menu = Menu(self.frame, tearoff=0)
        self.context_menu.add_command(label="Copy Hash", command=self.copy_hash)

        # Powered By Section
        powered_by_label = Label(self.frame, text="Powered by CYBERNERDS SOLUTIONS", font=("Helvetica", 9, "italic"), anchor="center")
        powered_by_label.pack(side="bottom", pady=2)

        # Footer Section
        footer_frame = Frame(self.frame, bd=1, relief="sunken")
        footer_frame.pack(side="bottom", fill="x", pady=2)
        self.footer = Label(footer_frame, text="Ready", font=("Helvetica", 10, "italic"), anchor="w", padx=10)
        self.footer.pack(side="top", fill="x")

        # Buttons
        button_frame = Frame(self.frame)
        button_frame.pack(pady=10)
        Button(button_frame, text="🔍 Generate Hash", command=self.start_hashing).pack(side="left", padx=5)
        Button(button_frame, text="💾 Save Report", command=self.save_results).pack(side="left", padx=5)

        self.search_var.trace_add("write", self.dynamic_search)

    def show_context_menu(self, event):
        try:
            self.hash_listbox.selection_clear(0, "end")
            self.hash_listbox.selection_set(self.hash_listbox.nearest(event.y))
            self.context_menu.post(event.x_root, event.y_root)
        except:
            pass

    def copy_hash(self):
        try:
            selected_index = self.hash_listbox.curselection()
            if selected_index:
                selected_text = self.hash_listbox.get(selected_index)
                sanitized_hash = selected_text.split("--")[-1].strip()
                if any(c in sanitized_hash for c in [";", "&", "|", "`", "$", "<", ">", "(", ")", "[", "]"]):
                    messagebox.showerror("Error", "Hash copying failed: Potentially unsafe content detected.")
                    return
                pyperclip.copy(sanitized_hash)
                messagebox.showinfo("Copied", "Hash copied to clipboard!")
        except:
            messagebox.showerror("Error", "Failed to copy hash.")

    def browse_directory(self):
        path = filedialog.askdirectory()
        if path:
            if any(path.startswith(p) for p in RESTRICTED_DIRECTORIES):
                messagebox.showerror("Access Denied", "You are not allowed to hash system directories.")
                return
            self.directory_path.set(path)

    def start_hashing(self):
        directory = self.directory_path.get()
        if not directory:
            messagebox.showwarning("Warning", "Please select a directory.")
            return

        self.results = {}
        self.hash_listbox.delete(0, "end")
        self.progress["value"] = 0
        start_time = time.time()

        # Count total files by doing an os.walk once
        total_files = sum(len(files) for _, _, files in os.walk(directory))
        processed_files = 0

        def update_progress(current, total):
            nonlocal processed_files
            processed_files = current
            progress_value = int((processed_files / total_files) * 90) if total_files else 90
            self.frame.after(10, lambda: self.progress.config(value=progress_value))

        def finalize_progress():
            self.frame.after(10, lambda: self.progress.config(value=100))

        def update_listbox(message):
            # Append new line to listbox
            self.frame.after(0, lambda: self.hash_listbox.insert("end", message))

        def hash_and_update():
            try:
                hash_directory_flat(directory, self.results, update_progress, update_listbox)
                finalize_progress()
                self.frame.after(0, self.refresh_listbox)
                elapsed_time = round(time.time() - start_time, 2)
                self.frame.after(0, lambda: self.footer.config(text=f"✅ Hashing completed in {elapsed_time} seconds!"))
            except Exception as e:
                finalize_progress()
                self.frame.after(0, lambda: self.footer.config(text=f"⚠ Error: {e}"))

        self.footer.config(text="⚙️ Generating hashes...")
        threading.Thread(target=hash_and_update, daemon=True).start()

    def refresh_listbox(self):
        self.hash_listbox.delete(0, "end")
        for line in format_results_tree(self.results):
            self.hash_listbox.insert("end", line)

    def save_results(self):
        """Save the hash results to a file."""
        if not self.results:
            messagebox.showwarning("Warning", "No results to save!")
            return

        file_types = [
            ("Text files", "*.txt"),
            ("JSON files", "*.json"),
            ("HTML files", "*.html"),
            ("PDF files", "*.pdf")
        ]
        
        output_file = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=file_types,
            title="Save Hash Report"
        )
        
        if not output_file:
            return

        file_type = output_file.split('.')[-1].lower()
        if file_type not in ['txt', 'json', 'html', 'pdf']:
            messagebox.showerror("Error", "Unsupported file type!")
            return

        # Update status
        self.status_var.set("Saving report...")
        self.frame.update()

        # Save the file
        success = save_results_to_file(self.results, output_file, file_type)

        if success:
            if file_type == 'pdf':
                # For PDF, show a different message since it's generating in background
                self.status_var.set("PDF generation started...")
                messagebox.showinfo("Success", "PDF generation has started. The file will be saved when complete.")
            else:
                self.status_var.set("Report saved successfully!")
                messagebox.showinfo("Success", "Report saved successfully!")
        else:
            self.status_var.set("Error saving report!")
            messagebox.showerror("Error", "Failed to save the report!")

    def dynamic_search(self, *args):
        search_term = self.search_var.get().strip().lower()
        self.hash_listbox.delete(0, "end")
        if not search_term:
            for line in format_results_tree(self.results):
                self.hash_listbox.insert("end", line)
            return
        filtered_lines = [line for line in format_results_tree(self.results) if search_term in line.lower()]
        if filtered_lines:
            for line in filtered_lines:
                self.hash_listbox.insert("end", line)
        else:
            self.hash_listbox.insert("end", "No matching results found.")
