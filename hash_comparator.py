import tkinter as tk
from tkinter import ttk, filedialog, messagebox, Label, Frame
import fitz  # PyMuPDF for PDF text extraction
import threading
import os
import re
import datetime
import hashlib
from html import escape
from weasyprint import HTML
from PyPDF2 import PdfReader
import json
import bleach

class HashComparator:
    def __init__(self, parent):
        self.frame = parent
        self.diff_window = None
        self.old_has_interacted = False
        self.new_has_interacted = False

        self.old_placeholder = "UPLOAD FILE OR PASTE HASH CONTENTS"
        self.new_placeholder = "UPLOAD FILE OR PASTE HASH CONTENTS"

        # Store hash difference details for report
        self.hash_differences = {}
        self.summary = ""
        self.structured_report = ""
        self.detailed_report = ""

        self.create_widgets()

    def create_widgets(self):
        title_label = ttk.Label(self.frame, text="🔍 HASH COMPARATOR", font=("Helvetica", 18, "bold"))
        title_label.pack(pady=5)

        report_frame = ttk.Frame(self.frame)
        report_frame.pack(fill="both", expand=True, padx=5, pady=5)

        self.left_frame = ttk.LabelFrame(report_frame, text="Primary File")
        self.left_frame.pack(side="left", fill="both", expand=True, padx=5, pady=5)
        self.old_report_text = tk.Text(self.left_frame, wrap="word", font=("Arial", 10), height=18, width=40)
        self.old_report_text.pack(side="left", fill="both", expand=True, padx=5, pady=5)
        old_scrollbar = ttk.Scrollbar(self.left_frame, command=self.old_report_text.yview)
        old_scrollbar.pack(side="right", fill="y")
        self.old_report_text.configure(yscrollcommand=old_scrollbar.set)

        self.right_frame = ttk.LabelFrame(report_frame, text="Secondary File")
        self.right_frame.pack(side="right", fill="both", expand=True, padx=5, pady=5)
        self.new_report_text = tk.Text(self.right_frame, wrap="word", font=("Arial", 10), height=18, width=40)
        self.new_report_text.pack(side="left", fill="both", expand=True, padx=5, pady=5)
        new_scrollbar = ttk.Scrollbar(self.right_frame, command=self.new_report_text.yview)
        new_scrollbar.pack(side="right", fill="y")
        self.new_report_text.configure(yscrollcommand=new_scrollbar.set)

        self.set_placeholder(self.old_report_text, self.old_placeholder)
        self.set_placeholder(self.new_report_text, self.new_placeholder)

        self.frame.bind("<Button-1>", self.handle_frame_click)
        self.old_report_text.bind("<FocusIn>", self.on_old_text_focus)
        self.old_report_text.bind("<FocusOut>", lambda event: self.restore_placeholder(self.old_report_text, self.old_placeholder))
        self.new_report_text.bind("<FocusIn>", self.on_new_text_focus)
        self.new_report_text.bind("<FocusOut>", lambda event: self.restore_placeholder(self.new_report_text, self.new_placeholder))

        button_frame = ttk.Frame(self.frame)
        button_frame.pack(fill="x", padx=5, pady=5)
        self.load_old_button = ttk.Button(button_frame, text="📂 Load Primary File", command=self.load_old_report)
        self.load_old_button.grid(row=0, column=0, padx=5, pady=2, sticky="ew")
        self.load_new_button = ttk.Button(button_frame, text="📂 Load Secondary File", command=self.load_new_report)
        self.load_new_button.grid(row=0, column=1, padx=5, pady=2, sticky="ew")
        self.compare_button = ttk.Button(button_frame, text="🔍 Compare Hashes", command=self.compare_hashes)
        self.compare_button.grid(row=1, column=0, padx=5, pady=2, sticky="ew")
        self.save_report_button = ttk.Button(button_frame, text="💾 Save Final Report", command=self.save_final_report)
        self.save_report_button.grid(row=1, column=1, padx=5, pady=2, sticky="ew")
        button_frame.grid_columnconfigure(0, weight=1)
        button_frame.grid_columnconfigure(1, weight=1)

        powered_by_label = Label(self.frame, text="Powered by CYBERNERDS SOLUTIONS", font=("Helvetica", 9, "italic"), anchor="center")
        powered_by_label.pack(side="bottom", pady=2)

        footer_frame = Frame(self.frame, bd=1, relief="sunken")
        footer_frame.pack(side="bottom", fill="x", pady=2)
        self.footer = Label(footer_frame, text="Ready", font=("Helvetica", 10, "italic"), anchor="w", padx=10)
        self.footer.pack(side="top", fill="x")

        self.frame.focus_set()

    def handle_frame_click(self, event):
        if not self.old_report_text.get("1.0", tk.END).strip():
            self.set_placeholder(self.old_report_text, self.old_placeholder)
        if not self.new_report_text.get("1.0", tk.END).strip():
            self.set_placeholder(self.new_report_text, self.new_placeholder)

    def on_old_text_focus(self, event):
        self.remove_placeholder(self.old_report_text, self.old_placeholder)

    def on_new_text_focus(self, event):
        self.remove_placeholder(self.new_report_text, self.new_placeholder)

    def set_placeholder(self, text_widget, placeholder):
        if text_widget == self.old_report_text and not self.old_has_interacted:
            text_widget.insert("1.0", placeholder)
            text_widget.config(fg="gray")
        elif text_widget == self.new_report_text and not self.new_has_interacted:
            text_widget.insert("1.0", placeholder)
            text_widget.config(fg="gray")

    def remove_placeholder(self, text_widget, placeholder):
        if text_widget == self.old_report_text:
            self.old_has_interacted = True
        elif text_widget == self.new_report_text:
            self.new_has_interacted = True
        if text_widget.get("1.0", tk.END).strip() == placeholder:
            text_widget.delete("1.0", tk.END)
            text_widget.config(fg="black")

    def restore_placeholder(self, text_widget, placeholder):
        if text_widget.get("1.0", tk.END).strip():
            return
        if text_widget == self.old_report_text and self.old_has_interacted:
            text_widget.insert("1.0", placeholder)
            text_widget.config(fg="gray")
        elif text_widget == self.new_report_text and self.new_has_interacted:
            text_widget.insert("1.0", placeholder)
            text_widget.config(fg="gray")

    def update_status(self, message):
        self.footer.config(text=message)

    def parse_hash_report(self, content):
        hash_dict = {}
        indent_dict = {}
        for line in content.splitlines():
            match = re.match(r"(\s*)([\📁📄]\s*.+?)\s*--\s*(\w+)", line)
            if match:
                indent, name, hash_value = match.groups()
                clean_name = name.strip()
                hash_dict[clean_name] = hash_value
                indent_dict[clean_name] = indent
        return hash_dict, indent_dict

    def get_hash_differences(self, old_content, new_content):
        old_hashes, old_indent = self.parse_hash_report(old_content)
        new_hashes, new_indent = self.parse_hash_report(new_content)
        differences = {}
        for path, old_hash in old_hashes.items():
            if path not in new_hashes:
                differences[path] = "➖Removed"
            elif old_hash != new_hashes[path]:
                differences[path] = "❌Modified"
        for path, new_hash in new_hashes.items():
            if path not in old_hashes:
                differences[path] = "➕Added"
        return differences, old_indent

    def load_old_report(self):
        threading.Thread(target=self._load_report, args=(self.old_report_text,), daemon=True).start()

    def load_new_report(self):
        threading.Thread(target=self._load_report, args=(self.new_report_text,), daemon=True).start()

    def _load_report(self, text_widget):
        file_path = filedialog.askopenfilename(filetypes=[("PDF Files", "*.pdf")])
        if file_path:
            try:
                content = self.extract_text_from_pdf(file_path)
                self.frame.after(0, self._update_text_widget, text_widget, content)
                self.update_status("Report loaded successfully.")
            except Exception as e:
                self.frame.after(0, messagebox.showerror, "Error", f"Failed to load report: {e}")
                self.update_status("⚠ Error loading report.")

    def _update_text_widget(self, text_widget, content):
        text_widget.delete("1.0", tk.END)
        text_widget.insert(tk.END, content)

    def extract_text_from_pdf(self, file_path):
        text = ""
        try:
            with fitz.open(file_path) as doc:
                for page in doc:
                    text += page.get_text("text") + "\n"
        except Exception as e:
            return f"⚠ Error: {e}"
        return text.strip()

    def compare_hashes(self):
        old_content = self.old_report_text.get("1.0", tk.END).strip()
        new_content = self.new_report_text.get("1.0", tk.END).strip()

        if not old_content or not new_content:
            messagebox.showwarning("Warning", "Both reports must be loaded before comparing.")
            self.update_status("⚠ Load both reports before comparing.")
            return

        differences, indent_dict = self.get_hash_differences(old_content, new_content)
        self.final_differences = differences
        self.hash_differences = self.format_differences(differences)
        self.summary = self.generate_summary(differences)
        self.update_status("Comparison completed successfully.")
        self.highlight_differences(differences)

        if differences:
            self.show_diff_window(differences, indent_dict)
        else:
            messagebox.showinfo("No Differences", "Both reports are identical. No differences found.")
            self.update_status("No differences found.")

    def format_differences(self, differences):
        # Build lists for each category.
        changed = []
        missing = []
        new = []
        for key, value in differences.items():
            if "Modified" in value:
                changed.append(f"│   ├── {key} -- {value}")
            elif "Removed" in value:
                missing.append(f"│   ├── {key}")
            elif "Added" in value:
                new.append(f"│   ├── {key} -- {value}")
        # If a category is empty, add a default line.
        if not changed:
            changed.append("│   └── No changed files.")
        if not missing:
            missing.append("│   └── No missing files.")
        if not new:
            new.append("│   └── No new files.")

        formatted = []
        formatted.append("├── Changed Files:")
        formatted.extend(changed)
        formatted.append("├── Missing Files:")
        formatted.extend(missing)
        formatted.append("├── New Files:")
        formatted.extend(new)
        return "\n".join(formatted)


    def generate_summary(self, differences):
        total_new = sum(1 for v in differences.values() if "Added" in v)
        total_modified = sum(1 for v in differences.values() if "Modified" in v)
        total_deleted = sum(1 for v in differences.values() if "Removed" in v)
        total_unchanged = 0
        return f"""
        Total New Files: {total_new}
        Total Modified Files: {total_modified}
        Total Deleted Files: {total_deleted}
        Unchanged Files: {total_unchanged}
        """

    def show_diff_window(self, differences, indent_dict):
        if not self.diff_window or not self.diff_window.winfo_exists():
            self.diff_window = tk.Toplevel(self.frame)
            self.diff_window.title("Hash Differences")
            self.diff_window.geometry("300x200")
            self.diff_window.protocol("WM_DELETE_WINDOW", self.reset_diff_window)
            self.diff_text = tk.Text(self.diff_window, wrap="word", font=("Arial", 10))
            self.diff_text.pack(expand=True, fill="both", padx=10, pady=10)
            save_button = ttk.Button(self.diff_window, text="💾 Save Report", command=self.save_final_report)
            save_button.pack(pady=5)
        self.diff_text.config(state="normal")
        self.diff_text.delete("1.0", tk.END)
        for key, value in differences.items():
            indent = indent_dict.get(key, "")
            self.diff_text.insert(tk.END, f"{indent}{key} -- {value}\n")
        self.diff_text.config(state="disabled")

    def reset_diff_window(self):
        if self.diff_window:
            self.diff_window.destroy()
            self.diff_window = None

    def highlight_differences(self, differences):
        self.new_report_text.tag_config("highlight", foreground="red", background="yellow")
        content = self.new_report_text.get("1.0", tk.END)
        for file, change in differences.items():
            search_start = "1.0"
            while True:
                start_idx = self.new_report_text.search(file, search_start, stopindex=tk.END, exact=True)
                if not start_idx:
                    break
                line_number, char_index = map(int, start_idx.split("."))
                line_start_idx = f"{line_number}.0"
                line_text = self.new_report_text.get(line_start_idx, f"{line_number}.end")
                clean_start = line_text.lstrip()
                offset = len(line_text) - len(clean_start)
                highlight_start = f"{line_number}.{offset}"
                highlight_end = f"{line_number}.end"
                self.new_report_text.tag_add("highlight", highlight_start, highlight_end)
                search_start = highlight_end

    def highlight_modified_in_detailed_report(self, differences, detailed_report):
        """
        Convert each line of 'detailed_report' into HTML.
        If a line has a key that is in 'differences' and indicates 'Modified' (or 'Added'/'Removed'),
        we wrap that line in a highlight span. Otherwise, we just escape the line normally.
        """
        highlighted_lines = []
        for line in detailed_report.splitlines():
            # Attempt to parse out the key, e.g. "📁test" or "📄 1.txt"
            match = re.match(r"\s*([\📁📄].+?)\s*--", line)
            if match:
                key = match.group(1).strip()  # e.g. "📁test"
                
                # Check if this key is in 'differences' and is "Modified"/"Added"/"Removed"
                if key in differences:
                    status = differences[key]  # e.g. "❌Modified" or "➕Added"
                    
                    # If the status indicates modification
                    if any(x in status for x in ["Modified", "Added", "Removed"]):
                        # Highlight this entire line
                        line_html = f'<span style="background:yellow; color:red;">{escape(line)}</span>'
                    else:
                        # No highlight
                        line_html = escape(line)
                else:
                    # Key not in differences, no highlight
                    line_html = escape(line)
            else:
                # If line doesn't match the "📁" or "📄" pattern, just escape it
                line_html = escape(line)
            
            highlighted_lines.append(line_html)
        
        # Join with <br> so that lines appear on separate lines in the HTML
        return "<br>".join(highlighted_lines)

    def save_final_report(self):
        """Save the comparison report to a file."""
        if not self.hash_differences:
            messagebox.showwarning("Warning", "No comparison results to save!")
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
            title="Save Comparison Report"
        )
        
        if not output_file:
            return

        file_type = output_file.split('.')[-1].lower()
        if file_type not in ['txt', 'json', 'html', 'pdf']:
            messagebox.showerror("Error", "Unsupported file type!")
            return

        # Update status
        self.update_status("Saving report...")

        try:
            if file_type == "txt":
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write("SHA-512 HASH COMPARATOR\n")
                    f.write("=" * 50 + "\n")
                    f.write("COMPARISON REPORT\n".center(50, " ") + "\n")
                    f.write("=" * 50 + "\n\n")
                    f.write(self.summary + "\n\n")
                    f.write("Detailed Differences:\n")
                    f.write(self.hash_differences + "\n\n")
                    f.write("=" * 50 + "\n")
                    f.write("Powered By CYBERNERDS SOLUTIONS".rjust(100) + "\n")
                self.update_status("Report saved successfully!")
                messagebox.showinfo("Success", "Report saved successfully!")

            elif file_type == "json":
                report_data = {
                    "Header": "SHA-512 HASH COMPARATOR",
                    "Report_Title": "COMPARISON REPORT",
                    "Summary": self.summary,
                    "Differences": self.hash_differences,
                    "Footer": "Powered By CYBERNERDS SOLUTIONS"
                }
                with open(output_file, 'w', encoding='utf-8') as f:
                    json.dump(report_data, f, indent=4)
                self.update_status("Report saved successfully!")
                messagebox.showinfo("Success", "Report saved successfully!")

            elif file_type == "html":
                sanitized_summary = bleach.clean(self.summary, tags=['pre', 'h1', 'h2', 'footer'], strip=True)
                sanitized_differences = bleach.clean(self.hash_differences, tags=['pre', 'h1', 'h2', 'footer'], strip=True)
                html_template = f"""
                <!DOCTYPE html>
                <html lang="en">
                <head>
                    <meta charset="UTF-8">
                    <title>SHA-512 HASH COMPARATOR</title>
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
                    <h1>SHA-512 HASH COMPARATOR</h1>
                    <h2>COMPARISON REPORT</h2>
                    <pre>{escape(sanitized_summary)}</pre>
                    <h3>Detailed Differences:</h3>
                    <pre>{escape(sanitized_differences)}</pre>
                </body>
                </html>
                """
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(html_template)
                self.update_status("Report saved successfully!")
                messagebox.showinfo("Success", "Report saved successfully!")

            elif file_type == "pdf":
                # Generate PDF in a separate thread
                def generate_pdf_thread():
                    try:
                        sanitized_summary = bleach.clean(self.summary, tags=['pre', 'h1', 'h2', 'footer'], strip=True)
                        sanitized_differences = bleach.clean(self.hash_differences, tags=['pre', 'h1', 'h2', 'footer'], strip=True)
                        pdf_metadata = {
                            "title": "SHA-512 COMPARISON REPORT",
                            "author": "CyberNerds Solutions",
                            "subject": "SHA-512 Integrity Comparison Report",
                            "keywords": "SHA-512, Integrity, Comparison"
                        }
                        html_template = f"""
                        <!DOCTYPE html>
                        <html lang="en">
                        <head>
                            <meta charset="UTF-8">
                            <title>SHA-512 HASH COMPARATOR</title>
                            <style>
                                @page {{
                                    size: A4;
                                    margin: 20mm 2mm 20mm 2mm;
                                    @top-center {{
                                        content: "SHA-512 HASH COMPARATOR";
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
                            <h1 style="text-align: center;">COMPARISON REPORT</h1>
                            <pre>{escape(sanitized_summary)}</pre>
                            <h3>Detailed Differences:</h3>
                            <pre>{escape(sanitized_differences)}</pre>
                        </body>
                        </html>
                        """
                        # Generate PDF using WeasyPrint
                        HTML(string=html_template).write_pdf(output_file)
                        self.frame.after(0, lambda: self.update_status("PDF generated successfully!"))
                        self.frame.after(0, lambda: messagebox.showinfo("Success", "PDF report has been generated!"))
                    except Exception as e:
                        self.frame.after(0, lambda: self.update_status(f"Error generating PDF: {e}"))
                        self.frame.after(0, lambda: messagebox.showerror("Error", f"Failed to generate PDF: {e}"))

                # Start PDF generation in background
                self.update_status("Starting PDF generation...")
                messagebox.showinfo("Info", "PDF generation has started. The file will be saved when complete.")
                threading.Thread(target=generate_pdf_thread, daemon=True).start()

        except Exception as e:
            self.update_status(f"Error saving report: {e}")
            messagebox.showerror("Error", f"Failed to save report: {e}")
