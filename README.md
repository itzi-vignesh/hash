# SHA-512 Integrity Tool

A powerful file integrity verification tool that generates and compares SHA-512 hashes for files and directories. This application helps ensure data integrity and detect unauthorized changes in your files.

![Application Logo](logo.ico)

## Features

- 🔐 **Hash Generator**: Generate SHA-512 hashes for files and directories
- 🔍 **Hash Comparator**: Compare hash reports to detect changes
- 📊 **Multiple Export Formats**: Export reports in TXT, JSON, HTML, and PDF
- 🌓 **Theme Support**: Light and dark mode
- 🚀 **Performance Optimized**: Parallel processing for faster hashing
- 🔒 **Security Focused**: Admin privileges and restricted directory access
- 📋 **Clipboard Integration**: Easy hash copying
- 📱 **Cross-Platform**: Works on Windows, Linux, and macOS

## Installation

1. Clone the repository:
```bash
git clone [repository-url]
cd [repository-name]
```

2. Install the required dependencies:
```bash
pip install -r requirements.txt
```

## Usage

1. Run the application:
```bash
python integratedapp.py
```

2. The application will request admin privileges (required for file access)

3. Use the two main tabs:
   - **Hash Generator**: Generate hashes for files/directories
   - **Hash Comparator**: Compare hash reports to detect changes

## System Requirements

- Python 3.7 or higher
- Admin/root privileges
- 2GB RAM minimum
- 100MB free disk space

## Dependencies

- ttkbootstrap: Modern UI components
- PyMuPDF: PDF handling
- WeasyPrint: PDF generation
- PyPDF2: PDF manipulation
- bleach: HTML sanitization
- pyperclip: Clipboard operations

## Security Features

- Admin privileges required for file access
- Restricted directory access prevention
- File size limits (2GB max)
- Secure session management
- Input sanitization for exports

## Export Formats

1. **TXT**: Plain text report
2. **JSON**: Structured data format
3. **HTML**: Web-friendly format
4. **PDF**: Professional document format

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For support, please open an issue in the repository.

## Credits

Developed by CYBERNERDS SOLUTIONS

---

*Note: This application requires admin privileges to access files and directories. Make sure to run it with appropriate permissions.* 