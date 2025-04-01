import os
import json
import fitz  # PyMuPDF
import sys

def get_file_size_kb(file_path):
    """Get file size in KB"""
    try:
        return os.path.getsize(file_path) / 1024
    except:
        return 0

def extract_pdf_features(pdf_path):
    """Extracts features from a PDF file, including metadata"""
    try:
        # Load PDF
        doc = fitz.open(pdf_path)
        
        # Basic features
        header_length = 0
        with open(pdf_path, "rb") as f:
            header = f.read(1024)
            header_length = len(header)
        
        file_size_kb = get_file_size_kb(pdf_path)
        num_pages = len(doc)
        is_encrypted = 1 if doc.is_encrypted else 0
        
        # Advanced features
        has_javascript = 0
        has_embedded_files = 0
        has_openaction = 0
        has_launch = 0
        
        for page in doc:
            if "/JS" in page.get_text("dict") or "/JavaScript" in page.get_text("dict"):
                has_javascript = 1
                break
        
        if doc.embfile_count() > 0:
            has_embedded_files = 1
        
        if doc.is_pdf and "/OpenAction" in doc.xref_object(1, compressed=False):
            has_openaction = 1
        
        for page in doc:
            if "/Launch" in page.get_text("dict"):
                has_launch = 1
                break
        
        # Extract metadata
        metadata = doc.metadata
        pdf_version = "unknown"
        author = "Not specified"
        creation_date = "Not specified"
        
        # Get PDF version
        try:
            with open(pdf_path, "rb") as f:
                header = f.read(8).decode("utf-8", errors="ignore")
                if header.startswith("%PDF-"):
                    pdf_version = header[5:]  # e.g., "1.7"
        except Exception:
            pass
        
        # Get author and creation date from metadata
        if metadata:
            author = metadata.get("author", "Not specified") or "Not specified"
            creation_date = metadata.get("creationDate", "Not specified") or "Not specified"
        
        # Return features and metadata
        features = {
            "header_length": header_length,
            "file_size_kb": file_size_kb,
            "num_pages": num_pages,
            "is_encrypted": is_encrypted,
            "has_javascript": has_javascript,
            "has_embedded_files": has_embedded_files,
            "has_openaction": has_openaction,
            "has_launch": has_launch,
            "pdf_version": pdf_version,
            "author": author,
            "creation_date": creation_date
        }
        
        doc.close()
        print(f"Extracted features for {pdf_path}: {features}", file=sys.stderr)  # Debug log to stderr
        return features
    except Exception as e:
        print(f"Error extracting features from {pdf_path}: {str(e)}", file=sys.stderr)  # Debug log to stderr
        return {"error": f"Error extracting features: {str(e)}"}

if __name__ == "__main__":
    if len(sys.argv) > 1:
        pdf_path = sys.argv[1]
        result = extract_pdf_features(pdf_path)
        print(json.dumps(result))  # Output JSON to stdout
    else:
        print(json.dumps({"error": "No PDF path provided"}))  # Output JSON to stdout