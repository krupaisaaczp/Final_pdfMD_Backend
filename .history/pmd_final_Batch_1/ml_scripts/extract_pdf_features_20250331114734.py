import os
import json
import fitz  # PyMuPDF

def get_file_size_kb(file_path):
    """Get file size in KB"""
    try:
        return os.path.getsize(file_path) / 1024
    except:
        return 0

def extract_pdf_features(pdf_path):
    """Extracts features from a PDF file"""
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
        
        # Check for JavaScript
        for page in doc:
            if "/JS" in page.get_text("dict") or "/JavaScript" in page.get_text("dict"):
                has_javascript = 1
                break
        
        # Check for embedded files
        if doc.embfile_count() > 0:
            has_embedded_files = 1
        
        # Check for OpenAction
        if doc.is_pdf and "/OpenAction" in doc.xref_object(1, compressed=False):
            has_openaction = 1
        
        # Check for Launch actions
        for page in doc:
            if "/Launch" in page.get_text("dict"):
                has_launch = 1
                break
        
        features = {
            "header_length": header_length,
            "file_size_kb": file_size_kb,
            "num_pages": num_pages,
            "is_encrypted": is_encrypted,
            "has_javascript": has_javascript,
            "has_embedded_files": has_embedded_files,
            "has_openaction": has_openaction,
            "has_launch": has_launch,
            "pdf_version": doc.pdf_version,
            "text_length": sum(len(page.get_text()) for page in doc),
            "num_images": sum(len(page.get_images()) for page in doc)
        }
        
        doc.close()
        return features
    except Exception as e:
        raise Exception(f"Error extracting features: {str(e)}")

# If running directly, output as JSON
if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        pdf_path = sys.argv[1]
        features = extract_pdf_features(pdf_path)
        print(json.dumps(features))