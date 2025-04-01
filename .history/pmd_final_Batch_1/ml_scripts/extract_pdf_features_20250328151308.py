import fitz  # PyMuPDF
import magic  # File type detection
import json

def get_pdf_version(pdf_path):
    """ Extract PDF version from file header """
    try:
        with open(pdf_path, "rb") as f:
            header = f.read(8).decode(errors="ignore")
        return header.split("-")[-1].strip() if "PDF-" in header else "Unknown"
    except Exception:
        return "Unknown"

def extract_pdf_features(pdf_path):
    """ Extracts features from a PDF file """
    try:
        # Load PDF
        doc = fitz.open(pdf_path)

        # Extract metadata
        metadata = doc.metadata or {}
        pdf_version = get_pdf_version(pdf_path)
        num_pages = len(doc)
        text_length = 0
        num_images = 0
        has_javascript = 0

        for page in doc:
            try:
                text_length += len(page.get_text("text"))  # Extract text length
                num_images += len(page.get_images(full=True))  # Count images

                # Check if JavaScript exists in the page
                has_javascript |= int("/JS" in page.get_text("dict"))

            except Exception as e:
                print(f"⚠ Skipping a problematic page due to error: {e}")

        # Detect file type
        file_type = magic.Magic(mime=True).from_file(pdf_path)

        features = {
            "pdf_version": pdf_version,
            "num_pages": num_pages,
            "text_length": text_length,
            "num_images": num_images,
            "has_javascript": has_javascript,
            "file_type": file_type,
            "title": metadata.get("title", "Unknown"),
            "author": metadata.get("author", "Unknown"),
            "creator": metadata.get("creator", "Unknown"),
            "producer": metadata.get("producer", "Unknown"),
        }

        return features

    except fitz.FileDataError:
        print(f"❌ Error: Corrupt PDF file {pdf_path}. Skipping...")
        return None
    except fitz.FileAccessError:
        print(f"❌ Error: Cannot access {pdf_path}. Check permissions.")
        return None
    except Exception as e:
        print(f"❌ Unexpected error processing {pdf_path}: {e}")
        return None

# Example usage
if __name__ == "__main__":
    sample_pdf = "sample.pdf"  # Change this to the actual PDF file
    features = extract_pdf_features(sample_pdf)

    if features:
        print(json.dumps(features, indent=4))
