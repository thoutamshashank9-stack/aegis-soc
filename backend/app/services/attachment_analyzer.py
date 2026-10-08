"""
Attachment Analysis Service.
Analyzes extracted email attachments safely:
- Extracts filenames, MIME types, and sizes
- Calculates SHA-256 evidence hash of file payload
- Detects dangerous and double extensions (.exe, .vbs, .scr, .bat, .pdf.exe)
- Safe handling: Never executes or spawns child processes for attachments
"""
import hashlib
from typing import Dict, Any, List

DANGEROUS_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".js", ".vbs", ".ps1", ".hta", ".wsf",
    ".jar", ".msi", ".com", ".pif", ".cpl", ".iso", ".img", ".vhd"
}

ARCHIVE_EXTENSIONS = {
    ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz", ".iso"
}


class AttachmentAnalyzer:

    @staticmethod
    def analyze_attachments(attachments: List[Dict[str, Any]], raw_bytes: bytes = b"") -> List[Dict[str, Any]]:
        results = []
        for att in attachments:
            filename = att.get("filename", "unnamed_file")
            content_type = att.get("content_type", "application/octet-stream")
            size_bytes = att.get("size_bytes", 0)

            # Check extension
            filename_lower = filename.lower()
            is_dangerous = False
            is_archive = False
            double_extension = False
            reasons = []

            # Double extension check e.g. statement.pdf.exe
            parts = filename_lower.split(".")
            if len(parts) > 2:
                for ext in DANGEROUS_EXTENSIONS:
                    if filename_lower.endswith(ext):
                        double_extension = True
                        is_dangerous = True
                        reasons.append(f"Suspicious double extension trick detected ({parts[-2]}.{parts[-1]})")
                        break

            # Dangerous extension
            for ext in DANGEROUS_EXTENSIONS:
                if filename_lower.endswith(ext):
                    is_dangerous = True
                    reasons.append(f"Executable/script file extension detected ({ext})")
                    break

            for ext in ARCHIVE_EXTENSIONS:
                if filename_lower.endswith(ext):
                    is_archive = True
                    reasons.append(f"Compressed archive container ({ext}) - potential malware carrier")
                    break

            # Calculate SHA-256 if attachment payload is provided, else compute placeholder
            payload = att.get("payload_bytes", b"")
            if payload:
                file_hash = hashlib.sha256(payload).hexdigest()
            else:
                file_hash = hashlib.sha256(f"{filename}_{size_bytes}".encode("utf-8")).hexdigest()

            results.append({
                "filename": filename,
                "content_type": content_type,
                "size_bytes": size_bytes,
                "sha256": file_hash,
                "is_dangerous": is_dangerous,
                "is_archive": is_archive,
                "double_extension": double_extension,
                "reasons": reasons
            })

        return results
