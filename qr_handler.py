"""
qr_handler.py — LumenPass QR Code Generation & Scanning Module
Generates QR passes from encrypted visitor data and provides an
optimized webcam scanner that releases resources immediately.

Hardware target: Intel i3 10th Gen / 8 GB RAM — every frame-loop
operation is kept lightweight to avoid lag.
"""

import os
import json
import time

import qrcode
from qrcode.constants import ERROR_CORRECT_M
from PIL import Image

try:
    import cv2
    from pyzbar.pyzbar import decode as pyzbar_decode
    SCAN_IMPORT_ERROR = None
except Exception as exc:
    cv2 = None
    pyzbar_decode = None
    SCAN_IMPORT_ERROR = exc

# ── Configuration ──────────────────────────────────────────────
QR_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "qr_codes")
os.makedirs(QR_DIR, exist_ok=True)


# ── QR Code Generation ────────────────────────────────────────

def generate_qr(visitor_id: int,
                encrypted_phone: str,
                encrypted_purpose: str) -> str:
    """
    Generate a QR code image containing the visitor's encrypted data.

    The QR payload is a compact JSON string:
        {"id": 42, "p": "<enc_phone>", "r": "<enc_purpose>"}
    Short keys ('p', 'r') keep the QR small and fast to scan.

    Args:
        visitor_id       : Database row ID of the visitor.
        encrypted_phone  : Base64 AES-256 cipher of the phone number.
        encrypted_purpose: Base64 AES-256 cipher of the visit purpose.

    Returns:
        Absolute path to the saved PNG image.
    """
    # Build a minimal JSON payload
    payload = json.dumps({
        "id": visitor_id,
        "p": encrypted_phone,
        "r": encrypted_purpose,
    }, separators=(",", ":"))          # No extra whitespace

    # Create QR with moderate error correction (good balance of
    # size vs. resilience for printed/on-screen passes)
    qr = qrcode.QRCode(
        version=None,                 # Auto-size
        error_correction=ERROR_CORRECT_M,
        box_size=10,
        border=4,
    )
    qr.add_data(payload)
    qr.make(fit=True)

    img: Image.Image = qr.make_image(fill_color="black", back_color="white")

    # Save to qr_codes/ directory
    filename = f"visitor_{visitor_id}.png"
    filepath = os.path.join(QR_DIR, filename)
    img.save(filepath)
    print(f"[OK] QR saved -> {filepath}")
    return filepath


# ── Optimised Webcam Scanner ──────────────────────────────────

def scan_qr_from_webcam(timeout_seconds: int = 30) -> dict | None:
    """
    Open the default webcam, scan for a QR code, and return the
    decoded payload as a dict. The camera is released the instant
    a code is detected OR the timeout expires.

    Optimisation notes (for i3 / 8 GB systems):
        • Resolution capped at 640×480 to reduce per-frame work.
        • Only every 3rd frame is decoded (pyzbar is the bottleneck).
        • Camera resource is released in a finally block so it never
          leaks, even on exceptions.

    Args:
        timeout_seconds: Max seconds to keep the camera open.

    Returns:
        Parsed dict from the QR JSON payload, or None on timeout /
        error / invalid data.
    """
    if SCAN_IMPORT_ERROR is not None:
        raise RuntimeError(
            f"QR scan dependencies unavailable on this host: {SCAN_IMPORT_ERROR}"
        )

    cap = cv2.VideoCapture(0)
    if not cap.isOpened():
        raise RuntimeError(
            "Webcam is not available on this host. "
            "Run scanner on a local machine with camera access."
        )

    # Low resolution → less CPU per frame
    cap.set(cv2.CAP_PROP_FRAME_WIDTH, 640)
    cap.set(cv2.CAP_PROP_FRAME_HEIGHT, 480)

    result = None
    frame_count = 0
    start = time.time()

    try:
        while time.time() - start < timeout_seconds:
            ret, frame = cap.read()
            if not ret:
                continue

            frame_count += 1

            # Decode only every 3rd frame to save CPU
            if frame_count % 3 != 0:
                # Still show the preview so the user can aim
                cv2.imshow("LumenPass Scanner  |  Press 'q' to quit", frame)
                if cv2.waitKey(1) & 0xFF == ord("q"):
                    break
                continue

            # Attempt QR detection
            decoded_objects = pyzbar_decode(frame)
            for obj in decoded_objects:
                try:
                    data = obj.data.decode("utf-8")
                    result = json.loads(data)
                    print(f"[OK] QR scanned -> Visitor ID {result.get('id')}")

                    # Draw a green rectangle around the detected code
                    pts = obj.polygon
                    if pts:
                        for i in range(len(pts)):
                            cv2.line(
                                frame,
                                (pts[i].x, pts[i].y),
                                (pts[(i + 1) % len(pts)].x, pts[(i + 1) % len(pts)].y),
                                (0, 255, 0), 3,
                            )
                    cv2.imshow("LumenPass Scanner  |  Press 'q' to quit", frame)
                    cv2.waitKey(800)  # Brief pause so user sees the detection
                    return result
                except (json.JSONDecodeError, UnicodeDecodeError):
                    # Not our QR — ignore and keep scanning
                    continue

            # Show live preview
            cv2.imshow("LumenPass Scanner  |  Press 'q' to quit", frame)
            if cv2.waitKey(1) & 0xFF == ord("q"):
                break

        print("[WARN] Scanner timed out: no QR code detected.")
        return None

    finally:
        # ── CRITICAL: always free the camera & windows ──
        cap.release()
        cv2.destroyAllWindows()
        print("[OK] Camera released.")


# ── Standalone Test ────────────────────────────────────────────
if __name__ == "__main__":
    # Quick generation test with dummy encrypted strings
    path = generate_qr(
        visitor_id=1,
        encrypted_phone="dGVzdF9waG9uZV9lbmNyeXB0ZWQ=",
        encrypted_purpose="dGVzdF9wdXJwb3NlX2VuY3J5cHRlZA==",
    )
    print(f"Test QR created at: {path}")

    # Uncomment below to test the webcam scanner interactively:
    # data = scan_qr_from_webcam()
    # if data:
    #     print("Scanned payload:", data)
