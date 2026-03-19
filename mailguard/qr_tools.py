import numpy as np
import cv2

from .my_types import Attachment, LinkFound


def extract_qr_links(attachments: list[Attachment]) -> list[LinkFound]:
    detector = cv2.QRCodeDetector()
    out: list[LinkFound] = []

    for a in attachments:
        if not a.payload:
            continue
        if not a.content_type.startswith("image/"):
            continue

        arr = np.frombuffer(a.payload, dtype=np.uint8)
        img = cv2.imdecode(arr, cv2.IMREAD_COLOR)
        if img is None:
            continue

        data, _, _ = detector.detectAndDecode(img)
        if data and data.startswith("http"):
            out.append(LinkFound(data, "qr"))

    return out
