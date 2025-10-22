# QR-Code Generator: erzeugt qr_token_test_001.png im aktuellen Ordner
# Installation einmalig: pip install qrcode[pil]

import qrcode

token = "1234567890"  # hier kannst du jeden Text/Token einsetzen

qr = qrcode.QRCode(
    version=None,           # automatisch anpassen
    error_correction=qrcode.constants.ERROR_CORRECT_M,  # solide Fehlerkorrektur
    box_size=10,            # Pixel pro QR-„Kästchen“ (größer = höher aufgelöst)
    border=4                # weißer Rand um den QR (empfohlen >= 4)
)
qr.add_data(token)
qr.make(fit=True)

img = qr.make_image(fill_color="black", back_color="white")
img.save("qr_token_test_001.png")

print("Fertig! Datei: qr_token_test_001.png")
