from PIL import Image
import os
import io

with open("flag.jpg", "rb") as fi:
    img_bytes = fi.read()

stream = io.BytesIO(img_bytes)

with Image.open(stream) as img:
    img.show()

os.abort()
