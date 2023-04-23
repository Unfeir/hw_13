import hashlib


name = hashlib.sha256('exemple@meta.ua'.encode()).hexdigest()[8]
print(f"NoteBook/{name}")
# print(name.decode())
# NoteBook/d7c2772b1c04