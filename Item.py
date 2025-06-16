from datetime import datetime
import random
import string
import secrets

class Item:
    def __init__(self, name, room, position, content, id=None, webtag=None):
        self.id = id or self.generate_id()
        self.name = name
        self.room = room
        self.position = position
        self.content = content
        self.added_date = datetime.now()
        self.last_modified = datetime.now()
        self.last_accessed = datetime.now()
        self.webtag = webtag or secrets.token_hex(16)  # 128-bit zufälliger Hex-Tag

    def generate_id(self):
        return ''.join(random.choices(string.ascii_uppercase + string.digits, k=4))

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "room": self.room,
            "position": self.position,
            "content": self.content,
            "added_date": self.added_date.isoformat(),
            "last_modified": self.last_modified.isoformat(),
            "last_accessed": self.last_accessed.isoformat(),
            "webtag": self.webtag
        }

    def __str__(self):
        return f"[{self.id}] {self.name} – {self.room}, {self.position} (Inhalt: {self.content})"

    @classmethod
    def from_dict(cls, data):
        item = cls(
            name=data["name"],
            room=data["room"],
            position=data["position"],
            content=data["content"],
            id=data["id"],
            webtag=data["webtag"]
        )
        item.added_date = datetime.fromisoformat(data.get("added_date", datetime.now().isoformat()))
        item.last_modified = datetime.fromisoformat(data.get("last_modified", datetime.now().isoformat()))
        item.last_accessed = datetime.fromisoformat(data.get("last_accessed", datetime.now().isoformat()))
        return item