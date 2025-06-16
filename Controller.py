from Item import Item
from DB import DB
from tinydb import Query


class Controller:
    def __init__(self):
        self.db = DB()

    def create_item(self, item: Item):
        self.db.add_item(item)

    def create_new_item(self, name: str, room: str, position: str, content: str) -> Item:
        # Neues Item erzeugen
        item = Item(name=name, room=room, position=position, content=content)

        # In DB speichern
        self.db.add_item(item)

        # Rückgabe an GUI (z. B. für Anzeige oder Druck)
        return item

    def get_all_items(self):
        # Alle Dokumente aus DB abrufen
        docs = self.db.get_all_items()

        # In Item-Objekte umwandeln
        return [Item.from_dict(doc) for doc in docs]

    def find_item(self, item_id):
        # Ein bestimmtes Item suchen
        doc = self.db.get_item(item_id)
        if doc:
            return Item.from_dict(doc)
        return None

    def delete_item(self, item_id):
        # Item löschen
        self.db.remove_item(item_id)

    def find_item_by_webtag(self, webtag):
        # TinyDB-kompatible Suche nach webtag
        query = Query()
        doc = self.db.table.get(query.webtag == webtag)
        if doc:
            return Item.from_dict(doc)
        return None