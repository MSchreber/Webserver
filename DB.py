from tinydb import TinyDB, Query
from datetime import datetime
import os

class DB:
    def __init__(self, db_path="gegenstaende.json"):
        self.db = TinyDB(db_path)
        self.table = self.db.table("gegenstaende")

    def add_item(self, item):
        self.table.insert(item.to_dict())

    def get_all_items(self):
        return self.table.all()

    def get_item(self, item_id):
        Item = Query()
        return self.table.get(Item.id == item_id)

    def remove_item(self, item_id):
        Item = Query()
        self.table.remove(Item.id == item_id)

    def update_item(self, item):
        Item = Query()
        self.table.update({
            "last_accessed": item.last_accessed.isoformat(),
            "last_modified": item.last_modified.isoformat()
        }, Item.id == item.id)