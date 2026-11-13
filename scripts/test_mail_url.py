"""Lecture de liens fictifs uniquement dans la boîte locale de test."""

import sys
from pymongo import MongoClient

email = sys.argv[1]
assert email.endswith("@example.test")
db = MongoClient("mongodb://127.0.0.1:27018")["officine_test_demo"]
mail = db.mail_outbox.find_one({"to": email}, sort=[("createdAt", -1)])
assert mail
print(mail["url"])
