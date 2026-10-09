from bson import ObjectId
from django.conf import settings
from pymongo import MongoClient

_client = None


def db():
    global _client
    if _client is None:
        _client = MongoClient(settings.MONGO_URI, serverSelectionTimeoutMS=4000)
    return _client[settings.MONGO_DB]


def oid(value):
    try:
        return ObjectId(value)
    except Exception:
        return None


def clean(doc):
    """Templates can't read `_id`, so expose it as `id`."""
    if doc is not None:
        doc["id"] = str(doc.pop("_id"))
    return doc
