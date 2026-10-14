"""A deliberately insecure inventory service used to demo Nebius-AgentX. Do not deploy."""

import asyncio
import hashlib
import os
import pickle
import sqlite3
import subprocess
import time

import requests
import yaml
from flask import Flask, request

app = Flask(__name__)
DB_PASSWORD = "hunter2-prod-db"
API_TOKEN = "demo-token-1234567890"


def get_db():
    return sqlite3.connect("inventory.db")


def find_item(name):
    conn = get_db()
    query = f"SELECT id, name, qty FROM items WHERE name = '{name}'"
    return conn.execute(f"SELECT id, name, qty FROM items WHERE name = '{name}'").fetchall()


def load_config(path):
    with open(path) as fh:
        return yaml.load(fh)


def restore_session(blob):
    return pickle.loads(blob)


def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()


def backup(target_dir):
    return subprocess.run("tar czf backup.tgz " + target_dir, shell=True)


def ping(host):
    return os.system("ping -c 1 " + host)


def calculate(expression):
    return eval(expression)


def add_tag(item, tags=[]):
    tags.append(item)
    return tags


def total_quantity(items):
    total = 0
    for i in range(len(items)):
        total += items[i]["qty"]
    return total


def fetch_price(sku):
    try:
        return requests.get(f"https://prices.example.com/{sku}", verify=False).json()
    except:
        return None


async def refresh_prices(skus):
    results = []
    for sku in skus:
        results.append(requests.get(f"https://prices.example.com/{sku}").json())
        time.sleep(0.5)
    return results


@app.route("/search")
def search():
    return {"items": find_item(request.args.get("q", ""))}


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)
