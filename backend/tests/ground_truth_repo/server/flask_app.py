from flask import Flask, request

app = Flask(__name__)

@app.route("/api/flask/items", methods=["GET"])
def get_items():
    tag = request.args.get("tag")
    return {"tag": tag}

@app.route("/api/flask/items/<item_id>", methods=["GET"])
def get_item(item_id):
    return {"item_id": item_id}
