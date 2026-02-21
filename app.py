import os
from flask import Flask, request, jsonify
from dotenv import load_dotenv
from models import db, EventLog

load_dotenv(dotenv_path=".env")

app = Flask(__name__)

app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db.init_app(app)


@app.route("/")
def home():
    return "Backend Running"

@app.route("/event", methods=["POST"])
def receive_event():
    data = request.get_json()

    log = EventLog(
        device_id=data["device_id"],
        sequence=data["sequence"],
        event=data["event"],
        hash=data["hash"],
        signature=data["signature"]
    )

    db.session.add(log)
    db.session.commit()

    return jsonify({"status": "stored"}), 200

if __name__ == "__main__":
    app.run()