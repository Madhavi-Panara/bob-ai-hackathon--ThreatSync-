from flask import Flask, jsonify, send_from_directory
from pipeline import get_dashboard_data,generate_live_alerts


app = Flask(__name__, static_folder="static")

@app.get("/")
def index():
    return send_from_directory("static","index.html")

@app.get("/api/dashboard")
def dashboard():
    return jsonify(get_dashboard_data())

@app.get("/api/alerts")
def api_alerts():
    return jsonify(get_dashboard_data()["alerts"])

@app.get("/api/incidents")
def api_incidents():
    return jsonify(get_dashboard_data()["incidents"])

@app.post("/api/live")
def live():
    try:
        new_alerts=generate_live_alerts(5)

        return jsonify({
            "new_alerts":new_alerts,
            "dashboard":get_dashboard_data()
        })

    except Exception as e:
        print("LIVE ERROR:",e)
        return jsonify({"error":str(e)}),500
    
if __name__=="__main__":
    app.run(debug=True,port=5000)