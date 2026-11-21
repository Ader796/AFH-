"""Production entry point:  python run.py   (env: AFH_HOST, AFH_PORT, AFH_DATA_DIR, AFH_TRUST_PROXY)"""
import os

from app import app, start_background

if __name__ == "__main__":
    host = os.environ.get("AFH_HOST", "0.0.0.0")
    port = int(os.environ.get("AFH_PORT", "8000"))
    start_background()
    try:
        from waitress import serve
        print(f"AFH running on http://{host}:{port} (waitress)")
        serve(app, host=host, port=port, threads=32, send_bytes=1, channel_timeout=3600)
    except ImportError:
        print(f"AFH running on http://{host}:{port} (werkzeug threaded server; install waitress for production)")
        app.run(host=host, port=port, threaded=True, debug=False)
