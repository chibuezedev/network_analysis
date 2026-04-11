import json
import logging
import os
import sys
import threading
import tkinter as tk
from http.server import BaseHTTPRequestHandler, HTTPServer

sys.path.insert(0, os.path.dirname(__file__))

from db.database import Database
from services.monitor import MonitorService
from ui.main_window import MainWindow

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s — %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("nids.main")


def main():
    use_sim = "--live" not in sys.argv

    logger.info("Initialising NIDS …")
    logger.info(f"Mode: {'simulation' if use_sim else 'live capture'}")

    db = Database()
    logger.info("Database ready")

    svc = MonitorService(db, use_simulation=use_sim)
    logger.info("Monitor service ready")

    class _WebhookHandler(BaseHTTPRequestHandler):
        def do_POST(self):
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length))
            ip = body.get("src_ip", "unknown")
            mac = body.get("mac", "unknown")
            attack = body.get("prediction", "Unknown")
            conf = float(body.get("confidence", 0.0))
            if attack != "Benign":
                svc._handle_alert(ip, mac, attack, conf)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{"ok": true}')

        def log_message(self, *args):
            pass  # silence webhook logs

    threading.Thread(
        target=lambda: HTTPServer(("127.0.0.1", 8001), _WebhookHandler).serve_forever(),
        daemon=True,
    ).start()
    logger.info("Webhook listener on port 8001")

    root = tk.Tk()
    root.geometry("1280x780")

    try:
        root.iconbitmap(os.path.join(os.path.dirname(__file__), "assets", "icon.ico"))
    except Exception:
        pass

    window = MainWindow(root, db, svc)  # noqa: F841

    def on_close():
        logger.info("Shutting down …")
        svc.stop()
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", on_close)
    logger.info("Starting Tkinter mainloop")
    root.mainloop()


if __name__ == "__main__":
    main()
