# users/consumers.py

import json
import threading
from channels.generic.websocket import WebsocketConsumer
from .live_sniffer import packet_stream

class DetectionConsumer(WebsocketConsumer):
    def connect(self):
        self.accept()

        def stream():
            for data in packet_stream():
                self.send(text_data=json.dumps(data))

        threading.Thread(target=stream, daemon=True).start()
