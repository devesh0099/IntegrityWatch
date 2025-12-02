#!/usr/bin/env python3
import sys
import json
import struct
import os
from pathlib import Path
from datetime import datetime
from typing import Optional, Any

class NativeMessagingProtocol:
    @staticmethod
    def read_message() -> Optional[dict[str, Any]]:
        try:
            length_bytes = sys.stdin.buffer.read(4)

            if len(length_bytes) == 0:
                return None
            
            if len(length_bytes) != 4:
                raise ValueError(f"Invalid length prefix: {len(length_bytes)}")
            
            message_length = struct.unpack('I', length_bytes)[0]
            message_bytes = sys.stdin.buffer.read(message_length)

            if len(message_bytes) != message_length:
                raise ValueError(f"Expected: {message_length} bytes, got {len(message_bytes)}")
            
            message_text = message_bytes.decode('utf-8')
            return json.loads(message_text)
        
        except Exception as e:
            sys.stderr.write(f"Error reading message: {e}")
            sys.stderr.flush()
            return None
        
    @staticmethod
    def send_message(message: dict[str, Any]) -> bool:
        try:
            message_text = json.dumps(message)
            message_bytes = message_text.encode('utf-8')
            message_length = len(message_bytes)

            sys.stdout.buffer.write(struct.pack('I', message_length))
            sys.stdout.buffer.write(message_bytes)
            sys.stdout.buffer.flush()

            return True
        except Exception as e:
            sys.stderr.write(f"Error sending message: {e}")
            sys.stderr.flush()
            return False
        

class NativeHostHandler:
    def __init__(self, runtime_dir: Path):
        self.runtime_dir = runtime_dir
        self.runtime_dir.mkdir(parents=True, exist_ok=True)

        self.violations_file = runtime_dir / 'violations.json'
        self.heartbeat_file = runtime_dir / 'heartbeat.json'
        self.status_file = runtime_dir / 'status.json'

        self.message_handlers: dict[str, callable] = {
            'EXTENSION_READY': self._handle_extension_ready,
            'HEARTBEAT': self._handle_heartbeat,
            'VIOLATION': self._handle_violation,
            'PONG': self._handle_pong,
            'SCREEN_SHARE_STOPPED': self._handle_screen_share_stopped,
        }

        self._running = False
        self._clear_old_data()

    def _clear_old_data(self):
        for file in [self.violations_file, self.heartbeat_file, self.status_file]:
            if file.exists():
                try:
                    file.unlink()
                except Exception as e:
                    sys.stderr.write(f"Failed to clear {file.name}: {e}")
                    sys.stderr.flush()

        sys.stderr.write("Cleared previous session data")
        sys.stderr.flush()

    def start(self):
        sys.stderr.write("=" * 60)
        sys.stderr.flush()
        sys.stderr.write("IntegrityWatch Native Host Started")
        sys.stderr.flush()
        sys.stderr.write(f"Runtime directory: {self.runtime_dir}")
        sys.stderr.flush()
        sys.stderr.write(f"PID: {os.getpid()}")
        sys.stderr.flush()
        sys.stderr.write("=" * 60)
        sys.stderr.flush()

        self._running = True
        self._write_status("RUNNING")

        try:
            while self._running:
                message = NativeMessagingProtocol.read_message()

                if message is None:
                    sys.stderr.write("Extension disconnected (stdin EOF)")
                    sys.stderr.flush()
                    break

                self._route_message(message)

        except KeyboardInterrupt:
            sys.stderr.write("Native host interrupted by user")
            sys.stderr.flush()
        except Exception as e:
            sys.stderr.write(f"Fatal error in main loop: {e}")
            sys.stderr.flush()
        finally:
            self._write_status('STOPPED')
            sys.stderr.write("Native host shutting down")
            sys.stderr.flush()

    def _route_message(self, message: dict[str, Any]):
        msg_type = message.get('type', 'UNKNOWN')
        sys.stderr.write(f"Received message type: {msg_type}")
        sys.stderr.flush()

        handler = self.message_handlers.get(msg_type)

        if handler:
            try:
                handler(message)
            except Exception as e:
                sys.stderr.write(f"handler failed for {msg_type}: {e}")
                sys.stderr.flush()
        else:
            sys.stderr.write(f"Unknown message type: {msg_type}")
            sys.stderr.flush()
    
    def _handle_extension_ready(self, message: dict[str, Any]):
        sys.stderr.write("Extension connected")
        sys.stderr.flush()

        response = {
            'type': 'START_MONITORING',
            'config': {
                'interval': 5,
                'suspiciousDomains': [
                    'meet.google.com',
                    'teams.microsoft.com',
                    'zoom.us',
                    'discord.com',
                    'whereby.com',
                    'jitsi.org',
                    '8x8.vc',
                    'webex.com'
                ]
            }
        }

        if NativeMessagingProtocol.send_message(response):
            sys.stderr.write("Sent START_MONITORING command to extension")
            sys.stderr.flush()
        else:
            sys.stderr.write("Failed to send START_MONITORING command")
            sys.stderr.flush()

    def _handle_heartbeat(self, message: dict[str, Any]):
        timestamp = message.get('timestamp', datetime.now().timestamp() * 1000)
        data = message.get('data', {})

        heartbeat_data = {
            'type': 'heartbeat',
            'timestamp': timestamp,
            'received_at': datetime.now().isoformat(),
            'data': data
        }

        try:
            with open(self.heartbeat_file, 'w') as f:
                json.dump(heartbeat_data, f, indent=2)

            total_tabs = data.get('totalTabs', 0)
            suspicious_count = data.get('suspiciousTabCount', 0)

            if suspicious_count > 0:
                sys.stderr.write(f"Heartbeat: {total_tabs} tabs, {suspicious_count} SUSPICIOUS")
                sys.stderr.flush()
                for tab in data.get('suspiciousTabs', []):
                    sys.stderr.write(f"  → Suspicious: {tab.get('url', 'unknown')}")
                    sys.stderr.flush()
                
            else:
                sys.stderr.write(f"Heartbeat: {total_tabs} tabs, {suspicious_count} suspicious")
                sys.stderr.flush()

        except Exception as e:
            sys.stderr.write(f"Failed to write heartbeat: {e}")
            sys.stderr.flush()

    def _handle_violation(self, message: dict[str, Any]):
        violation_type = message.get('violationType', 'UNKNOWN')
        timestamp = message.get('timestamp', datetime.now().timestamp() * 1000)
        details = message.get('details', {})

        violation_data = {
            'type': violation_type,
            'timestamp': timestamp,
            'detected_at': datetime.now().isoformat(),
            'details': details
        }

        try:
            violations = []
            if self.violations_file.exists():
                with open(self.violations_file, 'r') as f:
                    violations = json.load(f)
            
            violations.append(violation_data)
            
            with open(self.violations_file, 'w') as f:
                json.dump(violations, f, indent=2)
            
            sys.stderr.write("=" * 60)
            sys.stderr.flush()
            sys.stderr.write(f"VIOLATION DETECTED: {violation_type}")
            sys.stderr.flush()
            sys.stderr.write(f"Timestamp: {datetime.fromtimestamp(timestamp/1000).isoformat()}")
            sys.stderr.flush()
          
            if violation_type == 'SCREEN_SHARE_DETECTED':
                sys.stderr.write(f"URL: {details.get('url', 'N/A')}")
                sys.stderr.flush()
                sys.stderr.write(f"Tab: {details.get('title', 'N/A')}")
                sys.stderr.flush()
                sys.stderr.write(f"Constraints: {details.get('constraints', {})}")
                sys.stderr.flush()
            elif 'TAB' in violation_type:
                sys.stderr.write(f"URL: {details.get('url', 'N/A')}")
                sys.stderr.flush()
                sys.stderr.write(f"Tab ID: {details.get('tabId', 'N/A')}")
                sys.stderr.flush()
                sys.stderr.write(f"Title: {details.get('title', 'N/A')}")
                sys.stderr.flush()
            
            sys.stderr.write("=" * 60)
            sys.stderr.flush()
            
        except Exception as e:
            sys.stderr.write(f"Failed to write violation: {e}")
            sys.stderr.flush()
        
    def _handle_pong(self, message: dict[str, Any]):
        sys.stderr.write("Received PONG from extension")
        sys.stderr.flush()
    
    def _handle_screen_share_stopped(self, message: dict[str, Any]):
        data = message.get('data', {})
        tab_id = data.get('tabId', 'unknown')
        url = data.get('url', 'unknown')
        
        sys.stderr.write(f"Screen sharing stopped: Tab {tab_id} ({url})")
        sys.stderr.flush()

    
    def _write_status(self, status: str):
        try:
            status_data = {
                'status': status,
                'timestamp': datetime.now().isoformat(),
                'pid': os.getpid()
            }
            
            with open(self.status_file, 'w') as f:
                json.dump(status_data, f, indent=2)
            
            sys.stderr.write(f"Status updated: {status}")
            sys.stderr.flush()
                
        except Exception as e:
            sys.stderr.write(f"Failed to write status: {e}")
            sys.stderr.flush()


def main():
    project_root = Path(__file__).parent.parent.parent.parent
    runtime_dir = project_root / 'runtime' / 'browser'

    handler = NativeHostHandler(runtime_dir)
    handler.start()

if __name__ == '__main__':
    main()