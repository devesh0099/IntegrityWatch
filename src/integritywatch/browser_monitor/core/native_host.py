#!/usr/bin/env python3
import sys
import json
import struct
import os
from pathlib import Path
from datetime import datetime
from typing import Optional, Any
import threading
import queue
import time

RUNTIME_DIR = Path.home() / ".integritywatch" / "runtime" / "browser"
RUNTIME_DIR.mkdir(parents=True, exist_ok=True)

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
            sys.stderr.write(f"Error reading message: {e}\n")
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
            sys.stderr.write(f"Error sending message: {e}\n")
            sys.stderr.flush()
            return False
        

class NativeHostHandler:
    def __init__(self, runtime_dir: Path, config_file: Path):
        self.runtime_dir = runtime_dir
        self.runtime_dir.mkdir(parents=True, exist_ok=True)

        self.config_file = config_file

        self._msg_queue = queue.Queue()

        self.violations_file = runtime_dir / 'violations.json'
        self.heartbeat_file = runtime_dir / 'heartbeat.json'
        self.status_file = runtime_dir / 'status.json'
        self.command_file = runtime_dir / 'command.json'

        self.message_handlers: dict[str, callable] = {
            'EXTENSION_READY': self._handle_extension_ready,
            'HEARTBEAT': self._handle_heartbeat,
            'VIOLATION': self._handle_violation,
            'PONG': self._handle_pong,
            'SCREEN_SHARE_STOPPED': self._handle_screen_share_stopped,
        }

        self._running = False
        self._monitoring_active = False 
        self._clear_old_data()

    def _read_stdin(self):
        try:
            while self._running:
                msg = NativeMessagingProtocol.read_message()
                if msg is None:
                    self._running = False 
                    break
                if self._running: 
                    self._msg_queue.put(msg)
        except Exception as e:
            sys.stderr.write(f"Stdin reader error: {e}\n")
            sys.stderr.flush()
            self._running = False


    def _clear_old_data(self):
        for file in [self.violations_file, self.heartbeat_file, self.status_file]:
            if file.exists():
                try:
                    file.unlink()
                except Exception as e:
                    sys.stderr.write(f"Failed to clear {file.name}: {e}\n")
                    sys.stderr.flush()

        sys.stderr.write("Cleared previous session data\n")
        sys.stderr.flush()

    def start(self):
        sys.stderr.write("IntegrityWatch Native Host Started\n")
        sys.stderr.write(f"Runtime directory: {self.runtime_dir}\n")
        sys.stderr.write(f"PID: {os.getpid()}\n")
        sys.stderr.write("Waiting for CLI to start monitoring...\n")
        sys.stderr.flush()
        
        self._running = True
        self._write_status("RUNNING")
        
        threading.Thread(target=self._read_stdin, daemon=True).start()
        
        last_command_check = 0
        
        try:
            while self._running:
                current_time = time.time()
                if current_time - last_command_check > 1.0:
                    self._check_command_file()
                    last_command_check = current_time
                
                try:
                    message = self._msg_queue.get(timeout=0.1)
                    
                    if message is None:
                        sys.stderr.write("Extension disconnected (stdin EOF)\n")
                        sys.stderr.flush()
                        break
                    
                    self._route_message(message)
                except queue.Empty:
                    pass  
        
        except KeyboardInterrupt:
            sys.stderr.write("Native host interrupted by user\n")
            sys.stderr.flush()
        except Exception as e:
            sys.stderr.write(f"Fatal error in main loop: {e}\n")
            import traceback
            sys.stderr.write(traceback.format_exc())
            sys.stderr.flush()
        finally:
            self._running = False
            self._write_status('STOPPED')
            sys.stderr.write("Native host shutting down\n")
            sys.stderr.flush()


    def _route_message(self, message: dict[str, Any]):
        msg_type = message.get('type', 'UNKNOWN')
        sys.stderr.write(f"Received message type: {msg_type}\n")
        sys.stderr.flush()

        handler = self.message_handlers.get(msg_type)

        if handler:
            try:
                handler(message)
            except Exception as e:
                sys.stderr.write(f"handler failed for {msg_type}: {e}\n")
                sys.stderr.flush()
        else:
            sys.stderr.write(f"Unknown message type: {msg_type}\n")
            sys.stderr.flush()
    
    def _handle_extension_ready(self, message: dict[str, Any]):
        sys.stderr.write("Extension connected - waiting for CLI\n")
        sys.stderr.flush()

    def _check_command_file(self):
        if not self.command_file.exists():
            return
        
        try:
            with open(self.command_file, 'r') as f:
                command_data = json.load(f)
            
            command = command_data.get('command')
            
            if command == 'START_MONITORING' and not self._monitoring_active:
                sys.stderr.write("CLI STARTED - Initiating monitoring\n")
                sys.stderr.flush()
                
                self._monitoring_active = True
                
                try:
                    with open(self.config_file, 'r') as f:
                        config_data = json.load(f)
                    target_website = config_data.get('browser', {}).get('target_website', 'leetcode.com')
                except:
                    target_website = 'leetcode.com'
                
                response = {
                    'type': 'START_MONITORING',
                    'config': {
                        'interval': 5,
                        'targetWebsite': target_website,
                        'suspiciousDomains': [
                            'meet.google.com',
                            'teams.microsoft.com',
                            'zoom.us',
                            'discord.com',
                            'slack.com',
                            'whatsapp.com',
                            'telegram.org',
                            'messenger.com',
                            'chat.google.com',
                            'hangouts.google.com',
                            'whereby.com',
                            'jitsi.org',
                            '8x8.vc',
                            'webex.com'
                        ]
                    }
                }
                
                if NativeMessagingProtocol.send_message(response):
                    sys.stderr.write("Sent START_MONITORING to extension\n")
                    sys.stderr.flush()
            
            elif command == 'STOP_MONITORING':
                sys.stderr.write("CLI STOPPED - Stopping monitoring\n")
                sys.stderr.flush()
                
                self._monitoring_active = False
                
                NativeMessagingProtocol.send_message({'type': 'STOP_MONITORING'})
            
            self.command_file.unlink()
            
        except Exception as e:
            sys.stderr.write(f"Error processing command: {e}\n")
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
                sys.stderr.write(f"Heartbeat: {total_tabs} tabs, {suspicious_count} SUSPICIOUS\n")
                sys.stderr.flush()
                for tab in data.get('suspiciousTabs', []):
                    sys.stderr.write(f"  → Suspicious: {tab.get('url', 'unknown')}\n")
                    sys.stderr.flush()
                
            else:
                sys.stderr.write(f"Heartbeat: {total_tabs} tabs, {suspicious_count} suspicious\n")
                sys.stderr.flush()

        except Exception as e:
            sys.stderr.write(f"Failed to write heartbeat: {e}\n")
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
            
            sys.stderr.write(f"VIOLATION DETECTED: {violation_type}\n")
            sys.stderr.write(f"Timestamp: {datetime.fromtimestamp(timestamp/1000).isoformat()}\n")
          
            if violation_type == 'SCREEN_SHARE_DETECTED':
                sys.stderr.write(f"URL: {details.get('url', 'N/A')}\n")
                sys.stderr.flush()
                sys.stderr.write(f"Tab: {details.get('title', 'N/A')}\n")
                sys.stderr.flush()
                sys.stderr.write(f"Constraints: {details.get('constraints', {})}\n")
                sys.stderr.flush()
            elif 'TAB' in violation_type:
                sys.stderr.write(f"URL: {details.get('url', 'N/A')}\n")
                sys.stderr.flush()
                sys.stderr.write(f"Tab ID: {details.get('tabId', 'N/A')}\n")
                sys.stderr.flush()
                sys.stderr.write(f"Title: {details.get('title', 'N/A')}\n")
                sys.stderr.flush()
            
            
        except Exception as e:
            sys.stderr.write(f"Failed to write violation: {e}\n")
            sys.stderr.flush()
        
    def _handle_pong(self, message: dict[str, Any]):
        sys.stderr.write("Received PONG from extension\n")
        sys.stderr.flush()
    
    def _handle_screen_share_stopped(self, message: dict[str, Any]):
        data = message.get('data', {})
        tab_id = data.get('tabId', 'unknown')
        url = data.get('url', 'unknown')
        
        sys.stderr.write(f"Screen sharing stopped: Tab {tab_id} ({url})\n")
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
            
            sys.stderr.write(f"Status updated: {status}\n")
            sys.stderr.flush()
                
        except Exception as e:
            sys.stderr.write(f"Failed to write status: {e}\n")
            sys.stderr.flush()


def main():
    from pathlib import Path
    
    try:
        potential_root = RUNTIME_DIR
        if (potential_root / 'runtime').exists():
            project_root = potential_root
        else:
            project_root = Path.home() / '.integritywatch'
    except:
        project_root = Path.home() / '.integritywatch'
    
    runtime_dir = project_root / 'runtime' / 'browser'
    config_file = project_root / 'config' / 'settings.json'
    
    handler = NativeHostHandler(runtime_dir, config_file)
    handler.start()

if __name__ == '__main__':
    main()