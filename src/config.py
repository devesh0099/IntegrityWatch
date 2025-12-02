import json
import os
from pathlib import Path

# Default settings
DEFAULT_CONFIG = {
    "logging": {
        "console_output": False,
        "console_level": "INFO",
        "file_output": True,
        "file_path": "logs/integrity_watch.log", 
        "file_level": "DEBUG"
    },
    "output": {
        "save_json": True,
        "json_path": "results/scan_report.json",
        "heartbeat": "results/heatbeat/"
    },
    "monitoring": {
        "monitoring_interval": 5
    },
    "remote_access": {
        "allow_conference_tools": True
    },
    "browser": {
        "allow_suspicious_websites": False
    }
}

class GlobalConfig:
    _instance = None
    
    @classmethod
    def load(cls, config_file="config/settings.json"):
        if cls._instance is None:
            cls._instance = cls(config_file)
        return cls._instance

    def __init__(self, config_file):
        self.data = DEFAULT_CONFIG.copy()
        self.config_filename = config_file

        # Look for settings.json in Project Root
        self.root_dir = Path(os.getcwd())
        self.config_path = self.root_dir / config_file
        
        if self.config_path.exists():
            try:
                with open(self.config_path, 'r') as f:
                    user_config = json.load(f)
                    for section, values in user_config.items():
                        if section in self.data:
                            self.data[section].update(values)
                        else:
                            self.data[section] = values
            except Exception as e:
                print(f"[WARN] Config load failed: {e}")
        else:
            print(f"[INFO] Configuration file not found. Creating default at: {self.config_path}")
            self.save_defaults()
    
    def save_defaults(self):
        try:
            if self.config_path.parent.name:
                self.config_path.parent.mkdir(parents=True, exist_ok=True)
                
            with open(self.config_path, 'w') as f:
                json.dump(self.data, f, indent=4)
        except Exception as e:
            print(f"[ERROR] Failed to create default config file: {e}")

    def get(self, section, key, default=None):
        return self.data.get(section, {}).get(key, default)

# Initialize the config
config = GlobalConfig.load()
