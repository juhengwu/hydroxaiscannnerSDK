"""Configuration management for HydroxAI.

This module provides a centralized configuration system that supports:
- YAML configuration files
- Environment variable overrides
- Programmatic configuration updates
- Path resolution for resources
"""

import os
import yaml
from pathlib import Path
from typing import Any, Dict, Optional, Union
from dataclasses import dataclass, field


@dataclass
class Config:
    """Configuration container with support for nested access."""
    
    _data: Dict[str, Any] = field(default_factory=dict)
    _project_root: Optional[Path] = None
    
    def __post_init__(self):
        """Initialize the configuration after creation."""
        if self._project_root is None:
            self._project_root = self._find_project_root()
    
    @staticmethod
    def _find_project_root() -> Path:
        """Find the project root directory by looking for pyproject.toml."""
        current = Path(__file__).parent
        while current != current.parent:
            if (current / "pyproject.toml").exists():
                return current
            current = current.parent
        raise FileNotFoundError("Could not find project root (no pyproject.toml found)")
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value using dot notation (e.g., 'scanner.timeout')."""
        keys = key.split('.')
        value = self._data
        
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        
        return value
    
    def set(self, key: str, value: Any) -> None:
        """Set configuration value using dot notation."""
        keys = key.split('.')
        data = self._data
        
        for k in keys[:-1]:
            if k not in data:
                data[k] = {}
            data = data[k]
        
        data[keys[-1]] = value
    
    def get_resource_path(self, resource_key: str) -> Path:
        """Get absolute path to a resource file.
        
        Args:
            resource_key: Dot notation key for the resource (e.g., 'chatbot.selectors_file')
            
        Returns:
            Absolute path to the resource file
            
        Raises:
            FileNotFoundError: If the resource file doesn't exist
        """
        base_dir = self.get('resources.base_dir', 'data')
        resource_path = self.get(f'resources.{resource_key}')
        
        if not resource_path:
            raise ValueError(f"Resource key '{resource_key}' not found in configuration")
        
        full_path = self._project_root / base_dir / resource_path
        
        if not full_path.exists():
            raise FileNotFoundError(f"Resource file not found: {full_path}")
        
        return full_path
    
    def get_resource_dir(self, resource_key: str) -> Path:
        """Get absolute path to a resource directory."""
        base_dir = self.get('resources.base_dir', 'data')
        resource_path = self.get(f'resources.{resource_key}')
        
        if not resource_path:
            raise ValueError(f"Resource key '{resource_key}' not found in configuration")
        
        full_path = self._project_root / base_dir / resource_path
        
        if not full_path.exists():
            raise FileNotFoundError(f"Resource directory not found: {full_path}")
        
        return full_path
    
    def update(self, other: Dict[str, Any]) -> None:
        """Update configuration with another dictionary."""
        self._deep_update(self._data, other)
    
    @staticmethod
    def _deep_update(base_dict: Dict[str, Any], update_dict: Dict[str, Any]) -> None:
        """Recursively update nested dictionaries."""
        for key, value in update_dict.items():
            if isinstance(value, dict) and key in base_dict and isinstance(base_dict[key], dict):
                Config._deep_update(base_dict[key], value)
            else:
                base_dict[key] = value
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary."""
        return self._data.copy()


class ConfigManager:
    """Manages configuration loading and environment variable overrides."""
    
    def __init__(self):
        self._config: Optional[Config] = None
        # Look for config directory relative to project root
        project_root = Config._find_project_root()
        self._config_dir = project_root / "config"
    
    def load_config(self, config_name: str = "default") -> Config:
        """Load configuration from YAML file with environment variable overrides.
        
        Args:
            config_name: Name of the config file (without .yaml extension)
            
        Returns:
            Loaded and processed configuration
        """
        # Load base configuration
        config_file = self._config_dir / f"{config_name}.yaml"
        
        if not config_file.exists():
            raise FileNotFoundError(f"Configuration file not found: {config_file}")
        
        with config_file.open('r', encoding='utf-8') as f:
            config_data = yaml.safe_load(f)
        
        config = Config(_data=config_data)
        
        # Apply environment variable overrides
        self._apply_env_overrides(config)
        
        # Load user configuration if it exists
        user_config_file = self._config_dir / "user.yaml"
        if user_config_file.exists():
            with user_config_file.open('r', encoding='utf-8') as f:
                user_config_data = yaml.safe_load(f)
                config.update(user_config_data)
        
        self._config = config
        return config
    
    def _apply_env_overrides(self, config: Config) -> None:
        """Apply environment variable overrides to configuration.
        
        Environment variables should be prefixed with HYDROXAI_ and use
        double underscores to separate nested keys.
        
        Example: HYDROXAI_SCANNER__TIMEOUT=120 sets scanner.timeout to 120
        """
        prefix = "HYDROXAI_"
        
        for env_key, env_value in os.environ.items():
            if not env_key.startswith(prefix):
                continue
            
            # Convert environment variable name to config key
            config_key = env_key[len(prefix):].lower().replace('__', '.')
            
            # Try to convert value to appropriate type
            try:
                # Try boolean first
                if env_value.lower() in ('true', 'false'):
                    value = env_value.lower() == 'true'
                # Try integer
                elif env_value.isdigit():
                    value = int(env_value)
                # Try float
                elif '.' in env_value and env_value.replace('.', '').isdigit():
                    value = float(env_value)
                # Keep as string
                else:
                    value = env_value
                
                config.set(config_key, value)
                
            except Exception:
                # If conversion fails, keep as string
                config.set(config_key, env_value)
    
    def get_config(self) -> Config:
        """Get the current configuration, loading default if not loaded."""
        if self._config is None:
            self._config = self.load_config()
        return self._config


# Global configuration manager instance
_config_manager = ConfigManager()


def get_config() -> Config:
    """Get the global configuration instance."""
    return _config_manager.get_config()


def load_config(config_name: str = "default") -> Config:
    """Load a specific configuration."""
    return _config_manager.load_config(config_name)


def get_resource_path(resource_key: str) -> Path:
    """Convenience function to get resource path."""
    return get_config().get_resource_path(resource_key)


def get_resource_dir(resource_key: str) -> Path:
    """Convenience function to get resource directory path."""
    return get_config().get_resource_dir(resource_key)
