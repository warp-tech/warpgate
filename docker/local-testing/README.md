# Local Testing Environments

This folder contains Docker Compose setups for testing specific Warpgate features locally.

## Available Test Environments

| Folder | Feature | Description |
|--------|---------|-------------|
| [login-protection](./login-protection/) | Login Protection / Fail2Ban-like | Test IP blocking, user lockout, and exponential backoff |

## Usage

Each subfolder contains:
- `docker-compose.yml` - Docker Compose configuration
- `data/` - Warpgate configuration and data
- `scripts/` - Test scripts
- `README.md` - Feature-specific instructions

## Quick Start

```bash
cd <feature-folder>
docker compose up -d
```

## Adding New Test Environments

1. Create a new folder: `mkdir <feature-name>`
2. Copy the structure from an existing environment
3. Customize `docker-compose.yml` and `data/warpgate.yaml`
4. Add test scripts in `scripts/`
5. Document in `README.md`
