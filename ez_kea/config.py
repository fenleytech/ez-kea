import os

# Load environment variables (from OS environment, no dotenv needed)


class Config:
    DHCP_CONFIG_FILE = os.getenv("DHCP_CONFIG_FILE", "./data/kea-dhcp4.conf")
    DHCP_LEASES_FILE = os.getenv("DHCP_LEASES_FILE", "./data/kea-leases4.csv")
    DHCP_LOG_FILE    = os.getenv("DHCP_LOG_FILE",    "./data/kea-dhcp4.log")

    # DHCPv6 equivalents — mirror the DHCPv4 settings above exactly.
    DHCP6_CONFIG_FILE = os.getenv("DHCP6_CONFIG_FILE", "./data/kea-dhcp6.conf")
    DHCP6_LEASES_FILE = os.getenv("DHCP6_LEASES_FILE", "./data/kea-leases6.csv")
    DHCP6_LOG_FILE    = os.getenv("DHCP6_LOG_FILE",    "./data/kea-dhcp6.log")

    BACKUP_DIR       = os.getenv("BACKUP_DIR",       "./data/backups/")
    SETTINGS_FILE    = os.getenv("SETTINGS_FILE",    "./data/ez-kea-settings.json")
    SECRET_KEY       = os.getenv("SECRET_KEY",       "dev")

    # SQLite DB for users, auth state, and license key.
    # Kea daemon settings continue to live in ez-kea-settings.json.
    SQLALCHEMY_DATABASE_URI        = os.getenv("DATABASE_URL", "sqlite:///" + os.path.abspath("./data/ez-kea.db"))
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Kea commands — overridable at runtime via UI (see settings_manager)
    KEA_DHCP4_CMD = os.getenv("KEA_DHCP4_CMD", "kea-dhcp4")
    KEA_DHCP6_CMD = os.getenv("KEA_DHCP6_CMD", "kea-dhcp6")
    KEA_CTRL_CMD  = os.getenv("KEA_CTRL_CMD",  "keactrl")

    # --- Docker-deployment settings -----------------------------------------
    # When KEA_DHCP4_CMD/KEA_CTRL_CMD exec into a container (e.g.
    # "docker exec <container> kea-dhcp4"), DHCP_CONFIG_FILE/DHCP_LOG_FILE
    # above are HOST paths that EZ-Kea itself reads/writes — they are not
    # necessarily valid inside the container's own filesystem namespace (the
    # volume mount may expose the same file at a different in-container
    # path). These two settings let a Docker deployment tell EZ-Kea what path
    # to pass to `-t` / write into Kea's own logger config instead. Left
    # blank (the default), both fall back to the host path above, which is
    # exactly correct for bare-metal/non-Docker deployments — so existing
    # non-Docker setups are unaffected.
    DHCP_CONFIG_FILE_IN_CONTAINER = os.getenv("DHCP_CONFIG_FILE_IN_CONTAINER", "")
    DHCP_LOG_FILE_IN_CONTAINER    = os.getenv("DHCP_LOG_FILE_IN_CONTAINER", "")
    DHCP6_CONFIG_FILE_IN_CONTAINER = os.getenv("DHCP6_CONFIG_FILE_IN_CONTAINER", "")
    DHCP6_LOG_FILE_IN_CONTAINER    = os.getenv("DHCP6_LOG_FILE_IN_CONTAINER", "")

    # Reload strategy: "keactrl" (default; runs `KEA_CTRL_CMD reload`) or
    # "sighup" (runs `docker kill -s HUP <KEA_DOCKER_CONTAINER>`). Minimal Kea
    # Docker images often lack /etc/kea/keactrl.conf, which keactrl requires
    # to run at all — "sighup" is the supported alternative for those
    # deployments. This is an explicit, documented choice, never inferred:
    # guessing wrong here is worse than requiring one extra setting.
    KEA_RELOAD_STRATEGY = os.getenv("KEA_RELOAD_STRATEGY", "keactrl")
    KEA_DOCKER_CONTAINER = os.getenv("KEA_DOCKER_CONTAINER", "")
