"""WireGuard component for ESPHome – extended to support RP2040 (CYW43/lwIP).

Original component supports: ESP32, ESP8266, BK72xx
This fork adds: RP2040 (Raspberry Pi Pico W / rpipicow, rpipico2w)

All YAML parameter names are identical to the official component:
  https://esphome.io/components/wireguard/
"""

import esphome.codegen as cg
import esphome.config_validation as cv
from esphome import automation
from esphome.components import binary_sensor, sensor, text_sensor, time as time_
from esphome.const import (
    CONF_ADDRESS,
    CONF_ID,
    CONF_TIME_ID,
    ENTITY_CATEGORY_DIAGNOSTIC,
)
from esphome.core import CORE

# Define locally – not reliably present in esphome.const across all versions
ICON_NETWORK = "mdi:network"
UNIT_EMPTY   = ""

# -----------------------------------------------------------------------
# Supported platforms
# -----------------------------------------------------------------------
SUPPORTED_PLATFORMS = ["esp32", "esp8266", "bk72xx", "rp2040"]

CODEOWNERS = ["@droscy", "@lhoracek"]
DEPENDENCIES = ["network", "time"]
AUTO_LOAD = ["binary_sensor", "sensor", "text_sensor"]

wireguard_ns = cg.esphome_ns.namespace("wireguard")
Wireguard = wireguard_ns.class_("Wireguard", cg.PollingComponent)

WireguardPeerOnlineCondition = wireguard_ns.class_("WireguardPeerOnlineCondition", automation.Condition)
WireguardEnabledCondition    = wireguard_ns.class_("WireguardEnabledCondition",    automation.Condition)
WireguardEnableAction        = wireguard_ns.class_("WireguardEnableAction",        automation.Action)
WireguardDisableAction       = wireguard_ns.class_("WireguardDisableAction",       automation.Action)

CONF_WIREGUARD_ID = "wireguard_id"

# ---- exact official parameter names from https://esphome.io/components/wireguard/ ----
CONF_PRIVATE_KEY                    = "private_key"
CONF_PEER_ENDPOINT                  = "peer_endpoint"
CONF_PEER_PORT                      = "peer_port"
CONF_PEER_PUBLIC_KEY                = "peer_public_key"
CONF_PEER_PRESHARED_KEY             = "peer_preshared_key"
CONF_NETMASK                        = "netmask"
CONF_PEER_ALLOWED_IPS               = "peer_allowed_ips"
CONF_PEER_PERSISTENT_KEEPALIVE      = "peer_persistent_keepalive"
CONF_REBOOT_TIMEOUT                 = "reboot_timeout"
CONF_REQUIRE_CONNECTION_TO_PROCEED  = "require_connection_to_proceed"

# sensor sub-keys (used inside binary_sensor:/sensor:/text_sensor: platform: wireguard)
CONF_STATUS          = "status"
CONF_ENABLED         = "enabled"
CONF_LATEST_HANDSHAKE = "latest_handshake"

# WireGuard base64 key – 44 chars ending in '='
_WG_KEY_RE = r"^[A-Za-z0-9+/]{43}=$"

def _wg_key(value):
    import re
    value = cv.string_strict(value)
    if not re.match(_WG_KEY_RE, value):
        raise cv.Invalid(
            "WireGuard key must be a 44-character base64 string ending with '='"
        )
    return value

# -----------------------------------------------------------------------
# Validate that the platform is supported
# -----------------------------------------------------------------------
def _validate_platform(config):
    platform = CORE.target_platform
    if platform not in SUPPORTED_PLATFORMS:
        raise cv.Invalid(
            f"WireGuard is not supported on platform '{platform}'. "
            f"Supported platforms: {', '.join(SUPPORTED_PLATFORMS)}"
        )
    return config

# -----------------------------------------------------------------------
# Schema – mirrors the official component exactly
# -----------------------------------------------------------------------
AllowedIPSchema = cv.Schema(
    {
        cv.Required(CONF_ADDRESS): cv.ipv4address,
        cv.Optional("mask"): cv.ipv4address,  # CIDR mask part (optional)
    }
)

CONFIG_SCHEMA = cv.All(
    cv.Schema(
        {
            cv.GenerateID(): cv.declare_id(Wireguard),
            cv.GenerateID(CONF_TIME_ID): cv.use_id(time_.RealTimeClock),

            # Required
            cv.Required(CONF_ADDRESS):         cv.ipv4address,
            cv.Required(CONF_PRIVATE_KEY):     _wg_key,
            cv.Required(CONF_PEER_ENDPOINT):   cv.string_strict,
            cv.Required(CONF_PEER_PUBLIC_KEY): _wg_key,

            # Optional – defaults match official docs
            cv.Optional(CONF_NETMASK, default="255.255.255.255"): cv.ipv4address,
            cv.Optional(CONF_PEER_PORT, default=51820): cv.port,
            cv.Optional(CONF_PEER_PRESHARED_KEY): _wg_key,
            cv.Optional(CONF_PEER_ALLOWED_IPS, default=[]): cv.ensure_list(
                cv.Any(
                    cv.ipv4address,         # plain IP  e.g. 10.0.0.1
                    cv.string_strict,       # CIDR      e.g. 10.0.0.0/24
                )
            ),
            cv.Optional(CONF_PEER_PERSISTENT_KEEPALIVE, default="0s"): cv.positive_time_period_milliseconds,
            cv.Optional(CONF_REBOOT_TIMEOUT, default="15min"): cv.positive_time_period_milliseconds,
            cv.Optional(CONF_REQUIRE_CONNECTION_TO_PROCEED, default=False): cv.boolean,

            # Inline sensors (same as official component)
            cv.Optional(CONF_STATUS): binary_sensor.binary_sensor_schema(
                icon=ICON_NETWORK,
                entity_category=ENTITY_CATEGORY_DIAGNOSTIC,
            ),
            cv.Optional(CONF_ENABLED): binary_sensor.binary_sensor_schema(
                icon=ICON_NETWORK,
                entity_category=ENTITY_CATEGORY_DIAGNOSTIC,
            ),
            cv.Optional(CONF_LATEST_HANDSHAKE): sensor.sensor_schema(
                unit_of_measurement=UNIT_EMPTY,
                entity_category=ENTITY_CATEGORY_DIAGNOSTIC,
            ),
            cv.Optional(CONF_ADDRESS): text_sensor.text_sensor_schema(
                icon=ICON_NETWORK,
                entity_category=ENTITY_CATEGORY_DIAGNOSTIC,
            ),
        }
    ).extend(cv.polling_component_schema("10s")),
    _validate_platform,
)

# -----------------------------------------------------------------------
# lib_deps selection per platform
# -----------------------------------------------------------------------
def _get_lib_deps():
    if CORE.is_rp2040:
        return [("ciniml/WireGuard-ESP32-Arduino", "^0.3.1")]
    else:
        return [("droscy/esp_wireguard", "^0.3.3")]

# -----------------------------------------------------------------------
# Code generation
# -----------------------------------------------------------------------
async def to_code(config):
    var = cg.new_Pvariable(config[CONF_ID])
    await cg.register_component(var, config)

    time_var = await cg.get_variable(config[CONF_TIME_ID])
    cg.add(var.set_srctime(time_var))

    cg.add(var.set_address(str(config[CONF_ADDRESS])))
    cg.add(var.set_netmask(str(config[CONF_NETMASK])))
    cg.add(var.set_private_key(config[CONF_PRIVATE_KEY]))
    cg.add(var.set_peer_endpoint(config[CONF_PEER_ENDPOINT]))
    cg.add(var.set_peer_public_key(config[CONF_PEER_PUBLIC_KEY]))
    cg.add(var.set_peer_port(config[CONF_PEER_PORT]))

    if CONF_PEER_PRESHARED_KEY in config:
        cg.add(var.set_preshared_key(config[CONF_PEER_PRESHARED_KEY]))

    # Allowed IPs – pass as raw strings; C++ side parses them
    allowed_ips = config[CONF_PEER_ALLOWED_IPS]
    if allowed_ips:
        cg.add(var.set_allowed_ips_str(allowed_ips))

    # keepalive in seconds (uint16_t)
    keepalive_ms = config[CONF_PEER_PERSISTENT_KEEPALIVE]
    cg.add(var.set_keepalive(keepalive_ms // 1000))

    cg.add(var.set_reboot_timeout(config[CONF_REBOOT_TIMEOUT]))

    if config[CONF_REQUIRE_CONNECTION_TO_PROCEED]:
        cg.add(var.disable_auto_proceed())

    # Optional sensors
    if CONF_STATUS in config:
        sens = await binary_sensor.new_binary_sensor(config[CONF_STATUS])
        cg.add(var.set_status_sensor(sens))

    if CONF_ENABLED in config:
        sens = await binary_sensor.new_binary_sensor(config[CONF_ENABLED])
        cg.add(var.set_enabled_sensor(sens))

    if CONF_LATEST_HANDSHAKE in config:
        sens = await sensor.new_sensor(config[CONF_LATEST_HANDSHAKE])
        cg.add(var.set_handshake_sensor(sens))

    # address text sensor – only if it's the text_sensor variant
    # (CONF_ADDRESS is also used for the IP, so check type)
    if CONF_ADDRESS in config and isinstance(config[CONF_ADDRESS], dict):
        sens = await text_sensor.new_text_sensor(config[CONF_ADDRESS])
        cg.add(var.set_address_sensor(sens))

    # Platform-specific library
    for name, version in _get_lib_deps():
        cg.add_library(name, version)

    cg.add_define("USE_WIREGUARD")

# -----------------------------------------------------------------------
# Automation helpers
# -----------------------------------------------------------------------
WIREGUARD_ACTION_SCHEMA = automation.maybe_simple_id(
    {cv.GenerateID(CONF_WIREGUARD_ID): cv.use_id(Wireguard)}
)

@automation.register_action("wireguard.enable",  WireguardEnableAction,  WIREGUARD_ACTION_SCHEMA)
@automation.register_action("wireguard.disable", WireguardDisableAction, WIREGUARD_ACTION_SCHEMA)
async def wireguard_action_to_code(config, action_id, template_arg, args):
    var = cg.new_Pvariable(action_id, template_arg)
    await cg.register_parented(var, config[CONF_WIREGUARD_ID])
    return var

@automation.register_condition("wireguard.peer_online", WireguardPeerOnlineCondition, WIREGUARD_ACTION_SCHEMA)
@automation.register_condition("wireguard.enabled",     WireguardEnabledCondition,    WIREGUARD_ACTION_SCHEMA)
async def wireguard_condition_to_code(config, condition_id, template_arg, args):
    var = cg.new_Pvariable(condition_id, template_arg)
    await cg.register_parented(var, config[CONF_WIREGUARD_ID])
    return var
