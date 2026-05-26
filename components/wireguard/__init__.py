"""WireGuard component for ESPHome – extended to support RP2040 (CYW43/lwIP).

Original component supports: ESP32, ESP8266, BK72xx
This fork adds: RP2040 (Raspberry Pi Pico W / rpipicow, rpipico2w)

Platform detection follows the same pattern used by the wifi component.
"""

import esphome.codegen as cg
import esphome.config_validation as cv
from esphome import automation
from esphome.components import binary_sensor, sensor, text_sensor, time as time_
from esphome.const import (
    CONF_ADDRESS,
    CONF_ENABLED,
    CONF_ID,
    CONF_PORT,
    CONF_TIME_ID,
    CONF_TRIGGER_ID,
    ENTITY_CATEGORY_DIAGNOSTIC,
    ICON_NETWORK,
    UNIT_EMPTY,
)
from esphome.core import CORE

# -----------------------------------------------------------------------
# Supported platforms
# -----------------------------------------------------------------------
SUPPORTED_PLATFORMS = ["esp32", "esp8266", "bk72xx", "rp2040"]

CODEOWNERS = ["@droscy", "@lhoracek"]
DEPENDENCIES = ["network", "time"]
AUTO_LOAD = ["binary_sensor", "sensor", "text_sensor"]

wireguard_ns = cg.esphome_ns.namespace("wireguard")
Wireguard = wireguard_ns.class_("Wireguard", cg.PollingComponent)

WireguardPeerOnlineCondition  = wireguard_ns.class_("WireguardPeerOnlineCondition",  automation.Condition)
WireguardEnabledCondition     = wireguard_ns.class_("WireguardEnabledCondition",     automation.Condition)
WireguardEnableAction         = wireguard_ns.class_("WireguardEnableAction",         automation.Action)
WireguardDisableAction        = wireguard_ns.class_("WireguardDisableAction",        automation.Action)

CONF_WIREGUARD_ID     = "wireguard_id"
CONF_PRIVATE_KEY      = "private_key"
CONF_PEER_ENDPOINT    = "peer_endpoint"
CONF_PEER_PUBLIC_KEY  = "peer_public_key"
CONF_PEER_PORT        = "peer_port"
CONF_PRESHARED_KEY    = "preshared_key"
CONF_NETMASK          = "netmask"
CONF_ALLOWED_IPS      = "allowed_ips"
CONF_KEEPALIVE        = "keepalive"
CONF_REBOOT_TIMEOUT   = "reboot_timeout"
CONF_STATUS_SENSOR    = "status"
CONF_HANDSHAKE_SENSOR = "latest_handshake"
CONF_ADDRESS_SENSOR   = "address"
CONF_REQUIRE_CONNECTION_TO_PROCEED = "require_connection_to_proceed"

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
# Schema
# -----------------------------------------------------------------------
AllowedIPSchema = cv.Schema(
    {
        cv.Required(CONF_ADDRESS): cv.ipv4address,
        cv.Optional(CONF_NETMASK, default="255.255.255.255"): cv.ipv4address,
    }
)

CONFIG_SCHEMA = cv.All(
    cv.Schema(
        {
            cv.GenerateID(): cv.declare_id(Wireguard),
            cv.GenerateID(CONF_TIME_ID): cv.use_id(time_.RealTimeClock),

            cv.Required(CONF_ADDRESS):          cv.ipv4address,
            cv.Optional(CONF_NETMASK, default="255.255.255.255"): cv.ipv4address,
            cv.Required(CONF_PRIVATE_KEY):      _wg_key,
            cv.Required(CONF_PEER_ENDPOINT):    cv.string_strict,
            cv.Required(CONF_PEER_PUBLIC_KEY):  _wg_key,
            cv.Optional(CONF_PEER_PORT,      default=51820): cv.port,
            cv.Optional(CONF_PRESHARED_KEY):    _wg_key,
            cv.Optional(CONF_ALLOWED_IPS, default=[]): cv.ensure_list(AllowedIPSchema),
            cv.Optional(CONF_KEEPALIVE,      default=0): cv.positive_int,
            cv.Optional(CONF_REBOOT_TIMEOUT, default="3min"): cv.positive_time_period_milliseconds,
            cv.Optional(CONF_REQUIRE_CONNECTION_TO_PROCEED, default=False): cv.boolean,

            # Sensors
            cv.Optional(CONF_STATUS_SENSOR):    binary_sensor.binary_sensor_schema(
                icon=ICON_NETWORK,
                entity_category=ENTITY_CATEGORY_DIAGNOSTIC,
            ),
            cv.Optional(CONF_ENABLED): binary_sensor.binary_sensor_schema(
                icon=ICON_NETWORK,
                entity_category=ENTITY_CATEGORY_DIAGNOSTIC,
            ),
            cv.Optional(CONF_HANDSHAKE_SENSOR): sensor.sensor_schema(
                unit_of_measurement=UNIT_EMPTY,
                entity_category=ENTITY_CATEGORY_DIAGNOSTIC,
            ),
            cv.Optional(CONF_ADDRESS_SENSOR): text_sensor.text_sensor_schema(
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
    """Return the correct WireGuard library for the current platform."""
    if CORE.is_rp2040:
        # ciniml's WireGuard-ESP32-Arduino works on any lwIP platform.
        # The arduino-pico core ships lwIP so this compiles cleanly.
        return ["ciniml/WireGuard-ESP32-Arduino@^0.3.1"]
    else:
        # Upstream esp_wireguard (IDF component / Arduino wrapper)
        return ["droscy/esp_wireguard@^0.3.3"]

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

    if CONF_PRESHARED_KEY in config:
        cg.add(var.set_preshared_key(config[CONF_PRESHARED_KEY]))

    # Allowed IPs
    allowed_ips = []
    for ip_conf in config[CONF_ALLOWED_IPS]:
        allowed_ips.append(
            cg.StructInitializer(
                "esphome::wireguard::AllowedIP",
                ("ip",      str(ip_conf[CONF_ADDRESS])),
                ("netmask", str(ip_conf[CONF_NETMASK])),
            )
        )
    if allowed_ips:
        cg.add(var.set_allowed_ips(allowed_ips))

    cg.add(var.set_keepalive(config[CONF_KEEPALIVE]))
    cg.add(var.set_reboot_timeout(config[CONF_REBOOT_TIMEOUT]))

    if config[CONF_REQUIRE_CONNECTION_TO_PROCEED]:
        cg.add(var.disable_auto_proceed())

    # Optional sensors
    if CONF_STATUS_SENSOR in config:
        sens = await binary_sensor.new_binary_sensor(config[CONF_STATUS_SENSOR])
        cg.add(var.set_status_sensor(sens))

    if CONF_ENABLED in config:
        sens = await binary_sensor.new_binary_sensor(config[CONF_ENABLED])
        cg.add(var.set_enabled_sensor(sens))

    if CONF_HANDSHAKE_SENSOR in config:
        sens = await sensor.new_sensor(config[CONF_HANDSHAKE_SENSOR])
        cg.add(var.set_handshake_sensor(sens))

    if CONF_ADDRESS_SENSOR in config:
        sens = await text_sensor.new_text_sensor(config[CONF_ADDRESS_SENSOR])
        cg.add(var.set_address_sensor(sens))

    # Platform-specific library
    for lib in _get_lib_deps():
        cg.add_library(*lib.split("@", 1) if "@" in lib else (lib, None))

    # Tell ESPHome to define USE_WIREGUARD
    cg.add_define("USE_WIREGUARD")

# -----------------------------------------------------------------------
# Automation helpers (unchanged from upstream)
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
