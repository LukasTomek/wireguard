#include "wireguard.h"
#ifdef USE_WIREGUARD

#include <cinttypes>
#include <ctime>

#include "esphome/core/application.h"
#include "esphome/core/log.h"
#include "esphome/core/time.h"
#include "esphome/components/network/util.h"
#include "esphome/core/helpers.h"

// ---------------------------------------------------------------------------
// Platform-specific includes
// ---------------------------------------------------------------------------
#ifdef USE_RP2040
  // arduino-pico ships lwIP; no IDF, no esp_err_t, no WDT API.
  // We map the RP2040 SDK watchdog calls.
  #include <hardware/watchdog.h>
  // lwIP mutex (same as the upstream LwIPLock pattern but for arduino-pico)
  #include <lwip/tcpip.h>
  #include <lwip/dns.h>
#else
  // ESP32 / ESP8266 / BK72xx path – identical to upstream
#endif

namespace esphome {
namespace wireguard {

static const char *const TAG = "wireguard";

/*
 * Cannot use `static const char*` for LOGMSG_PEER_STATUS on esp8266 platform
 * because log messages in `Wireguard::update()` method fail.
 */
#define LOGMSG_PEER_STATUS "Remote peer is %s (latest handshake %s)"

static const char *const LOGMSG_ONLINE  = "online";
static const char *const LOGMSG_OFFLINE = "offline";

// ---------------------------------------------------------------------------
// WDT helpers
// ---------------------------------------------------------------------------

#ifdef USE_RP2040
void suspend_wdt() {
  // arduino-pico watchdog: update it to give DNS up to 30 s slack.
  // There is no official "disable" without a reboot, so we just tickle it.
  watchdog_update();
}
void resume_wdt() { watchdog_update(); }
#else
void suspend_wdt() {
#  if defined(USE_ESP32)
  // esp_task_wdt_reset() is the safe call; full disable is too aggressive.
  // The upstream component does nothing here in the current source but we
  // keep the hook for future use.
#  endif
}
void resume_wdt() {}
#endif

// ---------------------------------------------------------------------------
// setup()
// ---------------------------------------------------------------------------

void Wireguard::setup() {
  this->publish_enabled_state();

#ifdef USE_RP2040
  // -----------------------------------------------------------------------
  // RP2040 path: use WireGuard-ESP32 C++ class (pure-lwIP implementation).
  // Library: https://github.com/ciniml/WireGuard-ESP32-Arduino
  // It compiles fine on arduino-pico because it only uses lwIP primitives.
  // -----------------------------------------------------------------------
  ESP_LOGI(TAG, "Initialising WireGuard (RP2040/lwIP path)");

  // The library's begin() does DNS resolution + lwIP netif setup in one call.
  // We defer the actual connect to start_connection_() so that WiFi / SNTP
  // are ready first (same pattern as upstream).
  this->wg_initialized_ = true;   // mark as ready; connection happens later

  this->srctime_->add_on_time_sync_callback([this]() { this->start_connection_(); });
  this->defer([this]() { this->start_connection_(); });

#ifdef USE_TEXT_SENSOR
  if (this->address_sensor_ != nullptr) {
    this->address_sensor_->publish_state(this->address_);
  }
#endif

#else
  // -----------------------------------------------------------------------
  // Upstream ESP32 / ESP8266 / BK72xx path (unchanged from official source)
  // -----------------------------------------------------------------------
  this->wg_config_.address           = this->address_;
  this->wg_config_.private_key       = this->private_key_;
  this->wg_config_.endpoint          = this->peer_endpoint_;
  this->wg_config_.public_key        = this->peer_public_key_;
  this->wg_config_.port              = this->peer_port_;
  this->wg_config_.netmask           = this->netmask_;
  this->wg_config_.persistent_keepalive = this->keepalive_;

  if (this->preshared_key_ != nullptr)
    this->wg_config_.preshared_key = this->preshared_key_;

  this->publish_enabled_state();

  {
    LwIPLock lock;
    this->wg_initialized_ = esp_wireguard_init(&(this->wg_config_), &(this->wg_ctx_));
  }

  if (this->wg_initialized_ == ESP_OK) {
    ESP_LOGI(TAG, "Initialized");
    this->wg_peer_offline_time_ = millis();
    this->srctime_->add_on_time_sync_callback([this]() { this->start_connection_(); });
    this->defer([this]() { this->start_connection_(); });

#ifdef USE_TEXT_SENSOR
    if (this->address_sensor_ != nullptr) {
      this->address_sensor_->publish_state(this->address_);
    }
#endif
  } else {
    ESP_LOGE(TAG, "Cannot initialize: error code %d", this->wg_initialized_);
    this->mark_failed();
  }
#endif  // USE_RP2040
}

// ---------------------------------------------------------------------------
// loop()
// ---------------------------------------------------------------------------

void Wireguard::loop() {
  if (!this->enabled_) {
    return;

#ifdef USE_RP2040
  if (this->wg_initialized_ && this->wg_connected_ && !network::is_connected()) {
    ESP_LOGV(TAG, "Local network connection has been lost, stopping WireGuard...");
    this->stop_connection_();
  }
#else
  if ((this->wg_initialized_ == ESP_OK) && (this->wg_connected_ == ESP_OK) && (!network::is_connected())) {
    ESP_LOGV(TAG, "Local network connection has been lost, stopping WireGuard...");
    this->stop_connection_();
  }
#endif
}

// ---------------------------------------------------------------------------
// update()
// ---------------------------------------------------------------------------

void Wireguard::update() {
  bool peer_up    = this->is_peer_up();
  time_t lhs      = this->get_latest_handshake();
  bool lhs_updated = (lhs > this->latest_saved_handshake_);

  ESP_LOGV(TAG, "enabled=%d, connected=%d, peer_up=%d, handshake: current=%.0f latest=%.0f updated=%d",
           (int) this->enabled_,
#ifdef USE_RP2040
           (int) this->wg_connected_,
#else
           (int) (this->wg_connected_ == ESP_OK),
#endif
           (int) peer_up, (double) lhs,
           (double) this->latest_saved_handshake_, (int) lhs_updated);

  if (lhs_updated) {
    this->latest_saved_handshake_ = lhs;
  }

  std::string latest_handshake =
      (this->latest_saved_handshake_ > 0)
          ? ESPTime::from_epoch_local(this->latest_saved_handshake_).strftime("%Y-%m-%d %H:%M:%S %Z")
          : "timestamp not available";

  if (peer_up) {
    if (this->wg_peer_offline_time_ != 0) {
      ESP_LOGI(TAG, LOGMSG_PEER_STATUS, LOGMSG_ONLINE, latest_handshake.c_str());
      this->wg_peer_offline_time_ = 0;
    } else {
      ESP_LOGD(TAG, LOGMSG_PEER_STATUS, LOGMSG_ONLINE, latest_handshake.c_str());
    }
  } else {
    if (this->wg_peer_offline_time_ == 0) {
      ESP_LOGW(TAG, LOGMSG_PEER_STATUS, LOGMSG_OFFLINE, latest_handshake.c_str());
      this->wg_peer_offline_time_ = millis();
    } else if (this->enabled_) {
      ESP_LOGD(TAG, LOGMSG_PEER_STATUS, LOGMSG_OFFLINE, latest_handshake.c_str());
      this->start_connection_();
    }

    // check reboot timeout every time the peer is down
    if (this->enabled_ && this->reboot_timeout_ > 0) {
      if (millis() - this->wg_peer_offline_time_ > this->reboot_timeout_) {
        ESP_LOGE(TAG, "Remote peer is unreachable; rebooting");
        App.reboot();
      }
    }
  }

#ifdef USE_BINARY_SENSOR
  if (this->status_sensor_ != nullptr) {
    this->status_sensor_->publish_state(peer_up);
  }
#endif

#ifdef USE_SENSOR
  if (this->handshake_sensor_ != nullptr && lhs_updated) {
    this->handshake_sensor_->publish_state((double) this->latest_saved_handshake_);
  }
#endif
}

// ---------------------------------------------------------------------------
// dump_config()
// ---------------------------------------------------------------------------

void Wireguard::dump_config() {
  char private_key_masked[MASK_KEY_BUFFER_SIZE];
  char preshared_key_masked[MASK_KEY_BUFFER_SIZE];
  mask_key_to(private_key_masked,   sizeof(private_key_masked),   this->private_key_);
  mask_key_to(preshared_key_masked, sizeof(preshared_key_masked), this->preshared_key_);

  ESP_LOGCONFIG(
      TAG,
    "WireGuard:\n"
    "  Address:              %s\n"
    "  Netmask:              %s\n"
    "  Private Key:          " LOG_SECRET("%s") "\n"
    "  Peer Endpoint:        " LOG_SECRET("%s") "\n"
    "  Peer Port:            " LOG_SECRET("%d") "\n"
    "  Peer Public Key:      " LOG_SECRET("%s") "\n"
    "  Peer Pre-shared Key:  " LOG_SECRET("%s"),
    this->address_, this->netmask_, private_key_masked,
    this->peer_endpoint_, this->peer_port_, this->peer_public_key_,
    (this->preshared_key_ != nullptr ? preshared_key_masked : "NOT IN USE"));
  // clang-format on
  ESP_LOGCONFIG(TAG, "  Peer Allowed IPs:");
  for (const AllowedIP &allowed_ip : this->allowed_ips_) {
    ESP_LOGCONFIG(TAG, "    - %s/%s", allowed_ip.ip, allowed_ip.netmask);
  }
  ESP_LOGCONFIG(TAG, "  Peer Persistent Keepalive: %d%s", this->keepalive_,
                (this->keepalive_ > 0 ? "s" : " (DISABLED)"));
  ESP_LOGCONFIG(TAG, "  Reboot Timeout: %" PRIu32 "%s", (this->reboot_timeout_ / 1000),
                (this->reboot_timeout_ != 0 ? "s" : " (DISABLED)"));
  ESP_LOGCONFIG(TAG, "  Require Connection to Proceed: %s",
                (this->proceed_allowed_ ? "NO" : "YES"));

#ifdef USE_RP2040
  ESP_LOGCONFIG(TAG, "  Platform: RP2040 (CYW43/lwIP)");
#else
  ESP_LOGCONFIG(TAG, "  Platform: ESP (IDF/lwIP)");
#endif

  LOG_UPDATE_INTERVAL(this);
}

// ---------------------------------------------------------------------------

void Wireguard::on_shutdown() { this->stop_connection_(); }

bool Wireguard::can_proceed() { return (this->proceed_allowed_ || this->is_peer_up() || !this->enabled_); }

// ---------------------------------------------------------------------------
// is_peer_up() / get_latest_handshake()
// ---------------------------------------------------------------------------

bool Wireguard::is_peer_up() const {
#ifdef USE_RP2040
  if (!this->wg_initialized_ || !this->wg_connected_)
    return false;
  // WireGuard-ESP32 library exposes isConnected() which returns true once
  // a handshake has been completed and the peer is reachable.
  return const_cast<WireGuard &>(this->wg_instance_).isConnected();
#else
  return (this->wg_initialized_ == ESP_OK) && (this->wg_connected_   == ESP_OK) &&
         (esp_wireguardif_peer_is_up(&(this->wg_ctx_)) == ESP_OK);
#endif
}

time_t Wireguard::get_latest_handshake() const {
#ifdef USE_RP2040
  // The arduino-pico WireGuard library does not expose a direct handshake
  // timestamp API.  We use the system clock captured the moment isConnected()
  // first returned true (set inside start_connection_ / loop).
  return this->latest_handshake_approx_;
#else
  time_t result;
  if (esp_wireguard_latest_handshake(&(this->wg_ctx_), &result) != ESP_OK) {
    result = 0;
  }
  return result;
#endif
}

// ---------------------------------------------------------------------------
// Setters
// ---------------------------------------------------------------------------

void Wireguard::set_keepalive(const uint16_t seconds)   { this->keepalive_        = seconds; }
void Wireguard::set_reboot_timeout(const uint32_t seconds) { this->reboot_timeout_ = seconds; }
void Wireguard::set_srctime(time::RealTimeClock *srctime)  { this->srctime_        = srctime; }

#ifdef USE_BINARY_SENSOR
void Wireguard::set_status_sensor(binary_sensor::BinarySensor *sensor) { this->status_sensor_  = sensor; }
void Wireguard::set_enabled_sensor(binary_sensor::BinarySensor *sensor){ this->enabled_sensor_ = sensor; }
#endif

#ifdef USE_SENSOR
void Wireguard::set_handshake_sensor(sensor::Sensor *sensor) { this->handshake_sensor_ = sensor; }
#endif

#ifdef USE_TEXT_SENSOR
void Wireguard::set_address_sensor(text_sensor::TextSensor *sensor) { this->address_sensor_ = sensor; }
#endif

void Wireguard::disable_auto_proceed() { this->proceed_allowed_ = false; }

// ---------------------------------------------------------------------------
// enable() / disable()
// ---------------------------------------------------------------------------

void Wireguard::enable() {
  this->enabled_ = true;
  ESP_LOGI(TAG, "Enabled");
  this->publish_enabled_state();
}

void Wireguard::disable() {
  this->enabled_ = false;
  this->defer([this]() { this->stop_connection_(); });
  ESP_LOGI(TAG, "Disabled");
  this->publish_enabled_state();
}

void Wireguard::publish_enabled_state() {
#ifdef USE_BINARY_SENSOR
  if (this->enabled_sensor_ != nullptr) {
    this->enabled_sensor_->publish_state(this->enabled_);
  }
#endif
}

bool Wireguard::is_enabled() { return this->enabled_; }

// ---------------------------------------------------------------------------
// start_connection_()
// ---------------------------------------------------------------------------

void Wireguard::start_connection_() {
  if (!this->enabled_) {
    ESP_LOGV(TAG, "Disabled, cannot start connection");
    return;
  }

#ifdef USE_RP2040
  if (!this->wg_initialized_) {
    ESP_LOGE(TAG, "Cannot start: not initialised");
    return;
  }
#else
  if (this->wg_initialized_ != ESP_OK) {
    ESP_LOGE(TAG, "Cannot start: error code %d", this->wg_initialized_);
    return;
  }
#endif

  if (!network::is_connected()) {
    ESP_LOGD(TAG, "Waiting for local network connection to be available");
    return;
  }

  if (!this->srctime_->now().is_valid()) {
    ESP_LOGD(TAG, "Waiting for system time to be synchronized");
    return;
  }

#ifdef USE_RP2040
  if (this->wg_connected_) {
    ESP_LOGV(TAG, "Connection already started");
    return;
  }

  ESP_LOGD(TAG, "Starting WireGuard connection (RP2040/lwIP)");

  // WireGuard-ESP32 begin() signature:
  //   bool begin(const char *localIP,
  //              const char *privateKey,
  //              const char *serverAddress,
  //              const char *serverPublicKey,
  //              uint16_t serverPort,
  //              const char *presharedKey = nullptr);
  //
  // It sets up the lwIP netif, resolves the peer endpoint via DNS, and
  // initiates the handshake.  All crypto runs in the lwIP tcpip thread
  // (same thread model as on ESP32 with IDF WireGuard).
  suspend_wdt();
  bool ok = this->wg_instance_.begin(
    this->address_,
    this->private_key_,
    this->peer_endpoint_,
    this->peer_public_key_,
    this->peer_port_,
    this->preshared_key_   // may be nullptr – library handles it
  );
  resume_wdt();

  if (!ok) {
    ESP_LOGW(TAG, "WireGuard begin() failed – will retry on next update cycle");
    return;
  }

  // Keepalive: the library has a setPersistentKeepalive() method.
  if (this->keepalive_ > 0)
    this->wg_instance_.setPersistentKeepalive(this->keepalive_);

  this->wg_connected_           = true;
  this->wg_peer_offline_time_   = millis();
  this->latest_handshake_approx_ = this->srctime_->now().timestamp;

  ESP_LOGI(TAG, "WireGuard connection started");

  // Allowed IPs: on RP2040 the library installs a default route to the
  // peer's /32.  For additional subnets we add static lwIP routes.
  // NOTE: full multi-subnet routing via lwIP requires lwip/ip4_route.h which
  // is not always exposed by arduino-pico.  We log a warning if more than one
  // allowed IP is configured so the user knows to set netmask 0.0.0.0 for
  // full-tunnel instead.
  if (this->allowed_ips_.size() > 1) {
    ESP_LOGW(TAG, "Multiple allowed_ips entries are configured. "
                  "On RP2040, only the first entry / full-tunnel (0.0.0.0/0) "
                  "is reliably supported without custom lwIP routing patches.");
  }

#else
  // -----------------------------------------------------------------------
  // Upstream ESP path (unchanged)
  // -----------------------------------------------------------------------
  if (this->wg_connected_ == ESP_OK) {
    ESP_LOGV(TAG, "Connection already started");
    return;
  }

  ESP_LOGD(TAG, "Starting connection");
  {
    LwIPLock lock;
    this->wg_connected_ = esp_wireguard_connect(&(this->wg_ctx_));
  }

  if (this->wg_connected_ == ESP_OK) {
    ESP_LOGI(TAG, "Connection started");
  } else if (this->wg_connected_ == ESP_ERR_RETRY) {
    ESP_LOGD(TAG, "Waiting for endpoint IP address to be available");
    return;
  } else {
    ESP_LOGW(TAG, "Cannot start connection, error code %d", this->wg_connected_);
    return;
  }

  ESP_LOGD(TAG, "Configuring allowed IPs list");
  bool allowed_ips_ok = true;
  for (const AllowedIP &ip : this->allowed_ips_) {
    allowed_ips_ok &= (esp_wireguard_add_allowed_ip(&(this->wg_ctx_), ip.ip, ip.netmask) == ESP_OK);
  }

  if (allowed_ips_ok) {
    ESP_LOGD(TAG, "Allowed IPs list configured correctly");
  } else {
    ESP_LOGE(TAG, "Cannot configure allowed IPs list, aborting");
    this->stop_connection_();
    this->mark_failed();
  }
#endif  // USE_RP2040
}

// ---------------------------------------------------------------------------
// stop_connection_()
// ---------------------------------------------------------------------------

void Wireguard::stop_connection_() {
#ifdef USE_RP2040
  if (this->wg_initialized_ && this->wg_connected_) {
    ESP_LOGD(TAG, "Stopping WireGuard connection");
    this->wg_instance_.end();
    this->wg_connected_ = false;
  }
#else
  if (this->wg_initialized_ == ESP_OK && this->wg_connected_ == ESP_OK) {
    ESP_LOGD(TAG, "Stopping connection");
    {
      LwIPLock lock;
      esp_wireguard_disconnect(&(this->wg_ctx_));
    }
    this->wg_connected_ = ESP_FAIL;
  }
#endif
}

// ---------------------------------------------------------------------------
// mask_key_to() – identical to upstream
// ---------------------------------------------------------------------------

void mask_key_to(char *buffer, size_t len, const char *key) {
  // Format: "XXXXX[...]=\0" = MASK_KEY_BUFFER_SIZE chars minimum
  if (len < MASK_KEY_BUFFER_SIZE || key == nullptr) {
    if (len > 0)
      buffer[0] = '\0';
    return;
  }
  // Copy first 5 characters of the key
  size_t i = 0;
  for (; i < 5 && key[i] != '\0'; ++i) {
    buffer[i] = key[i];
  }
  // Append "[...]="
  const char *suffix = "[...]=";
  for (size_t j = 0; suffix[j] != '\0' && (i + j) < len - 1; ++j) {
    buffer[i + j] = suffix[j];
  }
  buffer[i + 6] = '\0';
}

}  // namespace wireguard
}  // namespace esphome
#endif  // USE_WIREGUARD
