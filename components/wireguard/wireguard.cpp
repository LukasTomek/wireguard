#include "wireguard.h"
#ifdef USE_WIREGUARD

#include <cinttypes>
#include <ctime>

#include "esphome/core/application.h"
#include "esphome/core/log.h"
#include "esphome/core/time.h"
#include "esphome/components/network/util.h"
#include "esphome/core/helpers.h"

#ifdef USE_RP2040
  #include "pico_stack.h"
  #include <hardware/watchdog.h>
  #include <pico/multicore.h>
  #include <IPAddress.h>

#endif

// Global pointer used by Core 1 entry function (only one WireGuard instance).
namespace esphome {
namespace wireguard {

  // Runs on Core 1 – has full access to protected members via s_wg_instance.
#ifdef USE_RP2040
static Wireguard *s_wg_instance = nullptr;
  // As a static method of the class there are no access restriction issues.
void Wireguard::core1_entry_() {
  //              const char* remotePeerPublicKey,
  //              uint16_t remotePeerPort)
  IPAddress local_ip, subnet, gateway;
  local_ip.fromString(s_wg_instance->address_);
  subnet.fromString(s_wg_instance->netmask_);
  // Gateway: use the WireGuard peer IP from allowed_ips[0], or 0.0.0.0
  if (s_wg_instance->allowed_ips_.size() > 0) {
    gateway.fromString(s_wg_instance->allowed_ips_[0].ip);
  } else {
    gateway = IPAddress(0, 0, 0, 0);
  }
  bool ok = s_wg_instance->wg_instance_.beginAdvanced(
    local_ip,
    s_wg_instance->private_key_,
    s_wg_instance->peer_endpoint_,
    s_wg_instance->peer_public_key_,
    s_wg_instance->peer_port_,
    gateway,
    subnet
  );
  s_wg_instance->wg_begin_result_ = ok;
  s_wg_instance->wg_begin_done_   = true;
  // Core 1 must not return – spin here.
  while (true) tight_loop_contents();
}
#endif

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
void suspend_wdt() { watchdog_update(); }
void resume_wdt()  { watchdog_update(); }
#else

#endif

// ---------------------------------------------------------------------------
// setup()
// ---------------------------------------------------------------------------
void Wireguard::setup() {
  this->publish_enabled_state();

#ifdef USE_RP2040
  ESP_LOGI(TAG, "Initialising WireGuard (RP2040/Pico W)");
  this->wg_initialized_ = true;
  this->srctime_->add_on_time_sync_callback([this]() { this->start_connection_(); });
  this->defer([this]() { this->start_connection_(); });

#ifdef USE_TEXT_SENSOR
  if (this->address_sensor_ != nullptr)
    this->address_sensor_->publish_state(this->address_);
#endif

#else
  // ESP32 / ESP8266 / BK72xx path – unchanged from official component
  this->wg_config_.address      = this->address_;
  this->wg_config_.private_key  = this->private_key_;
  this->wg_config_.endpoint     = this->peer_endpoint_;
  this->wg_config_.public_key   = this->peer_public_key_;
  this->wg_config_.port         = this->peer_port_;
  this->wg_config_.netmask      = this->netmask_;
  this->wg_config_.persistent_keepalive = this->keepalive_;

  if (this->preshared_key_ != nullptr)
    this->wg_config_.preshared_key = this->preshared_key_;

  {
    LwIPLock lock;
    this->wg_initialized_ = esp_wireguard_init(&(this->wg_config_), &(this->wg_ctx_));
  }

  if (this->wg_initialized_ == ESP_OK) {
    ESP_LOGI(TAG, "Initialized");
    this->wg_peer_offline_time_ = millis();
    this->srctime_->add_on_time_sync_callback([this]() { this->start_connection_(); });
    this->defer([this]() { this->start_connection_(); });  // defer to avoid blocking setup

#ifdef USE_TEXT_SENSOR
    if (this->address_sensor_ != nullptr) {
      this->address_sensor_->publish_state(this->address_);
    }
#endif
  } else {
    ESP_LOGE(TAG, "Cannot initialize: error code %d", this->wg_initialized_);
    this->mark_failed();
  }
#endif
}

// ---------------------------------------------------------------------------
// loop()
// ---------------------------------------------------------------------------
void Wireguard::loop() {
  if (!this->enabled_) {
    return;
}

#ifdef USE_RP2040
  // Pick up result from Core 1 begin() once it finishes
  if (this->wg_begin_pending_ && this->wg_begin_done_) {
    this->wg_begin_pending_ = false;
    if (this->wg_begin_result_) {
      this->wg_connected_            = true;
      this->wg_peer_offline_time_    = millis();
      this->latest_handshake_approx_ = (this->srctime_ != nullptr)
          ? this->srctime_->now().timestamp : 0;
      ESP_LOGI(TAG, "WireGuard connection started");
    } else {
      ESP_LOGW(TAG, "WireGuard begin() failed on Core 1, will retry");
    }
  }

  if (this->wg_initialized_ && this->wg_connected_ && !network::is_connected()) {
    ESP_LOGV(TAG, "Network lost, stopping WireGuard");
    this->stop_connection_();
  }
#else
  if ((this->wg_initialized_ == ESP_OK) && (this->wg_connected_ == ESP_OK) && (!network::is_connected())) {
    ESP_LOGV(TAG, "Local network connection has been lost, stopping");
    this->stop_connection_();
  }
#endif
}

// ---------------------------------------------------------------------------
// update()
// ---------------------------------------------------------------------------
void Wireguard::update() {
  bool peer_up = this->is_peer_up();
  time_t lhs = this->get_latest_handshake();
  bool lhs_updated = (lhs > this->latest_saved_handshake_);

  if (lhs_updated)
    this->latest_saved_handshake_ = lhs;

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
  mask_key_to(private_key_masked, sizeof(private_key_masked), this->private_key_);
  mask_key_to(preshared_key_masked, sizeof(preshared_key_masked), this->preshared_key_);
  // clang-format off
  ESP_LOGCONFIG(
      TAG,
      "WireGuard:\n"
      "  Address: %s\n"
      "  Netmask: %s\n"
      "  Private Key: " LOG_SECRET("%s") "\n"
      "  Peer Endpoint: " LOG_SECRET("%s") "\n"
      "  Peer Port: " LOG_SECRET("%d") "\n"

    "  Peer Public Key:     " LOG_SECRET("%s") "\n"
    "  Peer Preshared Key:  " LOG_SECRET("%s") "\n"
    "  Platform:            %s",
this->address_, this->netmask_, private_key_masked,
      this->peer_endpoint_, this->peer_port_, this->peer_public_key_,
      (this->preshared_key_ != nullptr ? preshared_key_masked : "NOT IN USE"),
#ifdef USE_RP2040
    "RP2040/Pico W (jaszczurtd/arduino-wireguard-pico-w)"
#else
    "ESP (droscy/esp_wireguard)"
#endif
  );

  ESP_LOGCONFIG(TAG, "  Peer Allowed IPs:");
  for (const AllowedIP &allowed_ip : this->allowed_ips_) {
    ESP_LOGCONFIG(TAG, "    - %s/%s", allowed_ip.ip, allowed_ip.netmask);
  }
  ESP_LOGCONFIG(TAG, "  Peer Persistent Keepalive: %d%s", this->keepalive_,
                (this->keepalive_ > 0 ? "s" : " (DISABLED)"));
  ESP_LOGCONFIG(TAG, "  Reboot Timeout: %" PRIu32 "%s", (this->reboot_timeout_ / 1000),
                (this->reboot_timeout_ != 0 ? "s" : " (DISABLED)"));
  // be careful: if proceed_allowed_ is true, require connection is false
  ESP_LOGCONFIG(TAG, "  Require Connection to Proceed: %s", (this->proceed_allowed_ ? "NO" : "YES"));
  LOG_UPDATE_INTERVAL(this);
}

void Wireguard::on_shutdown() { this->stop_connection_(); }

bool Wireguard::can_proceed() { return (this->proceed_allowed_ || this->is_peer_up() || !this->enabled_); }

// ---------------------------------------------------------------------------
// is_peer_up() / get_latest_handshake()
// ---------------------------------------------------------------------------
bool Wireguard::is_peer_up() const {
#ifdef USE_RP2040
  if (!this->wg_initialized_ || !this->wg_connected_)
    return false;
  // isConnected() dereferences lwIP internal state that is set up
  // asynchronously after begin() returns. Calling it too early causes
  // a hardfault. Wait at least 3 s after begin() before polling.
  return this->wg_connected_;
#else
  return (this->wg_initialized_ == ESP_OK) &&
         (this->wg_connected_   == ESP_OK) &&
         (esp_wireguardif_peer_is_up(&(this->wg_ctx_)) == ESP_OK);
#endif
}

time_t Wireguard::get_latest_handshake() const {
#ifdef USE_RP2040
  // The jaszczurtd library does not expose a handshake timestamp API;
  // we return the time captured when the connection was established.
  return this->latest_handshake_approx_;
#else
  time_t result;
  if (esp_wireguard_latest_handshake(&(this->wg_ctx_), &result) != ESP_OK) {
    result = 0;
  }
  return result;
#endif
}



void Wireguard::set_keepalive(const uint16_t seconds) { this->keepalive_ = seconds; }
void Wireguard::set_reboot_timeout(const uint32_t seconds) { this->reboot_timeout_ = seconds; }
void Wireguard::set_srctime(time::RealTimeClock *srctime) { this->srctime_ = srctime; }

#ifdef USE_BINARY_SENSOR
void Wireguard::set_status_sensor(binary_sensor::BinarySensor *sensor) { this->status_sensor_ = sensor; }
void Wireguard::set_enabled_sensor(binary_sensor::BinarySensor *sensor) { this->enabled_sensor_ = sensor; }
#endif

#ifdef USE_SENSOR
void Wireguard::set_handshake_sensor(sensor::Sensor *sensor) { this->handshake_sensor_ = sensor; }
#endif

#ifdef USE_TEXT_SENSOR
void Wireguard::set_address_sensor(text_sensor::TextSensor *sensor) { this->address_sensor_ = sensor; }
#endif

// ---------------------------------------------------------------------------
// enable() / disable()
// ---------------------------------------------------------------------------

void Wireguard::disable_auto_proceed() { this->proceed_allowed_ = false; }

void Wireguard::enable() {
  this->enabled_ = true;
  ESP_LOGI(TAG, "Enabled");
  this->publish_enabled_state();
}

void Wireguard::disable() {
  this->enabled_ = false;
  this->defer([this]() { this->stop_connection_(); });  // defer to avoid blocking running loop
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
    ESP_LOGE(TAG, "Not initialised");
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
  // begin() runs Curve25519 key generation which needs ~8KB of stack.
  // Core 0 (arduino-pico) only has 2KB and PICO_STACK_SIZE is baked into
  // the precompiled SDK so build flags cannot change it at compile time.
  // Solution: launch begin() on Core 1 with an explicit 16KB heap-allocated
  // stack via multicore_launch_core1_with_stack().
  if (this->wg_begin_pending_) {
    ESP_LOGV(TAG, "WireGuard begin() already running on Core 1");
    return;
  }

  ESP_LOGD(TAG, "Launching WireGuard begin() on Core 1 (dedicated stack)");
  this->wg_begin_done_    = false;
  this->wg_begin_result_  = false;
  this->wg_begin_pending_ = true;
  s_wg_instance           = this;

  multicore_launch_core1_with_stack(
    Wireguard::core1_entry_,
    this->wg_core1_stack_,
    sizeof(this->wg_core1_stack_)
  );
  // Result is picked up in loop() once wg_begin_done_ == true

#else
  // ESP32 / ESP8266 / BK72xx – unchanged from official component
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
#endif
}

// ---------------------------------------------------------------------------
// stop_connection_()
// ---------------------------------------------------------------------------
void Wireguard::stop_connection_() {
#ifdef USE_RP2040
  if (this->wg_initialized_ && this->wg_connected_) {
    ESP_LOGD(TAG, "Stopping WireGuard connection");
    this->wg_instance_.end();
    this->wg_connected_     = false;
    this->wg_begin_pending_ = false;
    this->wg_begin_done_    = false;
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
// mask_key_to()
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
