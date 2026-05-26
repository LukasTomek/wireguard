#pragma once
#include "esphome/core/defines.h"
#ifdef USE_WIREGUARD

#include <ctime>
#include <initializer_list>

#include "esphome/core/automation.h"
#include "esphome/core/component.h"
#include "esphome/core/helpers.h"
#include "esphome/components/time/real_time_clock.h"

#ifdef USE_BINARY_SENSOR
#include "esphome/components/binary_sensor/binary_sensor.h"
#endif

#ifdef USE_SENSOR
#include "esphome/components/sensor/sensor.h"
#endif

#ifdef USE_TEXT_SENSOR
#include "esphome/components/text_sensor/text_sensor.h"
#endif

// ---------------------------------------------------------------------------
// Platform abstraction
//
// On ESP32/ESP8266/BK72xx the upstream component uses the Espressif
// esp_wireguard library which calls into the IDF / lwIP stack directly.
// On RP2040 (arduino-pico / CYW43 / lwIP) we use the WireGuard-ESP32 port
// that has been adapted to plain lwIP – the same C API is exposed, but we
// have to include a different header and link a different library.
// ---------------------------------------------------------------------------

#ifdef USE_RP2040
  // wireguard-lwip: pure-C lwIP WireGuard implementation
  // https://github.com/ciniml/WireGuard-ESP32-Arduino
  // (also works on arduino-pico with the lwIP stack)
  //#include <WireGuard-ESP32.h>   // exposes WireGuard C++ class from that lib
  // We re-use the library's C++ class internally but wrap it in the same
  // ESPHome component interface as the upstream component so that the rest
  // of ESPHome (OTA, API, …) is unaffected.
  #define WG_USE_LWIP_DIRECTLY   // flag used in wireguard.cpp
#else
  #include <esp_wireguard.h>
  #include <esp_wireguard_err.h>
#endif

namespace esphome {
namespace wireguard {

/** Allowed IP entry for WireGuard peer configuration. */
struct AllowedIP {
  const char *ip;
  const char *netmask;
};

static constexpr size_t MASK_KEY_BUFFER_SIZE = 12;

/** Strip most of the key for secure log printing. */
void mask_key_to(char *buffer, size_t len, const char *key);

// Suspend / resume WDT around blocking DNS (platform-specific implementations
// in wireguard.cpp).
void suspend_wdt();
void resume_wdt();

// ---------------------------------------------------------------------------

class Wireguard : public PollingComponent {
 public:
  void setup() override;
  void loop() override;
  void update() override;
  void dump_config() override;
  void on_shutdown() override;
  bool can_proceed() override;

  float get_setup_priority() const override { return esphome::setup_priority::BEFORE_CONNECTION; }

  // ----- setters (const char* only – std::string overloads are deleted to
  //               prevent dangling pointers just like the upstream component) -----
  void set_address(const char *address) { this->address_ = address; }
  void set_netmask(const char *netmask) { this->netmask_ = netmask; }
  void set_private_key(const char *key) { this->private_key_ = key; }
  void set_peer_endpoint(const char *endpoint) { this->peer_endpoint_ = endpoint; }
  void set_peer_public_key(const char *key) { this->peer_public_key_ = key; }
  void set_peer_port(uint16_t port) { this->peer_port_ = port; }
  void set_preshared_key(const char *key) { this->preshared_key_ = key; }

  /// Prevent accidental use of std::string which would dangle
  void set_address(const std::string &address) = delete;
  void set_netmask(const std::string &netmask) = delete;
  void set_private_key(const std::string &key) = delete;
  void set_peer_endpoint(const std::string &endpoint) = delete;
  void set_peer_public_key(const std::string &key) = delete;
  void set_preshared_key(const std::string &key) = delete;

  void set_allowed_ips(std::initializer_list<AllowedIP> ips) { this->allowed_ips_ = ips; }
  /// Prevent accidental use of std::string which would dangle
  void set_allowed_ips(std::initializer_list<std::tuple<std::string, std::string>> ips) = delete;

  void set_keepalive(uint16_t seconds);
  void set_reboot_timeout(uint32_t seconds);
  void set_srctime(time::RealTimeClock *srctime);

#ifdef USE_BINARY_SENSOR
  void set_status_sensor(binary_sensor::BinarySensor *sensor);
  void set_enabled_sensor(binary_sensor::BinarySensor *sensor);
#endif

#ifdef USE_SENSOR
  void set_handshake_sensor(sensor::Sensor *sensor);
#endif

#ifdef USE_TEXT_SENSOR
  void set_address_sensor(text_sensor::TextSensor *sensor);
#endif

  /// Block the setup step until peer is connected.
  void disable_auto_proceed();

  /// Enable the WireGuard component.
  void enable();

  /// Stop any running connection and disable the WireGuard component.
  void disable();

  /// Publish the enabled state if the enabled binary sensor is configured.
  void publish_enabled_state();

  /// Return if the WireGuard component is or is not enabled.
  bool is_enabled();

  bool is_peer_up() const;
  time_t get_latest_handshake() const;

 protected:
  const char *address_{nullptr};
  const char *netmask_{nullptr};
  const char *private_key_{nullptr};
  const char *peer_endpoint_{nullptr};
  const char *peer_public_key_{nullptr};
  const char *preshared_key_{nullptr};

  FixedVector<AllowedIP> allowed_ips_;

  uint16_t peer_port_{51820};
  uint16_t keepalive_{0};
  uint32_t reboot_timeout_{0};

  time::RealTimeClock *srctime_{nullptr};

#ifdef USE_BINARY_SENSOR
  binary_sensor::BinarySensor *status_sensor_{nullptr};
  binary_sensor::BinarySensor *enabled_sensor_{nullptr};
#endif

#ifdef USE_SENSOR
  sensor::Sensor *handshake_sensor_{nullptr};
#endif

#ifdef USE_TEXT_SENSOR
  text_sensor::TextSensor *address_sensor_{nullptr};
#endif

  bool proceed_allowed_{true};
  bool enabled_{true};

  // ---- platform-specific state ----
#ifdef USE_RP2040
  // WireGuard-ESP32 C++ wrapper; works on any lwIP platform including RP2040
  WireGuard wg_instance_;
  bool      wg_connected_{false};
  bool      wg_initialized_{false};

  // We track handshake time ourselves because the arduino-pico library does
  // not expose a direct "latest handshake" API in the same way the IDF does.
  // The library's isConnected() returning true after the first keepalive is
  // our proxy for a successful handshake.
  time_t    latest_handshake_approx_{0};
#else
  wireguard_config_t wg_config_ = ESP_WIREGUARD_CONFIG_DEFAULT();
  wireguard_ctx_t    wg_ctx_    = ESP_WIREGUARD_CONTEXT_DEFAULT();
  esp_err_t          wg_initialized_{ESP_FAIL};
  esp_err_t          wg_connected_{ESP_FAIL};
#endif

  uint32_t wg_peer_offline_time_{0};
  time_t   latest_saved_handshake_{0};

  void start_connection_();
  void stop_connection_();
};

// ---------------------------------------------------------------------------
// Automation helpers (identical to upstream)
// ---------------------------------------------------------------------------

template<typename... Ts>
class WireguardPeerOnlineCondition : public Condition<Ts...>, public Parented<Wireguard> {
 public:
  bool check(const Ts &...x) override { return this->parent_->is_peer_up(); }
};

template<typename... Ts>
class WireguardEnabledCondition : public Condition<Ts...>, public Parented<Wireguard> {
 public:
  bool check(const Ts &...x) override { return this->parent_->is_enabled(); }
};

template<typename... Ts>
class WireguardEnableAction : public Action<Ts...>, public Parented<Wireguard> {
 public:
  void play(const Ts &...x) override { this->parent_->enable(); }
};

template<typename... Ts>
class WireguardDisableAction : public Action<Ts...>, public Parented<Wireguard> {
 public:
  void play(const Ts &...x) override { this->parent_->disable(); }
};

}  // namespace wireguard
}  // namespace esphome
#endif  // USE_WIREGUARD
