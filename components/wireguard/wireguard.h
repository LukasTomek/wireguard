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
// ---------------------------------------------------------------------------
#ifdef USE_RP2040
  // Dedicated Pico W port of WireGuard-ESP32 by jaszczurtd
  // https://github.com/jaszczurtd/arduino-wireguard-pico-w
  #include <arduino-wireguard-pico-w.h>
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

/// Main Wireguard component class.
class Wireguard : public PollingComponent {
 public:
  void setup() override;
  void loop() override;
  void update() override;
  void dump_config() override;
  void on_shutdown() override;
  bool can_proceed() override;

  float get_setup_priority() const override { return esphome::setup_priority::BEFORE_CONNECTION; }

  // All setters declared here, defined in wireguard.cpp
  void set_address(const char *address);
  void set_netmask(const char *netmask);
  void set_private_key(const char *key);
  void set_peer_endpoint(const char *ep);
  void set_peer_public_key(const char *key);
  void set_peer_port(uint16_t port);
  void set_preshared_key(const char *key);
  void set_allowed_ips(std::initializer_list<AllowedIP> ips);
  void set_keepalive(uint16_t seconds);
  void set_reboot_timeout(uint32_t ms);
  void set_srctime(time::RealTimeClock *t);

#ifdef USE_BINARY_SENSOR
  void set_status_sensor(binary_sensor::BinarySensor *s);
  void set_enabled_sensor(binary_sensor::BinarySensor *s);
#endif
#ifdef USE_SENSOR
  void set_handshake_sensor(sensor::Sensor *s);
#endif
#ifdef USE_TEXT_SENSOR
  void set_address_sensor(text_sensor::TextSensor *s);
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

#ifdef USE_RP2040
  WireGuard wg_instance_;
  bool      wg_initialized_{false};
  bool      wg_connected_{false};
  time_t    latest_handshake_approx_{0};
#else
  wireguard_config_t wg_config_ = ESP_WIREGUARD_CONFIG_DEFAULT();
  wireguard_ctx_t    wg_ctx_    = ESP_WIREGUARD_CONTEXT_DEFAULT();
  esp_err_t          wg_initialized_{ESP_FAIL};
  esp_err_t          wg_connected_{ESP_FAIL};
#endif

  /// The last time the remote peer become offline.
  uint32_t wg_peer_offline_time_ = 0;

  /** \brief The latest saved handshake.
   *
   * This is used to save (and log) the latest completed handshake even
   * after a full refresh of the wireguard keys (for example after a
   * stop/start connection cycle).
   */
  time_t latest_saved_handshake_ = 0;

  void start_connection_();
  void stop_connection_();
};

// These are used for possibly long DNS resolution to temporarily suspend the watchdog
void suspend_wdt();
void resume_wdt();

/// Size of buffer required for mask_key_to: 5 chars + "[...]=" + null = 12
static constexpr size_t MASK_KEY_BUFFER_SIZE = 12;

/// Strip most part of the key only for secure printing
void mask_key_to(char *buffer, size_t len, const char *key);

/// Condition to check if remote peer is online.
template<typename... Ts> class WireguardPeerOnlineCondition : public Condition<Ts...>, public Parented<Wireguard> {
 public:
  bool check(const Ts &...x) override { return this->parent_->is_peer_up(); }
};

/// Condition to check if Wireguard component is enabled.
template<typename... Ts> class WireguardEnabledCondition : public Condition<Ts...>, public Parented<Wireguard> {
 public:
  bool check(const Ts &...x) override { return this->parent_->is_enabled(); }
};

/// Action to enable Wireguard component.
template<typename... Ts> class WireguardEnableAction : public Action<Ts...>, public Parented<Wireguard> {
 public:
  void play(const Ts &...x) override { this->parent_->enable(); }
};

/// Action to disable Wireguard component.
template<typename... Ts> class WireguardDisableAction : public Action<Ts...>, public Parented<Wireguard> {
 public:
  void play(const Ts &...x) override { this->parent_->disable(); }
};

}  // namespace wireguard
}  // namespace esphome
#endif  // USE_WIREGUARD
