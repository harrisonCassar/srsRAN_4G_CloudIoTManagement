/**
 * Copyright 2013-2023 Software Radio Systems Limited
 *
 * This file is part of srsRAN.
 *
 * srsRAN is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * srsRAN is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * A copy of the GNU Affero General Public License can be found in
 * the LICENSE file in the top-level directory of this distribution
 * and at http://www.gnu.org/licenses/.
 *
 */

#ifndef SRSUE_GW_H
#define SRSUE_GW_H

#include "gw_metrics.h"
#include "srsran/common/buffer_pool.h"
#include "srsran/common/common.h"
#include "srsran/common/interfaces_common.h"
#include "srsran/common/threads.h"
#include "srsran/interfaces/ue_gw_interfaces.h"
#include "srsran/srslog/srslog.h"
#include "tft_packet_filter.h"
#include <atomic>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <net/if.h>
#include <netinet/in.h>

namespace srsue {

class stack_interface_gw;

struct gw_args_t {
  struct log_args_t {
    std::string gw_level;
    int         gw_hex_limit;
  } log;
  std::string netns;
  std::string tun_dev_name;
  std::string tun_dev_netmask;
};

class gw : public gw_interface_stack, public srsran::thread
{
public:
  gw(srslog::basic_logger& logger_);
  ~gw();
  int  init(const gw_args_t& args_, stack_interface_gw* stack);
  void stop();

  void get_metrics(gw_metrics_t& m, const uint32_t nof_tti);

  // PDCP interface
  void write_pdu(uint32_t lcid, srsran::unique_byte_buffer_t pdu);
  void write_pdu_mch(uint32_t lcid, srsran::unique_byte_buffer_t pdu);

  // NAS interface
  int  setup_if_addr(uint32_t eps_bearer_id, uint8_t pdn_type, uint32_t ip_addr, uint8_t* ipv6_if_addr, char* err_str);
  int  deactivate_eps_bearer(const uint32_t eps_bearer_id);
  int  apply_traffic_flow_template(const uint8_t& eps_bearer_id, const LIBLTE_MME_TRAFFIC_FLOW_TEMPLATE_STRUCT* tft);
  void set_test_loop_mode(const test_loop_mode_state_t mode, const uint32_t ip_pdu_delay_ms);

  // RRC interface
  void add_mch_port(uint32_t lcid, uint32_t port);
  bool is_running();

private:
  static const int GW_THREAD_PRIO = -1;

  stack_interface_gw* stack = nullptr;

  gw_args_t args = {};

  std::atomic<bool> running    = {false};
  std::atomic<bool> run_enable = {false};
  int32_t           netns_fd   = 0;
  int32_t           tun_fd     = 0;
  struct ifreq      ifr        = {};
  int32_t           sock       = 0;
  std::atomic<bool> if_up      = {false};

  static const int NOT_ASSIGNED          = -1;
  int32_t          default_eps_bearer_id = NOT_ASSIGNED;
  std::mutex       gw_mutex;

  srslog::basic_logger& logger;

  uint32_t current_ip_addr = 0;
  uint8_t  current_if_id[8];

  uint32_t                                       ul_tput_bytes = 0;
  uint32_t                                       dl_tput_bytes = 0;
  std::chrono::high_resolution_clock::time_point metrics_tp; // stores time when last metrics have been taken

  void run_thread();
  int  init_if(char* err_str);
  int  setup_if_addr4(uint32_t ip_addr, char* err_str);
  int  setup_if_addr6(uint8_t* ipv6_if_id, char* err_str);
  bool find_ipv6_addr(struct in6_addr* in6_out);
  void del_ipv6_addr(struct in6_addr* in6p);

  // MBSFN
  int                mbsfn_sock_fd                   = 0;  // Sink UDP socket file descriptor
  struct sockaddr_in mbsfn_sock_addr                 = {}; // Target address
  uint32_t           mbsfn_ports[SRSRAN_N_MCH_LCIDS] = {}; // Target ports for MBSFN data

  // TFT
  tft_pdu_matcher tft_matcher;
};

// TODO(hcassar): Consider adding CloudIoTManagement source code to a new file to be added in the build system.

class CloudIoTManagement
{
public:

  /**
   * @brief Pre-determined length of PDU message header.
   */
  static constexpr size_t PDU_HEADER_SIZE_BYTES = 28;

  /**
   * @brief Pre-determined (minimum) length of an IoT Data Modem packet, as
   * defined in the custom CloudIoTManagement protocol.
   */
  static constexpr size_t CLOUDIOTMANAGEMENT_IOT_DATA_PACKET_SIZE_BYTES_MINIMUM = 14;

  /**
   * @brief Pre-determined (maximum) length of the data field in an IoT Data
   * Modem packet, as defined in the custom CloudIoTManagement protocol.
   */
  static constexpr size_t CLOUDIOTMANAGEMENT_IOT_DATA_PACKET_DATA_FIELD_SIZE_BYTES_MAXIMUM = 32;

  /**
   * @brief Pre-determined (maximum) length of an IoT Data Modem packet, as
   * defined in the custom CloudIoTManagement protocol.
   */
  static constexpr size_t CLOUDIOTMANAGEMENT_IOT_DATA_PACKET_SIZE_BYTES_MAXIMUM = CLOUDIOTMANAGEMENT_IOT_DATA_PACKET_SIZE_BYTES_MINIMUM + CLOUDIOTMANAGEMENT_IOT_DATA_PACKET_DATA_FIELD_SIZE_BYTES_MAXIMUM;

  /**
   * @brief Pre-determined length of an IoT Status Modem packet, as defined in
   * the custom CloudIoTManagement protocol.
   */
  static constexpr size_t CLOUDIOTMANAGEMENT_IOT_STATUS_PACKET_SIZE_BYTES = 2;

  /**
   * @brief Pre-determined length of an Carrier Switch Perform Modem packet, as
   * defined in the custom CloudIoTManagement protocol.
   */
  static constexpr size_t CLOUDIOTMANAGEMENT_CARRIER_SWITCH_PERFORM_PACKET_SIZE_BYTES = 2;

  /**
   * @brief Pre-determined length of an Carrier Switch Ack Modem packet, as
   * defined in the custom CloudIoTManagement protocol.
   */
  static constexpr size_t CLOUDIOTMANAGEMENT_CARRIER_SWITCH_ACK_PACKET_SIZE_BYTES = 2;

  /**
   * @brief Structure representing the Modem packet used in the custom
   * CloudIoTManagement protocol.
   */
  struct ModemPacket {
  public:
    /**
     * @brief Enum for Flow field in Modem Packets.
     */
    enum Flow : uint8_t {
      IOT = 0x0,
      CARRIER_SWITCH = 0x1
    };

    /**
     * @brief Constructor for ModemPacket.
     */
    ModemPacket() {}
    ModemPacket(Flow _flow) : flow(_flow) {}

    /**
     * @brief Serializes the packet into a sequence of bytes, placing these
     * bytes into the specified buffer owned by the caller.
     *
     * NOTE: This buffer must be at LEAST the length required for the packet of
     * interest, which can be determined by the `get_serialized_length` method.
     *
     * @param output_buffer Buffer to hold serialized bytes.
     * @param buffer_length Size of the specified buffer to hold serialized bytes.
     */
    virtual void serialize(uint8_t *output_buffer, size_t buffer_length) = 0;

    /**
     * @brief Specifies the length of the serialized packet, which can be used
     * to properly size buffers accordingly.
     */
    virtual size_t get_serialized_length() const = 0;

    /**
     * @brief Virtual destructor to enable inheritance.
     */
    virtual ~ModemPacket() {}

    Flow flow;
  };

  /**
   * @brief Structure representing the IoT Modem packet used in the custom
   * CloudIoTManagement protocol.
   */
  struct IoTPacket : ModemPacket {
  public:
    /**
     * @brief Enum for Topic field in IoT Modem Packets.
     */
    enum Topic : uint8_t {
      DATA = 0x0,
      STATUS = 0x1
    };

    /**
     * @brief Constructor for IoTPacket.
     */
    IoTPacket() : ModemPacket(ModemPacket::Flow::IOT) {}
    IoTPacket(Topic _topic) : topic(_topic),
                              ModemPacket(ModemPacket::Flow::IOT) {}

    /**
     * @brief Virtual destructor to enable inheritance.
     */
    virtual ~IoTPacket() {}

    Topic topic;
  };

  /**
   * @brief Structure representing the CarrierSwitch Modem packet used in the
   * custom CloudIoTManagement protocol.
   */
  struct CarrierSwitchPacket : ModemPacket {
  public:
    /**
     * @brief Enum for Topic field in CarrierSwitch Modem packets.
     */
    enum Topic : uint8_t {
      PERFORM = 0x0,
      ACK = 0x1
    };

    /**
     * @brief Enum for Carrier ID fields in the various CarrierSwitch Modem
     * packets.
     */
    enum CarrierID : uint8_t {
      ATNT = 0x0,
      TMOBILE = 0x1,
      VERIZON = 0x2,
      INVALID = 0xF
    };

    /**
     * @brief Constructor for CarrierSwitchPacket.
     */
    CarrierSwitchPacket() : ModemPacket(ModemPacket::Flow::CARRIER_SWITCH) {}
    CarrierSwitchPacket(Topic _topic) : topic(_topic),
                                        ModemPacket(ModemPacket::Flow::CARRIER_SWITCH) {}

    /**
     * @brief Virtual destructor to enable inheritance.
     */
    virtual ~CarrierSwitchPacket() {}

    Topic topic;
  };

  /**
   * @brief Structure representing the IoT Data Modem packet used in the custom
   * CloudIoTManagement protocol.
   */
  struct IoTDataPacket final : IoTPacket {
  public:
    /**
     * @brief Constructor for IoTDataPacket.
     */
    IoTDataPacket() : IoTPacket(IoTPacket::Topic::DATA) {}
    IoTDataPacket(uint32_t _device_id,
                  uint64_t _timestamp,
                  uint32_t _data_length,
                  uint8_t *_data) : device_id(_device_id),
                                    timestamp(_timestamp),
                                    data_length(_data_length),
                                    IoTPacket(IoTPacket::Topic::DATA) {
                                      assert(_data_length <= CLOUDIOTMANAGEMENT_IOT_DATA_PACKET_DATA_FIELD_SIZE_BYTES_MAXIMUM);

                                      /* Copy data bytes over into IoTDataPacket-owned static array. */
                                      std::memcpy(data, _data, _data_length);
                                    }
    
    /**
     * @brief Serializes the packet into a sequence of bytes, placing these
     * bytes into the specified buffer owned by the caller.
     *
     * NOTE: This buffer must be at LEAST the length required for the packet of
     * interest, which can be determined by the `get_serialized_length` method.
     *
     * @param output_buffer Buffer to hold serialized bytes.
     * @param buffer_length Size of the specified buffer to hold serialized bytes.
     */
    virtual void serialize(uint8_t *output_buffer, size_t buffer_length) override;

    /**
     * @brief Specifies the length of the serialized packet, which can be used
     * to properly size buffers accordingly.
     */
    virtual size_t get_serialized_length() const override;

    uint32_t device_id;
    uint64_t timestamp;
    uint32_t data_length;
    uint8_t data[CLOUDIOTMANAGEMENT_IOT_DATA_PACKET_DATA_FIELD_SIZE_BYTES_MAXIMUM];
  };

  /**
   * @brief Structure representing the IoT Status Modem packet used in the
   * custom CloudIoTManagement protocol.
   */
  struct IoTStatusPacket final : IoTPacket {
  public:
    /**
     * @brief Enum for Status field in IoT Status Modem packet.
     */
    enum Status : uint8_t {
      NOMINAL = 0x0,
      IDLE = 0x1,
      OFF_NOMINAL = 0x2
    };

    /**
     * @brief Constructor for IoTStatusPacket.
     */
    IoTStatusPacket() : IoTPacket(IoTPacket::Topic::STATUS) {}
    IoTStatusPacket(Status _status) : status(_status),
                                      IoTPacket(IoTPacket::Topic::STATUS) {}

    /**
     * @brief Serializes the packet into a sequence of bytes, placing these
     * bytes into the specified buffer owned by the caller.
     *
     * NOTE: This buffer must be at LEAST the length required for the packet of
     * interest, which can be determined by the `get_serialized_length` method.
     *
     * @param output_buffer Buffer to hold serialized bytes.
     * @param buffer_length Size of the specified buffer to hold serialized bytes.
     */
    virtual void serialize(uint8_t *output_buffer, size_t buffer_length) override;

    /**
     * @brief Specifies the length of the serialized packet, which can be used
     * to properly size buffers accordingly.
     */
    virtual size_t get_serialized_length() const override;

    Status status;
  };

  /**
   * @brief Structure representing the Carrier Switch Perform Modem packet used
   * in the custom CloudIoTManagement protocol.
   */
  struct CarrierSwitchPerformPacket final : CarrierSwitchPacket {
  public:
    /**
     * @brief Enum for Status field in IoT Status Modem packet.
     */
    enum Status : uint8_t {
      NOMINAL = 0x0,
      IDLE = 0x1,
      OFF_NOMINAL = 0x2
    };

    /**
     * @brief Constructor for CarrierSwitchPerformPacket.
     */
    CarrierSwitchPerformPacket() : CarrierSwitchPacket(CarrierSwitchPacket::Topic::PERFORM) {}
    CarrierSwitchPerformPacket(CarrierID _carrier_id) : carrier_id(_carrier_id),
                                                        CarrierSwitchPacket(CarrierSwitchPacket::Topic::PERFORM) {}

    /**
     * @brief Serializes the packet into a sequence of bytes, placing these
     * bytes into the specified buffer owned by the caller.
     *
     * NOTE: This buffer must be at LEAST the length required for the packet of
     * interest, which can be determined by the `get_serialized_length` method.
     *
     * @param output_buffer Buffer to hold serialized bytes.
     * @param buffer_length Size of the specified buffer to hold serialized bytes.
     */
    virtual void serialize(uint8_t *output_buffer, size_t buffer_length) override;

    /**
     * @brief Specifies the length of the serialized packet, which can be used
     * to properly size buffers accordingly.
     */
    virtual size_t get_serialized_length() const override;

    CarrierID carrier_id;
  };

  /**
   * @brief Structure representing the Carrier Switch ACK Modem packet used in
   * the custom CloudIoTManagement protocol.
   */
  struct CarrierSwitchACKPacket final : CarrierSwitchPacket {
  public:
    /**
     * @brief Enum for Status field in Carrier Switch ACK Modem packet.
     */
    enum Status : uint8_t {
      ACK = 0x0,
      NACK = 0x1
    };

    /**
     * @brief Constructor for CarrierSwitchACKPacket.
     */
    CarrierSwitchACKPacket() : CarrierSwitchPacket(CarrierSwitchPacket::Topic::ACK) {}
    CarrierSwitchACKPacket(Status _status,
                           CarrierID _carrier_id) : status(_status),
                                                    carrier_id(_carrier_id),
                                                    CarrierSwitchPacket(CarrierSwitchPacket::Topic::ACK) {}

    /**
     * @brief Serializes the packet into a sequence of bytes, placing these
     * bytes into the specified buffer owned by the caller.
     *
     * NOTE: This buffer must be at LEAST the length required for the packet of
     * interest, which can be determined by the `get_serialized_length` method.
     *
     * @param output_buffer Buffer to hold serialized bytes.
     * @param buffer_length Size of the specified buffer to hold serialized bytes.
     */
    virtual void serialize(uint8_t *output_buffer, size_t buffer_length) override;

    /**
     * @brief Specifies the length of the serialized packet, which can be used
     * to properly size buffers accordingly.
     */
    virtual size_t get_serialized_length() const override;

    Status status;
    CarrierID carrier_id;
  };

  /**
   * @brief Constructor/destructor for CloudIoTManagement class.
   *
   * @param _debug Indicate whether or not to output debugging messages to STDOUT.
   */
  CloudIoTManagement(bool _debug);
  CloudIoTManagement();
  ~CloudIoTManagement();

  /**
   * @brief Initializes the CloudIoTManagement class, particularly the
   * connection with the external SIM card.
   *
   * NOTE: This SIM card/Javacard is connected external to the srsRAN stack,
   * due to the current project's scope. In a future extension of this project,
   * we look towards avoiding this external connection, instead exclusively
   * working within the srsRAN stack.
   *
   * @returns SRSRAN_SUCCESS on success, SRSRAN_ERROR on failure.
   */
  int init();

  /**
   * @brief Checks the PDU packet to confirm if it should be decoded as a
   * custom Modem packet, as defined by the custom CloudIoTManagement protocol.
   * This applicability is currently determined based on the UDP packet
   * header's destination port number.
   *
   * NOTE: Since our SIM card/Javacard is connected external to the srsRAN stack,
   * due to the current project's scope, we utilize this method to determine
   * which packets we should intercept and handle separate from the srsRAN's
   * handling. In the future, this interception should look to be de-integrated
   * as much as possible.
   *
   * @returns true if the PDU contains an applicable packet, false otherwise.
   */
  bool contains_applicable_packet(const uint8_t *pdu_buffer, size_t num_bytes);

  /**
   * @brief Decodes the UDP packet contained within the PDU packet according to
   * the custom CloudIoTManagement protocol's defined Modem packet structure,
   * and sends it to the (externally-connected) SIM card. This method should
   * only be called if `contains_applicable_packet` returns `true` when called
   * on the same PDU packet.
   * 
   * NOTE: Since our SIM card/Javacard is connected external to the srsRAN stack,
   * due to the current project's scope, we utilize this method as the main
   * entry-point to performing the special handling of the intercepted packets
   * intended for its delivery to our on-SIM-card-application. In the future,
   * this interception should look to be de-integrated as much as possible.
   *
   * @param pdu_buffer Buffer holding the PDU message that contains the custom
   * UDP packet to handle.
   * @param num_bytes Size of the `pdu_buffer` argument (expected to be at
   * least PDU_HEADER_SIZE_BYTES + minimum Modem packet size of 2 bytes).
   */
  void handle_packet(const uint8_t *pdu_buffer, size_t num_bytes);

  /**
   * @brief Constructs/formats the associated APDU message for the specified
   * Modem packet, and transmits it to the SIM card.
   *
   * NOTE: The `init` method must be called to initialize the
   * CloudIoTManagement object before invoking this method.
   *
   * @param packet const reference to the Modem packet to be sent.
   */
  void send_to_sim(const ModemPacket &packet);

private:
  /**
   * @brief Decoder helper method for IoT Data Modem packets. Returns whether
   * or not the IoT Data packet was valid and/or decoding was successful. If
   * the decoding was unsuccessful, the IoTDataPacket's contents are not to
   * be trusted.
   *
   * NOTE: Buffer size validation is expected to be completed by the caller.
   *
   * @param packet_buffer const pointer to the byte buffer to decode.
   * @param packet const reference to the IoTDataPacket object to populate.
   *
   * @returns true if the decoding was successful, false otherwise.
   */
  bool decode_iot_data(const uint8_t *packet_buffer, IoTDataPacket &packet);

  /**
   * @brief Decoder helper method for IoT Status Modem packets. Returns whether
   * or not the IoT Status packet was valid and/or decoding was successful. If
   * the decoding was unsuccessful, the IoTStatusPacket's contents are not to
   * be trusted.
   *
   * NOTE: Buffer size validation is expected to be completed by the caller.
   *
   * @param packet_buffer const pointer to the byte buffer to decode.
   * @param packet const reference to the IoTStatusPacket object to populate.
   *
   * @returns true if the decoding was successful, false otherwise.
   */
  bool decode_iot_status(const uint8_t *packet_buffer, IoTStatusPacket &packet);

  /**
   * @brief Decoder helper method for Carrier Switch Perform Modem packets.
   * Returns whether or not the Carrier Switch Perform packet was valid and/or
   * decoding was successful. If the decoding was unsuccessful, the
   * CarrierSwitchPerformPacket's contents are not to be trusted.
   *
   * NOTE: Buffer size validation is expected to be completed by the caller.
   *
   * @param packet_buffer const pointer to the byte buffer to decode.
   * @param packet const reference to the CarrierSwitchPerformPacket object to populate.
   *
   * @returns true if the decoding was successful, false otherwise.
   */
  bool decode_carrier_switch_perform(const uint8_t *packet_buffer, CarrierSwitchPerformPacket &packet);

  /**
   * @brief Decoder helper method for Carrier Switch ACK Modem packets.
   * Returns whether or not the Carrier Switch ACK packet was valid and/or
   * decoding was successful. If the decoding was unsuccessful, the
   * CarrierSwitchACKPacket's contents are not to be trusted.
   *
   * NOTE: Buffer size validation is expected to be completed by the caller.
   *
   * @param packet_buffer const pointer to the byte buffer to decode.
   * @param packet const reference to the CarrierSwitchACKPacket object to populate.
   *
   * @returns true if the decoding was successful, false otherwise.
   */
  bool decode_carrier_switch_ack(const uint8_t *packet_buffer, CarrierSwitchACKPacket &packet);

  /**
   * @brief Boolean flag determining whether or not debugging logs should be
   * outputted or not.
   */
  bool debug;

  /**
   * @brief Boolean flag determining whether or not the CloudIoTManagement
   * object's `init` method has been called yet.
   */
  bool initialized;
};

} // namespace srsue

#endif // SRSUE_GW_H
