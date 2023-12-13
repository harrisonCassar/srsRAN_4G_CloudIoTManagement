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

#include "srsue/hdr/stack/upper/gw.h"
#include "srsue/hdr/stack/upper/pcsc_usim.h"
#include "srsran/common/standard_streams.h"
#include "srsran/interfaces/ue_pdcp_interfaces.h"
#include "srsran/upper/ipv6.h"

#include <arpa/inet.h>
#include <cstdint>
#include <errno.h>
#include <fcntl.h>
#include <linux/if_tun.h>
#include <linux/ip.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

namespace srsue {

/*****************************************************************************
 * gw Class Definition
 *****************************************************************************/

gw::gw(srslog::basic_logger& logger_) : thread("GW"), logger(logger_), tft_matcher(logger), cloudiotmanagement(CLOUDIOTMANAGEMENT_DEBUG) {}

int gw::init(const gw_args_t& args_, stack_interface_gw* stack_)
{
  stack      = stack_;
  args       = args_;
  run_enable = true;

  logger.set_level(srslog::str_to_basic_level(args.log.gw_level));
  logger.set_hex_dump_max_size(args.log.gw_hex_limit);

  metrics_tp = std::chrono::high_resolution_clock::now();

  // MBSFN
  mbsfn_sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (mbsfn_sock_fd < 0) {
    logger.error("Failed to create MBSFN sink socket");
    return SRSRAN_ERROR;
  }
  if (fcntl(mbsfn_sock_fd, F_SETFL, O_NONBLOCK)) {
    logger.error("Failed to set non-blocking MBSFN sink socket");
    return SRSRAN_ERROR;
  }

  mbsfn_sock_addr.sin_family = AF_INET;
  if (inet_pton(mbsfn_sock_addr.sin_family, "127.0.0.1", &mbsfn_sock_addr.sin_addr.s_addr) != 1) {
    perror("inet_pton");
    return false;
  }

  /* Init the CloudIoTManagement object. */
  cloudiotmanagement.init();

  return SRSRAN_SUCCESS;
}

gw::~gw()
{
  if (tun_fd > 0) {
    close(tun_fd);
  }
}

void gw::stop()
{
  if (run_enable) {
    run_enable = false;
    if (if_up) {
      if_up = false;
      if (running) {
        thread_cancel();
      }

      // Wait thread to exit gracefully otherwise might leave a mutex locked
      int cnt = 0;
      while (running && cnt < 100) {
        usleep(10000);
        cnt++;
      }
      wait_thread_finish();

      current_ip_addr = 0;
    }
    // TODO: tear down TUN device?
  }
  if (mbsfn_sock_fd) {
    close(mbsfn_sock_fd);
  }
}

void gw::get_metrics(gw_metrics_t& m, const uint32_t nof_tti)
{
  std::lock_guard<std::mutex> lock(gw_mutex);

  std::chrono::duration<double> secs = std::chrono::high_resolution_clock::now() - metrics_tp;

  double dl_tput_mbps_real_time = (dl_tput_bytes * 8 / (double)1e6) / secs.count();
  double ul_tput_mbps_real_time = (ul_tput_bytes * 8 / (double)1e6) / secs.count();

  // Use the provided TTI counter to compute rate for metrics interface
  m.dl_tput_mbps = (nof_tti > 0) ? ((dl_tput_bytes * 8 / (double)1e6) / (nof_tti / 1000.0)) : 0.0;
  m.ul_tput_mbps = (nof_tti > 0) ? ((ul_tput_bytes * 8 / (double)1e6) / (nof_tti / 1000.0)) : 0.0;

  logger.debug("gw_rx_rate_mbps=%4.2f (real=%4.2f), gw_tx_rate_mbps=%4.2f (real=%4.2f)",
               m.dl_tput_mbps,
               dl_tput_mbps_real_time,
               m.ul_tput_mbps,
               ul_tput_mbps_real_time);

  // reset counters and store time
  metrics_tp    = std::chrono::high_resolution_clock::now();
  dl_tput_bytes = 0;
  ul_tput_bytes = 0;
}

/*****************************************************************************
 * gw - PDCP Interface
 *****************************************************************************/
void gw::write_pdu(uint32_t lcid, srsran::unique_byte_buffer_t pdu)
{
  logger.info(pdu->msg, pdu->N_bytes, "RX PDU. Stack latency: %ld us", pdu->get_latency_us().count());
  {
    std::unique_lock<std::mutex> lock(gw_mutex);
    dl_tput_bytes += pdu->N_bytes;
  }
  if (!if_up) {
    if (run_enable) {
      logger.warning("TUN/TAP not up - dropping gw RX message");
    }
  } else if (pdu->N_bytes < 20) {
    // Packet not large enough to hold IPv4 Header
    logger.warning("Packet too small to hold IPv4 header. Dropping packet with %d B", pdu->N_bytes);
  } else {
    // Only handle IPv4 and IPv6 packets
    struct iphdr* ip_pkt = (struct iphdr*)pdu->msg;
    if (ip_pkt->version == 4 || ip_pkt->version == 6) {
      if (CLOUDIOTMANAGEMENT_DEBUG) {
        printf("CloudIoTManagement: write_pdu with packet %u; ihl: %u; tot_len: %u; pdu->N_bytes: %u\n", ip_pkt->version, ip_pkt->ihl, ip_pkt->tot_len, pdu->N_bytes);
      }

      /* Intercept all CloudIoTManagement-specific packets to handle separately. */
      if (cloudiotmanagement.contains_applicable_packet(pdu->msg, pdu->N_bytes)) {
        /*
         * Packet is a CloudIoTManagement packet, so perform special handling,
         * specifically by decoding it, and constructing and sending the
         * appropiate APDU message to the externally-connected SIM card
         * according to the CloudIoTManagement custom protocol.
         */
        if (CLOUDIOTMANAGEMENT_DEBUG) {
          printf("CloudIoTManagement: Found applicable packet!\n");
        }
        cloudiotmanagement.handle_packet(pdu->msg, pdu->N_bytes);
      } else {
        /*
         * Packet is a non-CloudIoTManagement packet, so perform normal
         * handling by writing it to the srsRAN network stack.
         */
        int n = write(tun_fd, pdu->msg, pdu->N_bytes);
        if (n > 0 && (pdu->N_bytes != (uint32_t)n)) {
          logger.warning("DL TUN/TAP write failure. Wanted to write %d B but only wrote %d B.", pdu->N_bytes, n);
        }
      }
    } else {
      logger.error("Unsupported IP version. Dropping packet with %d B", pdu->N_bytes);
    }
  }
}

void gw::write_pdu_mch(uint32_t lcid, srsran::unique_byte_buffer_t pdu)
{
  if (pdu->N_bytes > 2) {
    logger.info(pdu->msg,
                pdu->N_bytes,
                "RX MCH PDU (%d B). Stack latency: %ld us",
                pdu->N_bytes,
                pdu->get_latency_us().count());
    {
      std::unique_lock<std::mutex> lock(gw_mutex);
      dl_tput_bytes += pdu->N_bytes;
    }

    // Hack to drop initial 2 bytes
    pdu->msg += 2;
    pdu->N_bytes -= 2;
    struct in_addr dst_addr;
    memcpy(&dst_addr.s_addr, &pdu->msg[16], 4);

    if (!if_up) {
      if (run_enable) {
        logger.warning("TUN/TAP not up - dropping gw RX message");
      }
    } else {
      struct iphdr* ip_pkt = (struct iphdr*)pdu->msg;
      unsigned char tmp = ip_pkt->version;
      printf("harrison: write_pdu_mch with packet %d; ihl: %d; tot_len: %d\n", tmp, ip_pkt->ihl, ip_pkt->tot_len);
      int n = write(tun_fd, pdu->msg, pdu->N_bytes);
      if (n > 0 && (pdu->N_bytes != (uint32_t)n)) {
        logger.warning("DL TUN/TAP write failure");
      }
    }
  }
}

/*****************************************************************************
 * gw - NAS Interface
 *****************************************************************************/
int gw::setup_if_addr(uint32_t eps_bearer_id, uint8_t pdn_type, uint32_t ip_addr, uint8_t* ipv6_if_addr, char* err_str)
{
  int err;

  // Make sure the worker thread is terminated before spawning a new one.
  if (running) {
    run_enable = false;
    thread_cancel();
    wait_thread_finish();
  }
  if (pdn_type == LIBLTE_MME_PDN_TYPE_IPV4 || pdn_type == LIBLTE_MME_PDN_TYPE_IPV4V6) {
    err = setup_if_addr4(ip_addr, err_str);
    if (err != SRSRAN_SUCCESS) {
      return err;
    }
  }
  if (pdn_type == LIBLTE_MME_PDN_TYPE_IPV6 || pdn_type == LIBLTE_MME_PDN_TYPE_IPV4V6) {
    err = setup_if_addr6(ipv6_if_addr, err_str);
    if (err != SRSRAN_SUCCESS) {
      return err;
    }
  }

  default_eps_bearer_id = static_cast<int>(eps_bearer_id);

  // Setup a thread to receive packets from the TUN device
  run_enable = true;
  start(GW_THREAD_PRIO);

  return SRSRAN_SUCCESS;
}

int gw::deactivate_eps_bearer(const uint32_t eps_bearer_id)
{
  std::lock_guard<std::mutex> lock(gw_mutex);

  // only deactivation of default bearer
  if (eps_bearer_id == static_cast<uint32_t>(default_eps_bearer_id)) {
    logger.debug("Deactivating EPS bearer %d", eps_bearer_id);
    default_eps_bearer_id = NOT_ASSIGNED;
    return SRSRAN_SUCCESS;
  } else {
    // delete TFT template (if any) for this bearer
    tft_matcher.delete_tft_for_eps_bearer(eps_bearer_id);
    return SRSRAN_SUCCESS;
  }
}

bool gw::is_running()
{
  return running;
}

int gw::apply_traffic_flow_template(const uint8_t& erab_id, const LIBLTE_MME_TRAFFIC_FLOW_TEMPLATE_STRUCT* tft)
{
  return tft_matcher.apply_traffic_flow_template(erab_id, tft);
}

void gw::set_test_loop_mode(const test_loop_mode_state_t mode, const uint32_t ip_pdu_delay_ms)
{
  logger.error("UE test loop mode not supported");
}

/*****************************************************************************
 * gw - RRC Interface
 *****************************************************************************/
void gw::add_mch_port(uint32_t lcid, uint32_t port)
{
  if (lcid > 0 && lcid < SRSRAN_N_MCH_LCIDS) {
    mbsfn_ports[lcid] = port;
  }
}

/*****************************************************************************
 * gw - GW Receive
 *****************************************************************************/
void gw::run_thread()
{
  uint32 idx     = 0;
  int32  N_bytes = 0;

  srsran::unique_byte_buffer_t pdu = srsran::make_byte_buffer();
  if (!pdu) {
    logger.error("Couldn't allocate PDU in %s().", __FUNCTION__);
    return;
  }

  const static uint32_t REGISTER_WAIT_TOUT = 40, SERVICE_WAIT_TOUT = 40; // 4 sec
  uint32_t              register_wait = 0, service_wait = 0;

  logger.info("GW IP packet receiver thread run_enable");

  running = true;
  while (run_enable) {
    // Read packet from TUN
    if (SRSRAN_MAX_BUFFER_SIZE_BYTES - SRSRAN_BUFFER_HEADER_OFFSET > idx) {
      N_bytes = read(tun_fd, &pdu->msg[idx], SRSRAN_MAX_BUFFER_SIZE_BYTES - SRSRAN_BUFFER_HEADER_OFFSET - idx);
    } else {
      logger.error("GW pdu buffer full - gw receive thread exiting.");
      srsran::console("GW pdu buffer full - gw receive thread exiting.\n");
      break;
    }
    logger.debug("Read %d bytes from TUN fd=%d, idx=%d", N_bytes, tun_fd, idx);

    if (N_bytes <= 0) {
      logger.error("Failed to read from TUN interface - gw receive thread exiting.");
      srsran::console("Failed to read from TUN interface - gw receive thread exiting.\n");
      break;
    }

    {
      std::unique_lock<std::mutex> lock(gw_mutex);
      // Check if IP version makes sense and get packtet length
      struct iphdr*   ip_pkt  = (struct iphdr*)pdu->msg;
      struct ipv6hdr* ip6_pkt = (struct ipv6hdr*)pdu->msg;
      uint16_t        pkt_len = 0;
      pdu->N_bytes            = idx + N_bytes;
      if (ip_pkt->version == 4) {
        pkt_len = ntohs(ip_pkt->tot_len);
      } else if (ip_pkt->version == 6) {
        pkt_len = ntohs(ip6_pkt->payload_len) + 40;
      } else {
        logger.error(pdu->msg, pdu->N_bytes, "Unsupported IP version. Dropping packet.");
        continue;
      }
      logger.debug("IPv%d packet total length: %d Bytes", int(ip_pkt->version), pkt_len);

      // Check if entire packet was received
      if (pkt_len == pdu->N_bytes) {
        logger.info(pdu->msg, pdu->N_bytes, "TX PDU");

        // Make sure UE is attached and has default EPS bearer activated
        while (run_enable && default_eps_bearer_id == NOT_ASSIGNED && register_wait < REGISTER_WAIT_TOUT) {
          if (!register_wait) {
            logger.info("UE is not attached, waiting for NAS attach (%d/%d)", register_wait, REGISTER_WAIT_TOUT);
          }
          lock.unlock();
          std::this_thread::sleep_for(std::chrono::microseconds(100));
          lock.lock();
          register_wait++;
        }
        register_wait = 0;

        // If we are still not attached by this stage, drop packet
        if (run_enable && default_eps_bearer_id == NOT_ASSIGNED) {
          continue;
        }

        if (!run_enable) {
          break;
        }

        // Beyond this point we should have a activated default EPS bearer
        srsran_assert(default_eps_bearer_id != NOT_ASSIGNED, "Default EPS bearer not activated");

        uint8_t eps_bearer_id = default_eps_bearer_id;
        tft_matcher.check_tft_filter_match(pdu, eps_bearer_id);

        // Wait for service request if necessary
        while (run_enable && !stack->has_active_radio_bearer(eps_bearer_id) && service_wait < SERVICE_WAIT_TOUT) {
          if (!service_wait) {
            logger.info(
                "UE does not have service, waiting for NAS service request (%d/%d)", service_wait, SERVICE_WAIT_TOUT);
            stack->start_service_request();
          }
          usleep(100000);
          service_wait++;
        }
        service_wait = 0;

        // Quit before writing packet if necessary
        if (!run_enable) {
          break;
        }

        // Send PDU directly to PDCP
        pdu->set_timestamp();
        ul_tput_bytes += pdu->N_bytes;
        stack->write_sdu(eps_bearer_id, std::move(pdu));
        do {
          pdu = srsran::make_byte_buffer();
          if (!pdu) {
            logger.error("Fatal Error: Couldn't allocate PDU in run_thread().");
            usleep(100000);
          }
        } while (!pdu);
        idx = 0;
      } else {
        idx += N_bytes;
        logger.debug("Entire packet not read from socket. Total Length %d, N_Bytes %d.", ip_pkt->tot_len, pdu->N_bytes);
      }
    } // end of holdering gw_mutex
  }
  running = false;
  logger.info("GW IP receiver thread exiting.");
}

/*****************************************************************************
 * gw - TUN Interface Helpers
 *****************************************************************************/
int gw::init_if(char* err_str)
{
  if (if_up) {
    return SRSRAN_ERROR_ALREADY_STARTED;
  }

  // change into netns
  if (!args.netns.empty()) {
    std::string netns("/run/netns/");
    netns += args.netns;
    netns_fd = open(netns.c_str(), O_RDONLY);
    if (netns_fd == -1) {
      err_str = strerror(errno);
      logger.error("Failed to find netns %s (%s): %s", args.netns.c_str(), netns.c_str(), err_str);
      return SRSRAN_ERROR_CANT_START;
    }
    if (setns(netns_fd, CLONE_NEWNET) == -1) {
      err_str = strerror(errno);
      logger.error("Failed to change netns: %s", err_str);
      return SRSRAN_ERROR_CANT_START;
    }
  }

  // Construct the TUN device
  tun_fd = open("/dev/net/tun", O_RDWR);
  logger.info("TUN file descriptor = %d", tun_fd);
  if (0 > tun_fd) {
    err_str = strerror(errno);
    logger.error("Failed to open TUN device: %s", err_str);
    return SRSRAN_ERROR_CANT_START;
  }

  memset(&ifr, 0, sizeof(ifr));
  ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
  strncpy(
      ifr.ifr_ifrn.ifrn_name, args.tun_dev_name.c_str(), std::min(args.tun_dev_name.length(), (size_t)(IFNAMSIZ - 1)));
  ifr.ifr_ifrn.ifrn_name[IFNAMSIZ - 1] = 0;
  if (0 > ioctl(tun_fd, TUNSETIFF, &ifr)) {
    err_str = strerror(errno);
    logger.error("Failed to set TUN device name: %s", err_str);
    close(tun_fd);
    return SRSRAN_ERROR_CANT_START;
  }

  // Bring up the interface
  sock = socket(AF_INET, SOCK_DGRAM, 0);
  if (0 > ioctl(sock, SIOCGIFFLAGS, &ifr)) {
    err_str = strerror(errno);
    logger.error("Failed to bring up socket: %s", err_str);
    close(tun_fd);
    return SRSRAN_ERROR_CANT_START;
  }
  ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
  if (0 > ioctl(sock, SIOCSIFFLAGS, &ifr)) {
    err_str = strerror(errno);
    logger.error("Failed to set socket flags: %s", err_str);
    close(tun_fd);
    return SRSRAN_ERROR_CANT_START;
  }

  // Delete link-local IPv6 address.
  struct in6_addr in6p;
  char            addr_str[INET6_ADDRSTRLEN];
  if (find_ipv6_addr(&in6p)) {
    logger.debug("Found link-local IPv6 address: %s", inet_ntop(AF_INET6, &in6p, addr_str, INET6_ADDRSTRLEN));
    del_ipv6_addr(&in6p);
  } else {
    logger.warning("Could not find link-local IPv6 address.");
  }
  if_up = true;

  return SRSRAN_SUCCESS;
}

int gw::setup_if_addr4(uint32_t ip_addr, char* err_str)
{
  if (ip_addr != current_ip_addr) {
    if (!if_up) {
      if (init_if(err_str)) {
        logger.error("init_if failed");
        return SRSRAN_ERROR_CANT_START;
      }
    }

    if (sock > 0) {
      close(sock);
    }
    // Setup the IP address
    sock                                                  = socket(AF_INET, SOCK_DGRAM, 0);
    ifr.ifr_addr.sa_family                                = AF_INET;
    ((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr.s_addr = htonl(ip_addr);
    if (0 > ioctl(sock, SIOCSIFADDR, &ifr)) {
      err_str = strerror(errno);
      logger.debug("Failed to set socket address: %s", err_str);
      close(tun_fd);
      return SRSRAN_ERROR_CANT_START;
    }
    ifr.ifr_netmask.sa_family = AF_INET;
    if (inet_pton(ifr.ifr_netmask.sa_family,
                  args.tun_dev_netmask.c_str(),
                  &((struct sockaddr_in*)&ifr.ifr_netmask)->sin_addr.s_addr) != 1) {
      logger.error("Invalid tun_dev_netmask: %s", args.tun_dev_netmask.c_str());
      srsran::console("Invalid tun_dev_netmask: %s\n", args.tun_dev_netmask.c_str());
      perror("inet_pton");
      return SRSRAN_ERROR_CANT_START;
    }
    if (0 > ioctl(sock, SIOCSIFNETMASK, &ifr)) {
      err_str = strerror(errno);
      logger.debug("Failed to set socket netmask: %s", err_str);
      close(tun_fd);
      return SRSRAN_ERROR_CANT_START;
    }
    current_ip_addr = ip_addr;
  }
  return SRSRAN_SUCCESS;
}

int gw::setup_if_addr6(uint8_t* ipv6_if_id, char* err_str)
{
  struct sockaddr_in6 sai;
  struct in6_ifreq    ifr6;
  bool                match = true;

  for (int i = 0; i < 8; i++) {
    if (ipv6_if_id[i] != current_if_id[i]) {
      match = false;
      break;
    }
  }

  if (!match) {
    if (!if_up) {
      if (init_if(err_str)) {
        logger.error("init_if failed");
        return SRSRAN_ERROR_CANT_START;
      }
    }

    if (sock > 0) {
      close(sock);
    }
    // Setup the IP address
    sock                   = socket(AF_INET6, SOCK_DGRAM, 0);
    ifr.ifr_addr.sa_family = AF_INET6;

    if (inet_pton(AF_INET6, "fe80::", (void*)&sai.sin6_addr) <= 0) {
      logger.error("Bad address");
      return SRSRAN_ERROR_CANT_START;
    }

    memcpy(&sai.sin6_addr.s6_addr[8], ipv6_if_id, 8);
    if (ioctl(sock, SIOGIFINDEX, &ifr) < 0) {
      perror("SIOGIFINDEX");
      return SRSRAN_ERROR_CANT_START;
    }
    ifr6.ifr6_ifindex   = ifr.ifr_ifindex;
    ifr6.ifr6_prefixlen = 64;
    memcpy((char*)&ifr6.ifr6_addr, (char*)&sai.sin6_addr, sizeof(struct in6_addr));

    if (ioctl(sock, SIOCSIFADDR, &ifr6) < 0) {
      err_str = strerror(errno);
      logger.error("Could not set IPv6 Link local address. Error %s", err_str);
      return SRSRAN_ERROR_CANT_START;
    }

    for (int i = 0; i < 8; i++) {
      current_if_id[i] = ipv6_if_id[i];
    }
  }

  return SRSRAN_SUCCESS;
}

bool gw::find_ipv6_addr(struct in6_addr* in6_out)
{
  int               n, rtattrlen, fd = -1;
  unsigned int      if_index;
  struct rtattr *   rta, *rtatp;
  struct nlmsghdr*  nlmp;
  struct ifaddrmsg* rtmp;
  struct in6_addr*  in6p;
  char              buf[2048];
  struct {
    struct nlmsghdr  n;
    struct ifaddrmsg r;
    char             buf[1024];
  } req;

  logger.debug("Trying to obtain IPv6 addr of %s interface", args.tun_dev_name.c_str());

  // Get Interface Index
  if_index = if_nametoindex(args.tun_dev_name.c_str());
  if (if_index == 0) {
    logger.error("Could not find interface index");
    goto err_out;
  }

  // Open NETLINK socket
  fd = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
  if (fd < 0) {
    logger.error("Error openning NETLINK socket -- %s", strerror(errno));
    goto err_out;
  }

  // We use RTM_GETADDR to get the ip address from the kernel
  memset(&req, 0, sizeof(req));
  req.n.nlmsg_len   = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
  req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_MATCH;
  req.n.nlmsg_type  = RTM_GETADDR;

  // AF_INET6 is used to signify the kernel to fetch only ipv6 entires.
  req.r.ifa_family = AF_INET6;

  // Fill up all the attributes for the rtnetlink header.
  // The length is important. 16 signifies we are requesting IPv6 addresses
  rta          = (struct rtattr*)(((char*)&req) + NLMSG_ALIGN(req.n.nlmsg_len));
  rta->rta_len = RTA_LENGTH(16);

  // Time to send and recv the message from kernel
  n = send(fd, &req, req.n.nlmsg_len, 0);
  if (n < 0) {
    logger.error("Error sending NETLINK message to kernel -- %s", strerror(errno));
    goto err_out;
  }

  n = recv(fd, buf, sizeof(buf), 0);
  if (n < 0) {
    logger.error("Error receiving from NETLINK socket");
    goto err_out;
  }

  if (n == 0) {
    logger.error("Nothing received from NETLINK Socket");
    goto err_out;
  }

  // Parse the reply
  for (nlmp = (struct nlmsghdr*)buf; NLMSG_OK(nlmp, n); nlmp = NLMSG_NEXT(nlmp, n)) {
    // Chack NL message type
    if (nlmp->nlmsg_type == NLMSG_DONE) {
      logger.error("Reach end of NETLINK message without finding IPv6 address.");
      goto err_out;
    }
    if (nlmp->nlmsg_type == NLMSG_ERROR) {
      logger.error("NLMSG_ERROR in NETLINK reply");
      goto err_out;
    }
    logger.debug("NETLINK message type %d", nlmp->nlmsg_type);

    // Get IFA message
    rtmp      = (struct ifaddrmsg*)NLMSG_DATA(nlmp);
    rtatp     = (struct rtattr*)IFA_RTA(rtmp);
    rtattrlen = IFA_PAYLOAD(nlmp);
    for (; RTA_OK(rtatp, rtattrlen); rtatp = RTA_NEXT(rtatp, rtattrlen)) {
      // We are looking IFA_ADDRESS rt_attribute type.
      // For more info on the different types see man(7) rtnetlink.
      if (rtatp->rta_type == IFA_ADDRESS) {
        in6p = (struct in6_addr*)RTA_DATA(rtatp);
        if (if_index == rtmp->ifa_index) {
          for (int i = 0; i < 16; i++) {
            in6_out->s6_addr[i] = in6p->s6_addr[i];
          }
          goto out;
        }
      }
    }
  }

err_out:
  if (fd > 0) {
    close(fd);
  }
  return false;
out:
  close(fd);
  return true;
}

void gw::del_ipv6_addr(struct in6_addr* in6p)
{
  int          status, fd = -1;
  unsigned int if_index;
  struct {
    struct nlmsghdr  n;
    struct ifaddrmsg ifa;
    char             buf[1024];
  } req;

  // Get Interface Index
  if_index = if_nametoindex(args.tun_dev_name.c_str());
  if (if_index == 0) {
    logger.error("Could not find interface index");
    goto out;
  }

  // Open netlink socket
  fd = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
  if (fd < 0) {
    logger.error("Error openning NETLINK socket -- %s", strerror(errno));
    goto out;
  }

  // We use RTM_DELADDR to delete the ip address from the interface
  memset(&req, 0, sizeof(req));
  req.n.nlmsg_len   = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
  req.n.nlmsg_type  = RTM_DELADDR;
  req.n.nlmsg_flags = NLM_F_REQUEST;

  req.ifa.ifa_family    = AF_INET6;
  req.ifa.ifa_prefixlen = 64;
  req.ifa.ifa_index     = if_index; // set the tun_srsue index
  req.ifa.ifa_scope     = 0;

  // Add RT atribute
  struct rtattr* rta;
  rta           = (struct rtattr*)(((char*)&req.n) + NLMSG_ALIGN(req.n.nlmsg_len));
  rta->rta_type = IFA_LOCAL;
  rta->rta_len  = RTA_LENGTH(16);
  memcpy(RTA_DATA(rta), in6p, 16);
  req.n.nlmsg_len = NLMSG_ALIGN(req.n.nlmsg_len) + rta->rta_len;

  status = send(fd, &req, req.n.nlmsg_len, 0);
  if (status < 0) {
    logger.error("Error sending NETLINK message");
    goto out;
  }

out:
  if (fd >= 0) {
    close(fd);
  }
}

/*****************************************************************************
 * CloudIoTManagement Class Definition
 *****************************************************************************/

CloudIoTManagement::CloudIoTManagement(bool _debug) : debug(_debug),
                                                      sc(_debug),
                                                      uplink_socket_fd(-1),
                                                      initialized(false) {
                                                        memset(&uplink_server_addr, 0, sizeof(uplink_server_addr));
                                                      }
CloudIoTManagement::CloudIoTManagement() : debug(false),
                                           sc(false),
                                           uplink_socket_fd(-1),
                                           initialized(false) {
                                             memset(&uplink_server_addr, 0, sizeof(uplink_server_addr));
                                           }
CloudIoTManagement::~CloudIoTManagement() {
  if (initialized) {
    sc.deinit();
    close(uplink_socket_fd);
  }

  printf("CloudIoTManagement: deinit/destructor completed!");
}

int CloudIoTManagement::init() {
  assert(!initialized);

  /* Init the connection to the SIM card. */
  sc.init();

  /* Init the socket we will use to uplink traffic to the cloud subsystem's UDP server. */
  if ((uplink_socket_fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
    printf("CloudIoTManagement ERROR: Uplink docket creation failed: %s\n", strerror(errno));
    return SRSRAN_ERROR;
  }

  uplink_server_addr.sin_family = AF_INET;
  uplink_server_addr.sin_port = htons(CLOUDIOTMANAGEMENT_SERVER_PORT_NUMBER);
  if (inet_pton(AF_INET, CLOUDIOTMANAGEMENT_SERVER_IP_ADDRESS, &uplink_server_addr.sin_addr) <= 0) {
    printf("CloudIoTManagement ERROR: Failed to convert IP address %s: %s\n", CLOUDIOTMANAGEMENT_SERVER_IP_ADDRESS, strerror(errno));
    close(uplink_socket_fd);
    return SRSRAN_ERROR;
  }

  /* Mark that we've now been initialized. */
  initialized = true;

  printf("CloudIoTManagement: init success!\n");

  return SRSRAN_SUCCESS;
}

bool CloudIoTManagement::contains_applicable_packet(const uint8_t *pdu_buffer, size_t num_bytes) {
  assert(num_bytes >= PDU_HEADER_SIZE_BYTES);
  uint16_t destination_port = (pdu_buffer[22] << 8) +
                              (pdu_buffer[23] << 0);
  return destination_port == CLOUDIOTMANAGEMENT_MODEM_PORT_NUMBER;
}

void CloudIoTManagement::handle_packet(const uint8_t *pdu_buffer, size_t num_bytes) {
  assert(initialized);
  assert(pdu_buffer != nullptr);
  assert(num_bytes >= PDU_HEADER_SIZE_BYTES + 1);  // Every PDU must have at least one valid byte beyond its 28 byte header so that we can determine the custom Modem packet header information.

  if (debug) {
    print_pdu(pdu_buffer, num_bytes);
  }

  /* Determine Modem Packet type, and then handle each accordingly (decode and send). */
  ModemPacket::Flow flow = static_cast<ModemPacket::Flow>((pdu_buffer[PDU_HEADER_SIZE_BYTES + ModemPacket::MODEMPACKET_OFFSET_FLOW_FIELD] & 0xF0) >> 4);
  size_t packet_size = num_bytes - PDU_HEADER_SIZE_BYTES;

  if (flow == ModemPacket::Flow::IOT) {
    IoTPacket::Topic topic = static_cast<IoTPacket::Topic>((pdu_buffer[PDU_HEADER_SIZE_BYTES + IoTPacket::IOTPACKET_OFFSET_TOPIC_FIELD] & 0x0F) >> 0);
    if (topic == IoTPacket::Topic::DATA) {
      /* Confirm we have an expected number of bytes, and gracefully handle if not (return early). */
      if (packet_size < CLOUDIOTMANAGEMENT_IOT_DATA_PACKET_SIZE_BYTES_MINIMUM ||
          packet_size > CLOUDIOTMANAGEMENT_IOT_DATA_PACKET_SIZE_BYTES_MAXIMUM) {
        printf("CloudIOTManagement: Although the Modem packet's flow and topic field indicated an IoT Data packet, the determined packet size in bytes was unexpected (got %lu, but expected at least %lu and at most %lu).\n", packet_size, CLOUDIOTMANAGEMENT_IOT_DATA_PACKET_SIZE_BYTES_MINIMUM, CLOUDIOTMANAGEMENT_IOT_DATA_PACKET_SIZE_BYTES_MAXIMUM);
        return;
      }

      /* Decode packet, and send to the SIM card (if there was no decoding errors). */
      IoTDataPacket packet;
      if (!decode_iot_data(&pdu_buffer[PDU_HEADER_SIZE_BYTES], packet)) {
        printf("CloudIOTManagement: An error occured while decoding the IoT Data packet! Dropping packet/avoiding transmission to the SIM card...\n");
        return;
      }

      /* Send packet to SIM card, and buffer the response. */
      uint8_t response_buffer[CLOUDIOTMANAGEMENT_IOT_DATA_PACKET_SIZE_BYTES_MAXIMUM];
      size_t num_response_bytes = sizeof(response_buffer);
      packet.send_and_recv_sim(sc, response_buffer, num_response_bytes);

      /* Send response to our cloud subsystem. */
      send_to_cloud(response_buffer, num_response_bytes);
    }
    else if (topic == IoTPacket::Topic::STATUS) {
      /* Confirm we have an expected number of bytes, and gracefully handle if not (return early). */
      if (packet_size != CLOUDIOTMANAGEMENT_IOT_STATUS_PACKET_SIZE_BYTES) {
        printf("CloudIOTManagement: Although the Modem packet's flow and topic field indicated an IoT Status packet, the determined packet size in bytes was unexpected (got %lu, but expected %lu).\n", packet_size, CLOUDIOTMANAGEMENT_IOT_STATUS_PACKET_SIZE_BYTES);
        return;
      }

      /* Decode packet, and send to the SIM card (if there was no decoding errors). */
      IoTStatusPacket packet;
      if (!decode_iot_status(&pdu_buffer[PDU_HEADER_SIZE_BYTES], packet)) {
        printf("CloudIOTManagement: An error occured while decoding the IoT Status packet! Dropping packet/avoiding transmission to the SIM card...\n");
        return;
      }

      /* Send packet to SIM card, and buffer the response. */
      uint8_t response_buffer[CLOUDIOTMANAGEMENT_IOT_STATUS_PACKET_SIZE_BYTES];
      size_t num_response_bytes = sizeof(response_buffer);
      packet.send_and_recv_sim(sc, response_buffer, num_response_bytes);

      /* Send response to our cloud subsystem. */
      send_to_cloud(response_buffer, num_response_bytes);
    }
    else {
      printf("CloudIOTManagement: Unrecognized TOPIC field (value: %u) for the IoT Modem packet.\n", topic);
      return;
    }
  }
  else if (flow == ModemPacket::Flow::CARRIER_SWITCH) {
    CarrierSwitchPacket::Topic topic = static_cast<CarrierSwitchPacket::Topic>((pdu_buffer[PDU_HEADER_SIZE_BYTES + CarrierSwitchPacket::CARRIERSWITCHPACKET_OFFSET_TOPIC_FIELD] & 0x0F) >> 0);
    if (topic == CarrierSwitchPacket::Topic::PERFORM) {
      /* Confirm we have an expected number of bytes, and gracefully handle if not (return early). */
      if (packet_size != CLOUDIOTMANAGEMENT_CARRIER_SWITCH_PERFORM_PACKET_SIZE_BYTES) {
        printf("CloudIOTManagement: Although the Modem packet's flow and topic field indicated a Carrier Switch Perform packet, the determined packet size in bytes was unexpected (got %lu, but expected %lu).\n", packet_size, CLOUDIOTMANAGEMENT_CARRIER_SWITCH_PERFORM_PACKET_SIZE_BYTES);
        return;
      }

      /* Decode packet, and send to the SIM card (if there was no decoding errors). */
      CarrierSwitchPerformPacket packet;
      if (!decode_carrier_switch_perform(&pdu_buffer[PDU_HEADER_SIZE_BYTES], packet)) {
        printf("CloudIOTManagement: An error occured while decoding the Carrier Switch Perform packet! Dropping packet/avoiding transmission to the SIM card...\n");
        return;
      }

      /* Send packet to SIM card, and buffer the response. */
      uint8_t response_buffer[CLOUDIOTMANAGEMENT_CARRIER_SWITCH_ACK_PACKET_SIZE_BYTES];
      size_t num_response_bytes = sizeof(response_buffer);
      packet.send_and_recv_sim(sc, response_buffer, num_response_bytes);

      /* Send response to our cloud subsystem. */
      send_to_cloud(response_buffer, num_response_bytes);
    }
    else if (topic == CarrierSwitchPacket::Topic::ACK) {
      /* Confirm we have an expected number of bytes, and gracefully handle if not (return early). */
      if (packet_size != CLOUDIOTMANAGEMENT_CARRIER_SWITCH_ACK_PACKET_SIZE_BYTES) {
        printf("CloudIOTManagement: Although the Modem packet's flow and topic field indicated a Carrier Switch ACK packet, the determined packet size in bytes was unexpected (got %lu, but expected %lu).\n", packet_size, CLOUDIOTMANAGEMENT_CARRIER_SWITCH_ACK_PACKET_SIZE_BYTES);
        return;
      }

      /* Decode packet, and send to the SIM card (if there was no decoding errors). */
      CarrierSwitchPerformPacket packet;
      if (!decode_carrier_switch_ack(&pdu_buffer[PDU_HEADER_SIZE_BYTES], packet)) {
        printf("CloudIOTManagement: An error occured while decoding the Carrier Switch ACK packet! Dropping packet/avoiding transmission to the SIM card...\n");
        return;
      }

      /* Send packet to SIM card, and buffer the response. */
      uint8_t response_buffer[CLOUDIOTMANAGEMENT_CARRIER_SWITCH_ACK_PACKET_SIZE_BYTES];
      size_t num_response_bytes = sizeof(response_buffer);
      packet.send_and_recv_sim(sc, response_buffer, num_response_bytes);

      /* Send response to our cloud subsystem. */
      send_to_cloud(response_buffer, num_response_bytes);
    }
    else {
      printf("CloudIOTManagement: Unrecognized TOPIC field (value: %u) for the Carrier Switch Modem packet.\n", topic);
      return;
    }
  }
  else {
    printf("CloudIOTManagement: Unrecognized FLOW field (value: %u) for the Modem packet.\n", flow);
    return;
  }
}

bool CloudIoTManagement::decode_iot_data(const uint8_t *packet_buffer, IoTDataPacket &packet) const {
  assert(packet_buffer != nullptr);

  if (debug) {
    printf("CloudIoTManagement: Decoding IoT Data packet...\n");
  }

  /* Extract relevant fields. */
  ModemPacket::Flow flow = static_cast<ModemPacket::Flow>((packet_buffer[ModemPacket::MODEMPACKET_OFFSET_FLOW_FIELD] & 0xF0) >> 4);
  IoTPacket::Topic topic = static_cast<IoTPacket::Topic>((packet_buffer[IoTPacket::IOTPACKET_OFFSET_TOPIC_FIELD] & 0x0F) >> 0);
  uint32_t device_id = ((static_cast<uint32_t>(packet_buffer[IoTDataPacket::IOTDATAPACKET_OFFSET_DEVICE_ID_FIELD + 0]) << 24) +
                        (static_cast<uint32_t>(packet_buffer[IoTDataPacket::IOTDATAPACKET_OFFSET_DEVICE_ID_FIELD + 1]) << 16) +
                        (static_cast<uint32_t>(packet_buffer[IoTDataPacket::IOTDATAPACKET_OFFSET_DEVICE_ID_FIELD + 2]) << 8) +
                        (static_cast<uint32_t>(packet_buffer[IoTDataPacket::IOTDATAPACKET_OFFSET_DEVICE_ID_FIELD + 3]) << 0));
  Timestamp timestamp = decode_temporenc_timestamp(&packet_buffer[IoTDataPacket::IOTDATAPACKET_OFFSET_TIMESTAMP_FIELD], 8);
  uint8_t data_length = packet_buffer[IoTDataPacket::IOTDATAPACKET_OFFSET_DATA_LENGTH_FIELD];
  const uint8_t *data = &packet_buffer[IoTDataPacket::IOTDATAPACKET_OFFSET_DATA_FIELD];

  /* Sanity check header is correct. */
  if (flow != ModemPacket::Flow::IOT ||
      topic != IoTPacket::Topic::DATA) {
    printf("CloudIoTManagement: Header invalid when attempting to decode IoT Data Packet.\n");
    return false;  // Indicate failed attempt to decode packet.
  }

  /* Set IoTDataPacket members accordingly. */
  packet.device_id = device_id;
  packet.timestamp = timestamp;
  packet.data_length = data_length;
  std::memcpy(packet.data, data, data_length);

  /* Indicate successful attempt to decode packet. */
  return true;
}

bool CloudIoTManagement::decode_iot_status(const uint8_t *packet_buffer, IoTStatusPacket &packet) const {
  assert(packet_buffer != nullptr);

  if (debug) {
    printf("CloudIoTManagement: Decoding IoT Status packet...\n");
  }

  /* Extract relevant fields. */
  ModemPacket::Flow flow = static_cast<ModemPacket::Flow>((packet_buffer[ModemPacket::MODEMPACKET_OFFSET_FLOW_FIELD] & 0xF0) >> 4);
  IoTPacket::Topic topic = static_cast<IoTPacket::Topic>((packet_buffer[IoTPacket::IOTPACKET_OFFSET_TOPIC_FIELD] & 0x0F) >> 0);
  IoTStatusPacket::Status status = static_cast<IoTStatusPacket::Status>((packet_buffer[IoTStatusPacket::IOTSTATUSPACKET_OFFSET_STATUS_FIELD] & 0xF0) >> 4);

  /* Sanity check header is correct. */
  if (flow != ModemPacket::Flow::IOT ||
      topic != IoTPacket::Topic::STATUS) {
    printf("CloudIoTManagement: Header invalid when attempting to decode IoT Status Packet.\n");
    return false;  // Indicate failed attempt to decode packet.
  }

  /* Set IoTStatusPacket members accordingly. */
  packet.status = status;

  /* Indicate successful attempt to decode packet. */
  return true;
}

bool CloudIoTManagement::decode_carrier_switch_perform(const uint8_t *packet_buffer, CarrierSwitchPerformPacket &packet) const {
  assert(packet_buffer != nullptr);

  if (debug) {
    printf("CloudIoTManagement: Decoding Carrier Switch Perform packet...\n");
  }

  /* Extract relevant fields. */
  ModemPacket::Flow flow = static_cast<ModemPacket::Flow>((packet_buffer[ModemPacket::MODEMPACKET_OFFSET_FLOW_FIELD] & 0xF0) >> 4);
  CarrierSwitchPacket::Topic topic = static_cast<CarrierSwitchPacket::Topic>((packet_buffer[CarrierSwitchPacket::CARRIERSWITCHPACKET_OFFSET_TOPIC_FIELD] & 0x0F) >> 0);
  CarrierSwitchPacket::CarrierID carrier_id = static_cast<CarrierSwitchPacket::CarrierID>((packet_buffer[CarrierSwitchPerformPacket::CARRIERSWITCHPERFORMPACKET_OFFSET_CARRIER_ID_FIELD] & 0xF0) >> 4);

  if (debug) {
    printf("CloudIoTManagement: Received Carrier Switch Perform packet with CarrierID of %u.\n", carrier_id);
  }

  /* Sanity check header is correct. */
  if (flow != ModemPacket::Flow::CARRIER_SWITCH ||
      topic != CarrierSwitchPacket::Topic::PERFORM) {
    printf("CloudIoTManagement: Header invalid when attempting to decode Carrier Switch Perform Packet.\n");
    return false;  // Indicate failed attempt to decode packet.
  }

  /* Set CarrierSwitchPerformPacket members accordingly. */
  packet.carrier_id = carrier_id;

  /* Indicate successful attempt to decode packet. */
  return true;
}

bool CloudIoTManagement::decode_carrier_switch_ack(const uint8_t *packet_buffer, CarrierSwitchACKPacket &packet) const {
  assert(packet_buffer != nullptr);

  if (debug) {
    printf("CloudIoTManagement: Decoding Carrier Switch ACK packet...\n");
  }

  /* Extract relevant fields. */
  ModemPacket::Flow flow = static_cast<ModemPacket::Flow>((packet_buffer[ModemPacket::MODEMPACKET_OFFSET_FLOW_FIELD] & 0xF0) >> 4);
  CarrierSwitchPacket::Topic topic = static_cast<CarrierSwitchPacket::Topic>((packet_buffer[CarrierSwitchPacket::CARRIERSWITCHPACKET_OFFSET_TOPIC_FIELD] & 0x0F) >> 0);
  CarrierSwitchACKPacket::Status status = static_cast<CarrierSwitchACKPacket::Status>((packet_buffer[CarrierSwitchACKPacket::CARRIERSWITCHACKPACKET_OFFSET_STATUS_FIELD] & 0xF0) >> 4);
  CarrierSwitchPacket::CarrierID carrier_id = static_cast<CarrierSwitchPacket::CarrierID>((packet_buffer[CarrierSwitchACKPacket::CARRIERSWITCHACKPACKET_OFFSET_CARRIER_ID_FIELD] & 0x0F) >> 4);

  /* Sanity check header is correct. */
  if (flow != ModemPacket::Flow::CARRIER_SWITCH ||
      topic != CarrierSwitchPacket::Topic::ACK) {
    printf("CloudIoTManagement: Header invalid when attempting to decode Carrier Switch ACK Packet.\n");
    return false;  // Indicate failed attempt to decode packet.
  }

  /* Set CarrierSwitchACKPacket members accordingly. */
  packet.status = status;
  packet.carrier_id = carrier_id;

  /* Indicate successful attempt to decode packet. */
  return true;
}

CloudIoTManagement::Timestamp CloudIoTManagement::decode_temporenc_timestamp(const uint8_t *timestamp_buffer, size_t num_bytes) {
  assert(num_bytes == 8);

  /* Timestamp components from the temporenc bytes. */
  uint16_t year = (timestamp_buffer[0] << 8) | timestamp_buffer[1];
  uint8_t month = timestamp_buffer[2];
  uint8_t day = timestamp_buffer[3];
  uint8_t hour = timestamp_buffer[4];
  uint8_t minute = timestamp_buffer[5];
  uint8_t second = timestamp_buffer[6];
  uint16_t millisecond = (timestamp_buffer[7] << 8);

  /* Populate Timestamp's fields accordingly. */
  Timestamp timestamp = {};
  timestamp.year = year;
  timestamp.month = month;
  timestamp.day = day;
  timestamp.hour = hour;
  timestamp.minute = minute;
  timestamp.second = second;
  timestamp.millisecond = millisecond;

  return timestamp;
}

void CloudIoTManagement::encode_temporenc_timestamp(const CloudIoTManagement::Timestamp &timestamp, uint8_t *timestamp_buffer, size_t num_bytes) {
  assert(num_bytes == 8);

  /* Encode Timestamp components into a temporenc-formatted byte sequence. */
  timestamp_buffer[0] = static_cast<uint8_t>((timestamp.year & 0xFF00) >> 8);
  timestamp_buffer[1] = static_cast<uint8_t>(timestamp.year & 0x00FF);
  timestamp_buffer[2] = timestamp.month;
  timestamp_buffer[3] = timestamp.day;
  timestamp_buffer[4] = timestamp.hour;
  timestamp_buffer[5] = timestamp.minute;
  timestamp_buffer[6] = timestamp.second;
  timestamp_buffer[7] = static_cast<uint8_t>((timestamp.millisecond & 0xFF00) >> 8);
}

void CloudIoTManagement::print_pdu(const uint8_t *pdu_buffer, size_t num_bytes) {
  assert(num_bytes >= PDU_HEADER_SIZE_BYTES);
  printf("=======================================\n");
  printf("Version, IHL: %u\n", pdu_buffer[0]);
  printf("TOS: %u\n", pdu_buffer[1]);
  printf("Total Length: %u\n", (pdu_buffer[2] << 8) +
                                (pdu_buffer[3] << 0));
  printf("ID: %u\n", (pdu_buffer[4] << 8) +
                      (pdu_buffer[5] << 0));
  printf("Fragment Offset: %u\n", (pdu_buffer[6] << 8) +
                                  (pdu_buffer[7] << 0));
  printf("TTL: %u\n", pdu_buffer[8]);
  printf("Protocol: %u\n", pdu_buffer[9]);
  printf("Header Checksum: %u\n", (pdu_buffer[10] << 8) +
                                  (pdu_buffer[11] << 0));
  printf("Source IP address: %u.%u.%u.%u\n", pdu_buffer[12], pdu_buffer[13], pdu_buffer[14], pdu_buffer[15]);
  printf("Destination IP address: %u.%u.%u.%u\n", pdu_buffer[16], pdu_buffer[17], pdu_buffer[18], pdu_buffer[19]);
  printf("Source Port: %u\n", (pdu_buffer[20] << 8) +
                              (pdu_buffer[21] << 0));
  printf("Destination Port: %u\n", (pdu_buffer[22] << 8) +
                                    (pdu_buffer[23] << 0));
  printf("UDP Length: %u\n", (pdu_buffer[24] << 8) +
                              (pdu_buffer[25] << 0));
  printf("UDP Checksum: %u\n", (pdu_buffer[26] << 8) +
                                (pdu_buffer[27] << 0));
  printf("Payload: ");
  for (size_t i = 28; i < num_bytes; i++)
    printf("%u ", pdu_buffer[i]);
  printf("\n");
  printf("=======================================\n");
}

long CloudIoTManagement::send_to_cloud(const uint8_t *bytes_buffer, size_t num_bytes) {
  ssize_t bytes_sent = sendto(uplink_socket_fd, bytes_buffer, num_bytes, 0, (const struct sockaddr*)&uplink_server_addr, sizeof(uplink_server_addr));
  if (bytes_sent < 0) {
    printf("CloudIoTManagement ERROR: Error while sending message to cloud subsystem: \"%s\" Dropping packet...\n", strerror(errno));
    return SRSRAN_ERROR;
  }

  printf("CloudIoTManagement INFO: Successfully sent %lu bytes to the server at (%s, %u)\n", static_cast<size_t>(bytes_sent), CLOUDIOTMANAGEMENT_SERVER_IP_ADDRESS, CLOUDIOTMANAGEMENT_SERVER_PORT_NUMBER);

  return SRSRAN_SUCCESS;
}

/*****************************************************************************
 * CloudIoTManagement - IoTDataPacket Class Definition
 *****************************************************************************/

void CloudIoTManagement::IoTDataPacket::serialize_packet(uint8_t *serialized_buffer, size_t &buffer_length) const {
  assert(buffer_length >= CLOUDIOTMANAGEMENT_IOT_DATA_PACKET_SIZE_BYTES_MAXIMUM);

  /* Flow/Topic */
  serialized_buffer[0] = static_cast<uint8_t>(flow)   << 4 |
                         static_cast<uint8_t>(topic)  << 0;
  /* Device ID */
  serialized_buffer[1] = static_cast<uint8_t>(device_id & 0xFF000000);
  serialized_buffer[2] = static_cast<uint8_t>(device_id & 0x00FF0000);
  serialized_buffer[3] = static_cast<uint8_t>(device_id & 0x0000FF00);
  serialized_buffer[4] = static_cast<uint8_t>(device_id & 0x000000FF);
  /* Timestamp */
  encode_temporenc_timestamp(timestamp, &serialized_buffer[5], 8);
  /* Data Length */
  serialized_buffer[13] = data_length;
  /* Data */
  memcpy(&serialized_buffer[14], data, data_length);

  buffer_length = CLOUDIOTMANAGEMENT_IOT_DATA_PACKET_SIZE_BYTES_MINIMUM + data_length;
}

size_t CloudIoTManagement::IoTDataPacket::get_max_serialized_length() const {
  return CLOUDIOTMANAGEMENT_IOT_DATA_PACKET_SIZE_BYTES_MAXIMUM;
}

long CloudIoTManagement::IoTDataPacket::send_and_recv_sim(CloudIoTManagement::scard &sc, uint8_t *response_buffer, size_t &buffer_length) {
  assert(buffer_length >= CLOUDIOTMANAGEMENT_IOT_DATA_PACKET_SIZE_BYTES_MAXIMUM);
  
  (void) sc;

  long ret = SRSRAN_SUCCESS;

  printf("CloudIoTManagement: `send_and_recv_sim` is not yet supported for IoT Data packets. Bypass sending to SIM, and setting response equal to input...");
  serialize_packet(response_buffer, buffer_length);

  return ret;
}

/*****************************************************************************
 * CloudIoTManagement - IoTStatusPacket Class Definition
 *****************************************************************************/

void CloudIoTManagement::IoTStatusPacket::serialize_packet(uint8_t *serialized_buffer, size_t &buffer_length) const {
  assert(buffer_length >= CLOUDIOTMANAGEMENT_IOT_STATUS_PACKET_SIZE_BYTES);

  /* Flow/Topic */
  serialized_buffer[0] = static_cast<uint8_t>(flow)   << 4 |
                         static_cast<uint8_t>(topic)  << 0;
  /* Status */
  serialized_buffer[1] = static_cast<uint8_t>(status) << 4;

  buffer_length = CLOUDIOTMANAGEMENT_IOT_STATUS_PACKET_SIZE_BYTES;
}

size_t CloudIoTManagement::IoTStatusPacket::get_max_serialized_length() const {
  return CLOUDIOTMANAGEMENT_IOT_STATUS_PACKET_SIZE_BYTES;
}

long CloudIoTManagement::IoTStatusPacket::send_and_recv_sim(CloudIoTManagement::scard &sc, uint8_t *response_buffer, size_t &buffer_length) {
  assert(buffer_length >= CLOUDIOTMANAGEMENT_IOT_STATUS_PACKET_SIZE_BYTES);

  (void) sc;

  printf("CloudIoTManagement: `send_and_recv_sim` is not yet supported for IoT Status packets. Bypass sending to SIM, and setting response equal to input...");
  serialize_packet(response_buffer, buffer_length);

  return SRSRAN_SUCCESS;
}

/*****************************************************************************
 * CloudIoTManagement - CarrierSwitchPerformPacket Class Definition
 *****************************************************************************/

void CloudIoTManagement::CarrierSwitchPerformPacket::serialize_packet(uint8_t *serialized_buffer, size_t &buffer_length) const {
  assert(buffer_length >= CLOUDIOTMANAGEMENT_CARRIER_SWITCH_PERFORM_PACKET_SIZE_BYTES);

  /* Flow/Topic */
  serialized_buffer[0] = static_cast<uint8_t>(flow)   << 4 |
                         static_cast<uint8_t>(topic)  << 0;
  /* Carrier ID */
  serialized_buffer[1] = static_cast<uint8_t>(carrier_id) << 4;

  buffer_length = CLOUDIOTMANAGEMENT_CARRIER_SWITCH_PERFORM_PACKET_SIZE_BYTES;
}

size_t CloudIoTManagement::CarrierSwitchPerformPacket::get_max_serialized_length() const {
  return CLOUDIOTMANAGEMENT_CARRIER_SWITCH_PERFORM_PACKET_SIZE_BYTES;
}

long CloudIoTManagement::CarrierSwitchPerformPacket::send_and_recv_sim(CloudIoTManagement::scard &sc, uint8_t *response_buffer, size_t &buffer_length) {
  assert(buffer_length >= CLOUDIOTMANAGEMENT_CARRIER_SWITCH_PERFORM_PACKET_SIZE_BYTES);

  long ret;

  /* Serialize the packet. */
  uint8_t serialized_buffer[CLOUDIOTMANAGEMENT_CARRIER_SWITCH_PERFORM_PACKET_SIZE_BYTES];
  size_t num_serialized_bytes = CLOUDIOTMANAGEMENT_CARRIER_SWITCH_PERFORM_PACKET_SIZE_BYTES;
  serialize_packet(serialized_buffer, num_serialized_bytes);

  /* Construct TERMINAL_RESPONSE command, and all of the input args to the transmit method. */
  uint8_t cmd[50] = {/* APDU Header */ SIM_CMD_TERMINAL_RESPONSE,
                     /* Payload (Modem Packet) Length */ static_cast<uint8_t>(num_serialized_bytes)};
  memcpy(&cmd[6], serialized_buffer, num_serialized_bytes);  // sizeof(SIM_CMD_TERMINAL_RESPONSE) + 2
  size_t  cmdlen = 5 + num_serialized_bytes;  // sizeof(SIM_CMD_TERMINAL_RESPONSE) + 1
  uint8_t resp[3]; /* 1-byte Length, 2-byte APDU Footer */
  size_t resp_len = sizeof(resp);

  /* Perform transmit for TERMINAL_RESPONSE command. */
  ret = sc.transmit(cmd, cmdlen, resp, &resp_len);
  if (ret != SCARD_S_SUCCESS) {
    printf("CloudIoTManagement SCARD ERROR: SCARD: SCardTransmit for TERMINAL_RESPONSE command failed %s\n", pcsc_stringify_error(ret));
    return -1;
  }

  /* Construct CS_RESPONSE command, and all of the input args to the transmit method. */
  uint8_t get_ack_cmd[50] = {/* APDU Header */ SIM_CMD_CS_RESPONSE,
                             /* Carrier Switch ACK */ 0x11};
  size_t  get_ack_cmdlen = 5;  // sizeof(SIM_CMD_CS_RESPONSE) + 1
  uint8_t get_ack_resp[17 + CLOUDIOTMANAGEMENT_CARRIER_SWITCH_ACK_PACKET_SIZE_BYTES];  // R-APDU Header (14), Length (1), CarrierSwitchACK Payload (CLOUDIOTMANAGEMENT_CARRIER_SWITCH_ACK_PACKET_SIZE_BYTES), APDU Footer (2)
  size_t get_ack_resp_len = sizeof(resp);

  /* Perform transmit for CS_RESPONSE command. */
  ret = sc.transmit(get_ack_cmd, get_ack_cmdlen, get_ack_resp, &get_ack_resp_len);
  if (ret != SCARD_S_SUCCESS) {
    printf("CloudIoTManagement SCARD ERROR: SCARD: SCardTransmit for CS_RESPONSE command failed %s\n", pcsc_stringify_error(ret));
    return -1;
  }

  /* Copy response data (CarrierSwitchACK packet) to caller's buffer. */
  memcpy(response_buffer, &get_ack_resp[15], CLOUDIOTMANAGEMENT_CARRIER_SWITCH_ACK_PACKET_SIZE_BYTES);

  buffer_length = CLOUDIOTMANAGEMENT_CARRIER_SWITCH_ACK_PACKET_SIZE_BYTES;

  return SRSRAN_SUCCESS;
}

/*****************************************************************************
 * CloudIoTManagement - CarrierSwitchACKPacket Class Definition
 *****************************************************************************/

void CloudIoTManagement::CarrierSwitchACKPacket::serialize_packet(uint8_t *serialized_buffer, size_t &buffer_length) const {
  assert(buffer_length >= CLOUDIOTMANAGEMENT_CARRIER_SWITCH_ACK_PACKET_SIZE_BYTES);

  /* Flow/Topic */
  serialized_buffer[0] = static_cast<uint8_t>(flow)   << 4 |
                         static_cast<uint8_t>(topic)  << 0;
  /* Carrier ID */
  serialized_buffer[1] = static_cast<uint8_t>(status)     << 4 |
                         static_cast<uint8_t>(carrier_id) << 0;

  buffer_length = CLOUDIOTMANAGEMENT_CARRIER_SWITCH_ACK_PACKET_SIZE_BYTES;
}

size_t CloudIoTManagement::CarrierSwitchACKPacket::get_max_serialized_length() const {
  return CLOUDIOTMANAGEMENT_CARRIER_SWITCH_ACK_PACKET_SIZE_BYTES;
}

long CloudIoTManagement::CarrierSwitchACKPacket::send_and_recv_sim(CloudIoTManagement::scard &sc, uint8_t *response_buffer, size_t &buffer_length) {
  assert(buffer_length >= CLOUDIOTMANAGEMENT_CARRIER_SWITCH_ACK_PACKET_SIZE_BYTES);

  (void) sc;

  printf("CloudIoTManagement: `send_and_recv_sim` is not yet supported for Carrier Switch ACK packets. Bypass sending to SIM, and setting response equal to input...");
  serialize_packet(response_buffer, buffer_length);

  return SRSRAN_SUCCESS;
}

/*****************************************************************************
 * CloudIoTManagement - scard Class Definition
 *****************************************************************************/

// return 0 if initialization was successfull, -1 otherwies
int CloudIoTManagement::scard::init()
{
  int  ret_value    = SRSRAN_ERROR;
  uint pos          = 0; // SC reader
  bool reader_found = false;
  size_t blen;

  long ret;
  ret = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &scard_context);
  if (ret != SCARD_S_SUCCESS) {
    printf("CloudIoTManagement SCARD ERROR: SCardEstablishContext(): %s\n", pcsc_stringify_error(ret));
    return ret_value;
  }

  unsigned long len = 0;
  ret               = SCardListReaders(scard_context, NULL, NULL, &len);
  if (ret != SCARD_S_SUCCESS) {
    printf("CloudIoTManagement SCARD ERROR: SCardListReaders(): %s\n", pcsc_stringify_error(ret));
    return ret_value;
  }

  char* readers = (char*)malloc(len);
  if (readers == NULL) {
    printf("CloudIoTManagement SCARD ERROR: Malloc failed\n");
    return ret_value;
  }

  ret = SCardListReaders(scard_context, NULL, readers, &len);
  if (ret != SCARD_S_SUCCESS) {
    printf("CloudIoTManagement SCARD ERROR: SCardListReaders() 2: %s\n", pcsc_stringify_error(ret));
    goto clean_exit;
  }
  if (len < 3) {
    printf("CloudIoTManagement SCARD INFO: No smart card readers available.\n");
    return ret_value;
  }

  /* readers: NULL-separated list of reader names, and terminating NULL */
  pos = 0;
  while (pos < len - 1) {
    printf("CloudIoTManagement SCARD INFO: Available Card Reader: %s\n", &readers[pos]);
    while (readers[pos] != '\0' && pos < len) {
      pos++;
    }
    pos++; // skip separator
  }

  reader_found = false;
  pos          = 0;

  // If no reader specified, test all available readers for SIM cards. Otherwise consider specified reader only.
  while (pos < len && !reader_found) {
    printf("CloudIoTManagement SCARD INFO: Trying Card Reader: %s\n", &readers[pos]);
    // Connect to card
    ret = SCardConnect(scard_context,
                        &readers[pos],
                        SCARD_SHARE_SHARED,
                        SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1,
                        &scard_handle,
                        &scard_protocol);
    if (ret == SCARD_S_SUCCESS) {
      reader_found = true;
    } else {
      if (ret == (long)SCARD_E_NO_SMARTCARD) {
        printf("CloudIoTManagement SCARD ERROR: No smart card inserted.\n");
      } else {
        printf("CloudIoTManagement SCARD ERROR: %s\n", pcsc_stringify_error(ret));
      }
      printf("CloudIoTManagement SCARD INFO: Failed to use Card Reader: %s\n", &readers[pos]);

      // proceed to next reader
      while (pos < len && readers[pos] != '\0') {
        pos++;
      }
      pos++; // skip separator
    }
  }

  free(readers);
  readers = NULL;

  printf("CloudIoTManagement SCARD INFO: Card=0x%x active_protocol=%lu (%s)\n",
              (unsigned int)scard_handle,
              (unsigned long)scard_protocol,
              scard_protocol == SCARD_PROTOCOL_T0 ? "T0" : "T1");

  ret = SCardBeginTransaction(scard_handle);
  if (ret != SCARD_S_SUCCESS) {
    printf("CloudIoTManagement SCARD ERROR: %s\n", pcsc_stringify_error(ret));
    goto clean_exit;
  }

  ret = SCardEndTransaction(scard_handle, SCARD_LEAVE_CARD);
  if (ret != SCARD_S_SUCCESS) {
    if (debug) {
      printf("CloudIoTManagement SCARD DEBUG: SCARD: Could not end transaction: 0x%x\n", (unsigned int)ret);
    }
    goto clean_exit;
  }

  ret_value = SRSRAN_SUCCESS;

clean_exit:
  if (readers) {
    free(readers);
  }

  return ret_value;
}

long CloudIoTManagement::scard::transmit(unsigned char* _send, size_t send_len, unsigned char* _recv, size_t* recv_len)
{
  long          ret;
  unsigned long rlen;

  if (debug) {
    printf("CloudIoTManagement SCARD DEBUG: SCARD: scard_transmit: send, %lu bytes\n", send_len);
  }

  rlen      = *recv_len;
  ret       = SCardTransmit(scard_handle,
                      scard_protocol == SCARD_PROTOCOL_T1 ? SCARD_PCI_T1 : SCARD_PCI_T0,
                      _send,
                      (unsigned long)send_len,
                      NULL,
                      _recv,
                      &rlen);
  *recv_len = rlen;
  if (ret == SCARD_S_SUCCESS) {
    if (debug) {
      printf("CloudIoTManagement SCARD DEBUG: SCARD: scard_transmit: recv, %lu bytes\n", rlen);
    }
  } else {
    printf("CloudIoTManagement SCARD ERROR: SCARD: SCardTransmit failed %s\n", pcsc_stringify_error(ret));
  }

  if (debug) {
    printf("CloudIoTManagement SCARD DEBUG: Received %lu bytes: ", rlen);
    for (size_t i = 0; i < rlen; i++) {
      printf("%u ", _recv[i]);
    }
    printf("\n");
  }

  return ret;
}

void CloudIoTManagement::scard::deinit()
{
  long ret;

  if (debug) {
    printf("CloudIoTManagement SCARD DEBUG: SCARD: deinitializing smart card interface\n");
  }

  ret = SCardDisconnect(scard_handle, SCARD_UNPOWER_CARD);
  if (ret != SCARD_S_SUCCESS) {
    printf("CloudIoTManagement SCARD ERROR: SCARD: Failed to disconnect smart card (err=%ld)\n", ret);
  }

  ret = SCardReleaseContext(scard_context);
  if (ret != SCARD_S_SUCCESS) {
    printf("CloudIoTManagement SCARD ERROR: Failed to release smart card context (err=%ld)\n", ret);
  }
}

} // namespace srsue
