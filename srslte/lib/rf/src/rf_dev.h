/**
 *
 * \section COPYRIGHT
 *
 * Copyright 2013-2015 Software Radio Systems Limited
 *
 * \section LICENSE
 *
 * This file is part of the srsLTE library.
 *
 * srsLTE is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * srsLTE is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * A copy of the GNU Affero General Public License can be found in
 * the LICENSE file in the top-level directory of this distribution
 * and at http://www.gnu.org/licenses/.
 *
 */


/* RF frontend API */
typedef struct {
  const char *name;
  bool   (*srslte_rf_rx_wait_lo_locked) (void*);
  int    (*srslte_rf_start_rx_stream)(void *h);
  int    (*srslte_rf_stop_rx_stream)(void *h);
  void   (*srslte_rf_flush_buffer)(void *h);
  bool   (*srslte_rf_has_rssi)(void *h);
  float  (*srslte_rf_get_rssi)(void *h);
  void   (*srslte_rf_suppress_stdout)(void *h);
  void   (*srslte_rf_register_msg_handler)(void *h, srslte_rf_msg_handler_t msg_handler);
  int    (*srslte_rf_open)(char *args, void **h);
  int    (*srslte_rf_close)(void *h);
  void   (*srslte_rf_set_master_clock_rate)(void *h, double rate);
  bool   (*srslte_rf_is_master_clock_dynamic)(void *h);
  double (*srslte_rf_set_rx_srate)(void *h, double freq);
  double (*srslte_rf_set_rx_gain)(void *h, double gain);
  double (*srslte_rf_set_tx_gain)(void *h, double gain);
  double (*srslte_rf_get_rx_gain)(void *h);
  double (*srslte_rf_get_tx_gain)(void *h);
  double (*srslte_rf_set_rx_freq)(void *h, double freq);  
  double (*srslte_rf_set_tx_srate)(void *h, double freq);
  double (*srslte_rf_set_tx_freq)(void *h, double freq);
  void   (*srslte_rf_get_time)(void *h, time_t *secs, double *frac_secs);  
  int    (*srslte_rf_recv_with_time)(void *h, void *data, uint32_t nsamples, 
                           bool blocking, time_t *secs,double *frac_secs);
  int    (*srslte_rf_send_timed)(void *h, void *data, int nsamples,
                     time_t secs, double frac_secs, bool has_time_spec,
                     bool blocking, bool is_start_of_burst, bool is_end_of_burst);
} rf_dev_t; 

/* Define implementation for UHD */
#ifdef ENABLE_UHD

#include "rf_uhd_imp.h"

static rf_dev_t dev_uhd = {
  "UHD", 
  rf_uhd_rx_wait_lo_locked,
  rf_uhd_start_rx_stream,
  rf_uhd_stop_rx_stream,
  rf_uhd_flush_buffer,
  rf_uhd_has_rssi,
  rf_uhd_get_rssi,
  rf_uhd_suppress_stdout,
  rf_uhd_register_msg_handler,
  rf_uhd_open,
  rf_uhd_close,
  rf_uhd_set_master_clock_rate,
  rf_uhd_is_master_clock_dynamic,
  rf_uhd_set_rx_srate,
  rf_uhd_set_rx_gain,
  rf_uhd_set_tx_gain,
  rf_uhd_get_rx_gain,
  rf_uhd_get_tx_gain,
  rf_uhd_set_rx_freq, 
  rf_uhd_set_tx_srate,
  rf_uhd_set_tx_freq,
  rf_uhd_get_time,  
  rf_uhd_recv_with_time,
  rf_uhd_send_timed
};
#endif

/* Define implementation for bladeRF */
#ifdef ENABLE_BLADERF

#include "rf_blade_imp.h"

static rf_dev_t dev_blade = {
  "bladeRF", 
  rf_blade_rx_wait_lo_locked,
  rf_blade_start_rx_stream,
  rf_blade_stop_rx_stream,
  rf_blade_flush_buffer,
  rf_blade_has_rssi,
  rf_blade_get_rssi,
  rf_blade_suppress_stdout,
  rf_blade_register_msg_handler,
  rf_blade_open,
  rf_blade_close,
  rf_blade_set_master_clock_rate,
  rf_blade_is_master_clock_dynamic,
  rf_blade_set_rx_srate,
  rf_blade_set_rx_gain,
  rf_blade_set_tx_gain,
  rf_blade_get_rx_gain,
  rf_blade_get_tx_gain,
  rf_blade_set_rx_freq, 
  rf_blade_set_tx_srate,
  rf_blade_set_tx_freq,
  rf_blade_get_time,  
  rf_blade_recv_with_time,
  rf_blade_send_timed
};
#endif

static rf_dev_t *available_devices[] = {
#ifdef ENABLE_UHD
  &dev_uhd, 
#endif
#ifdef ENABLE_BLADERF
  &dev_blade,
#endif
  NULL
};
