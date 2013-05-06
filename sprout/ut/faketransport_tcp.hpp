/**
 * @file sip_transport_fake.h
 *
 * Copyright (C) 2013  Metaswitch Networks Ltd
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * The author can be reached by email at clearwater@metaswitch.com or by post at
 * Metaswitch Networks Ltd, 100 Church St, Enfield EN2 6BQ, UK
 */

#ifndef __PJSIP_TRANSPORT_FAKE_TCP_H__
#define __PJSIP_TRANSPORT_FAKE_TCP_H__

#include <pjsip/sip_transport.h>
#include <pj/sock_qos.h>

PJ_BEGIN_DECL

/**
 * @defgroup PJSIP_TRANSPORT_FAKE_TCP FAKE_TCP Transport
 * @ingroup PJSIP_TRANSPORT
 * @brief API to create and register FAKE_TCP transport.
 * @{
 * The functions below are used to create FAKE_TCP transport and register
 * the transport to the framework.
 */

/**
 * Settings to be specified when creating the FAKE_TCP transport. Application
 * should initialize this structure with its default values by calling
 * pjsip_fake_tcp_transport_cfg_default().
 */
typedef struct pjsip_fake_tcp_transport_cfg
{
    /**
     * Address family to use. Valid values are pj_AF_INET() and
     * pj_AF_INET6(). Default is pj_AF_INET().
     */
    int			af;

    /**
     * Optional address to bind the socket to. Default is to bind to
     * PJ_INADDR_ANY and to any available port.
     */
    pj_sockaddr		bind_addr;

    /**
     * Optional published address, which is the address to be
     * advertised as the address of this SIP transport.
     * By default the bound address will be used as the published address.
     */
    pjsip_host_port	addr_name;

    /**
     * Number of simultaneous asynchronous accept() operations to be
     * supported. It is recommended that the number here corresponds to
     * the number of processors in the system (or the number of SIP
     * worker threads).
     *
     * Default: 1
     */
    unsigned	       async_cnt;

    /**
     * QoS traffic type to be set on this transport. When application wants
     * to apply QoS tagging to the transport, it's preferable to set this
     * field rather than \a qos_param fields since this is more portable.
     *
     * Default is QoS not set.
     */
    pj_qos_type		qos_type;

    /**
     * Set the low level QoS parameters to the transport. This is a lower
     * level operation than setting the \a qos_type field and may not be
     * supported on all platforms.
     *
     * Default is QoS not set.
     */
    pj_qos_params	qos_params;

} pjsip_fake_tcp_transport_cfg;


/**
 * Initialize pjsip_fake_tcp_transport_cfg structure with default values for
 * the specifed address family.
 *
 * @param cfg		The structure to initialize.
 * @param af		Address family to be used.
 */
PJ_DECL(void) pjsip_fake_tcp_transport_cfg_default(pjsip_fake_tcp_transport_cfg *cfg,
					      int af);

/**
 * Another variant of #pjsip_fake_tcp_transport_start().
 *
 * @param endpt		The SIP endpoint.
 * @param cfg		FAKE_TCP transport settings. Application should initialize
 *			this setting with #pjsip_fake_tcp_transport_cfg_default().
 * @param p_factory	Optional pointer to receive the instance of the
 *			SIP FAKE_TCP transport factory just created.
 *
 * @return		PJ_SUCCESS when the transport has been successfully
 *			started and registered to transport manager, or
 *			the appropriate error code.
 */
PJ_DECL(pj_status_t) pjsip_fake_tcp_transport_start3(
					pjsip_endpoint *endpt,
					const pjsip_fake_tcp_transport_cfg *cfg,
					pjsip_tpfactory **p_factory
					);


/**
 * Shut down connection (driven by connection error or EOF).
 *
 */
void fake_tcp_init_shutdown(struct fake_tcp_transport *fake_tcp, pj_status_t status);

PJ_END_DECL

/**
 * @}
 */

#endif	/* __PJSIP_TRANSPORT_FAKE_TCP_H__ */
