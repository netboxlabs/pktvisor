/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

#include <pcapplusplus/DnsLayerEnums.h>

namespace visor::lib::dns {

// DNS record types
using pcpp::DnsType;
using pcpp::DNS_TYPE_A;
using pcpp::DNS_TYPE_NS;
using pcpp::DNS_TYPE_MD;
using pcpp::DNS_TYPE_MF;
using pcpp::DNS_TYPE_CNAME;
using pcpp::DNS_TYPE_SOA;
using pcpp::DNS_TYPE_MB;
using pcpp::DNS_TYPE_MG;
using pcpp::DNS_TYPE_MR;
using pcpp::DNS_TYPE_NULL_R;
using pcpp::DNS_TYPE_WKS;
using pcpp::DNS_TYPE_PTR;
using pcpp::DNS_TYPE_HINFO;
using pcpp::DNS_TYPE_MINFO;
using pcpp::DNS_TYPE_MX;
using pcpp::DNS_TYPE_TXT;
using pcpp::DNS_TYPE_RP;
using pcpp::DNS_TYPE_AFSDB;
using pcpp::DNS_TYPE_X25;
using pcpp::DNS_TYPE_ISDN;
using pcpp::DNS_TYPE_RT;
using pcpp::DNS_TYPE_NSAP;
using pcpp::DNS_TYPE_NSAP_PTR;
using pcpp::DNS_TYPE_SIG;
using pcpp::DNS_TYPE_KEY;
using pcpp::DNS_TYPE_PX;
using pcpp::DNS_TYPE_GPOS;
using pcpp::DNS_TYPE_AAAA;
using pcpp::DNS_TYPE_LOC;
using pcpp::DNS_TYPE_NXT;
using pcpp::DNS_TYPE_EID;
using pcpp::DNS_TYPE_NIMLOC;
using pcpp::DNS_TYPE_SRV;
using pcpp::DNS_TYPE_ATMA;
using pcpp::DNS_TYPE_NAPTR;
using pcpp::DNS_TYPE_KX;
using pcpp::DNS_TYPE_CERT;
using pcpp::DNS_TYPE_A6;
using pcpp::DNS_TYPE_DNAM;
using pcpp::DNS_TYPE_SINK;
using pcpp::DNS_TYPE_OPT;
using pcpp::DNS_TYPE_APL;
using pcpp::DNS_TYPE_DS;
using pcpp::DNS_TYPE_SSHFP;
using pcpp::DNS_TYPE_IPSECKEY;
using pcpp::DNS_TYPE_RRSIG;
using pcpp::DNS_TYPE_NSEC;
using pcpp::DNS_TYPE_DNSKEY;
using pcpp::DNS_TYPE_DHCID;
using pcpp::DNS_TYPE_NSEC3;
using pcpp::DNS_TYPE_NSEC3PARAM;
using pcpp::DNS_TYPE_ALL;

// DNS classes
using pcpp::DnsClass;
using pcpp::DNS_CLASS_IN;
using pcpp::DNS_CLASS_IN_QU;
using pcpp::DNS_CLASS_CH;
using pcpp::DNS_CLASS_HS;
using pcpp::DNS_CLASS_ANY;

// DNS resource record types
using pcpp::DnsResourceType;
using pcpp::DnsQueryType;
using pcpp::DnsAnswerType;
using pcpp::DnsAuthorityType;
using pcpp::DnsAdditionalType;

} // namespace visor::lib::dns
