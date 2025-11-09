#include "vpnip.h"
#include "common/io/io.h"
#include "common/netif/netif.h"
#include "util/stringUtils.h"
#include "util/debug.h"

#include <string.h>
#include <ctype.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>

const char* ffDetectVpnIps(const FFVpnIpOptions* options, FFlist* results)
{
    struct ifaddrs* ifAddrStruct = NULL;
    if(getifaddrs(&ifAddrStruct) < 0)
        return "getifaddrs(&ifAddrStruct) failed";

    for (struct ifaddrs* ifa = ifAddrStruct; ifa; ifa = ifa->ifa_next)
    {
        if (!ifa->ifa_addr)
            continue;

        if (strcmp(ifa->ifa_name, "tun0") != 0)
            continue;

        if (ifa->ifa_addr->sa_family == AF_INET)
        {
            if (options->showType & FF_VPNIP_TYPE_IPV4_BIT)
            {
                FFVpnIpResult* item = (FFVpnIpResult*) ffListAdd(results);
                ffStrbufInitS(&item->name, ifa->ifa_name);
                ffStrbufInit(&item->ipv4);
                ffStrbufInit(&item->ipv6);

                struct sockaddr_in* ipv4 = (struct sockaddr_in*) ifa->ifa_addr;
                char addressBuffer[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &ipv4->sin_addr, addressBuffer, INET_ADDRSTRLEN);
                ffStrbufAppendS(&item->ipv4, addressBuffer);
            }
        }
        else if (ifa->ifa_addr->sa_family == AF_INET6)
        {
            if (options->showType & FF_VPNIP_TYPE_IPV6_BIT)
            {
                FFVpnIpResult* item = (FFVpnIpResult*) ffListAdd(results);
                ffStrbufInitS(&item->name, ifa->ifa_name);
                ffStrbufInit(&item->ipv4);
                ffStrbufInit(&item->ipv6);

                struct sockaddr_in6* ipv6 = (struct sockaddr_in6*) ifa->ifa_addr;
                char addressBuffer[INET6_ADDRSTRLEN];
                inet_ntop(AF_INET6, &ipv6->sin6_addr, addressBuffer, INET6_ADDRSTRLEN);
                ffStrbufAppendS(&item->ipv6, addressBuffer);
            }
        }
    }

    if (ifAddrStruct)
        freeifaddrs(ifAddrStruct);

    return NULL;
}