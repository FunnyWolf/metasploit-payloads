#include "precomp.h"
#include "common_metapi.h"

DWORD add_remove_route(Packet *request, BOOLEAN add);

/*
 * Returns zero or more routes to the requestor from the active routing table
 */
DWORD request_net_config_get_routes(Remote *remote, Packet *packet)
{
	Packet *response = met_api->packet.create_response(packet);
	DWORD result = ERROR_SUCCESS;
	DWORD index;
	DWORD metric_bigendian;

	PMIB_IPFORWARDTABLE table_ipv4 = NULL;
	PMIB_IPFORWARDTABLE table_ipv6 = NULL;
	DWORD tableSize = sizeof(MIB_IPFORWARDROW) * 96;
	char int_name[20];

	do
	{
		// Allocate storage for the routing table
		if (!(table_ipv4 = (PMIB_IPFORWARDTABLE)malloc(tableSize)))
		{
			result = ERROR_NOT_ENOUGH_MEMORY;
			break;
		}

		// Get the routing table
		if (GetIpForwardTable(table_ipv4, &tableSize, TRUE) != NO_ERROR)
		{
			result = GetLastError();
			break;
		}

		// Enumerate it
		for (index = 0;
		     index < table_ipv4->dwNumEntries;
		     index++)
		{
			Tlv route[5];
			memset(int_name, 0, 20);

			route[0].header.type   = TLV_TYPE_SUBNET;
			route[0].header.length = sizeof(DWORD);
			route[0].buffer        = (PUCHAR)&table_ipv4->table[index].dwForwardDest;
			route[1].header.type   = TLV_TYPE_NETMASK;
			route[1].header.length = sizeof(DWORD);
			route[1].buffer        = (PUCHAR)&table_ipv4->table[index].dwForwardMask;
			route[2].header.type   = TLV_TYPE_GATEWAY;
			route[2].header.length = sizeof(DWORD);
			route[2].buffer        = (PUCHAR)&table_ipv4->table[index].dwForwardNextHop;

			// we just get the interface index, not the name, because names can be __long__
            _itoa(table_ipv4->table[index].dwForwardIfIndex, int_name, 10);
    		route[3].header.type   = TLV_TYPE_STRING;
			route[3].header.length = (DWORD)strlen(int_name)+1;
			route[3].buffer        = (PUCHAR)int_name;

			metric_bigendian = htonl(table_ipv4->table[index].dwForwardMetric1);
			route[4].header.type   = TLV_TYPE_ROUTE_METRIC;
			route[4].header.length = sizeof(DWORD);
			route[4].buffer        = (PUCHAR)&metric_bigendian;

			met_api->packet.add_tlv_group(response, TLV_TYPE_NETWORK_ROUTE,
					route, 5);
		}

	} while (0);

	if(table_ipv4)
		free(table_ipv4);
	if(table_ipv6)
		free(table_ipv6);

	met_api->packet.transmit_response(result, remote, response);

	return ERROR_SUCCESS;
}

/*
 * Adds a route to the routing table
 */
DWORD request_net_config_add_route(Remote *remote, Packet *packet)
{
	Packet *response = met_api->packet.create_response(packet);
	DWORD result = ERROR_SUCCESS;

	result = add_remove_route(packet, TRUE);

	// Transmit the response packet
	met_api->packet.transmit_response(result, remote, response);

	return ERROR_SUCCESS;
}

/*
 * Removes a route from the routing table
 */
DWORD request_net_config_remove_route(Remote *remote, Packet *packet)
{
	Packet *response = met_api->packet.create_response(packet);
	DWORD result;

	result = add_remove_route(packet, FALSE);

	// Transmit the response packet
	met_api->packet.transmit_response(result, remote, response);

	return ERROR_SUCCESS;
}

/*
 * Adds or removes a route from the supplied request
 */
DWORD add_remove_route(Packet *packet, BOOLEAN add)
{
	MIB_IPFORWARDROW route;
	DWORD (WINAPI *LocalGetBestInterface)(IPAddr, LPDWORD) = NULL;
	LPCSTR subnet;
	LPCSTR netmask;
	LPCSTR gateway;

	subnet  = met_api->packet.get_tlv_value_string(packet, TLV_TYPE_SUBNET_STRING);
	netmask = met_api->packet.get_tlv_value_string(packet, TLV_TYPE_NETMASK_STRING);
	gateway = met_api->packet.get_tlv_value_string(packet, TLV_TYPE_GATEWAY_STRING);

	memset(&route, 0, sizeof(route));

	route.dwForwardDest    = inet_addr(subnet);
	route.dwForwardMask    = inet_addr(netmask);
	route.dwForwardNextHop = inet_addr(gateway);
	route.dwForwardType    = 4; // Assume next hop.
	route.dwForwardProto   = 3;
	route.dwForwardAge     = -1;

	if ((LocalGetBestInterface = (DWORD (WINAPI *)(IPAddr, LPDWORD))GetProcAddress(
			GetModuleHandle("iphlpapi"),
			"GetBestInterface")))
	{
		DWORD result = LocalGetBestInterface(route.dwForwardDest,
				&route.dwForwardIfIndex);

		if (result != ERROR_SUCCESS)
			return result;
	}
	// I'm lazy.  Need manual lookup of ifindex based on gateway for NT.
	else
		return ERROR_NOT_SUPPORTED;

	if (add)
		return CreateIpForwardEntry(&route);
	else
		return DeleteIpForwardEntry(&route);
}
