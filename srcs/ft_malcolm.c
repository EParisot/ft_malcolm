/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_malcolm.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: eparisot <eparisot@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2020/08/24 23:09:42 by eparisot          #+#    #+#             */
/*   Updated: 2020/08/24 23:11:02 by eparisot         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../includes/ft_malcolm.h"

int			getlocalhost(t_env *env)
{
    struct ifaddrs  *id;
    struct ifaddrs  *ifa;
	int				ret = 0;

    if (getifaddrs(&id) == -1)
    {
	    return (-1);
	}
	if ((env->localhost = (struct sockaddr_in *)malloc(sizeof(struct sockaddr_in))) == NULL)
	{
		return (-1);
	}
    for (ifa = id; ifa != NULL; ifa = ifa->ifa_next)
    {
        if(env->iface && ifa->ifa_addr != NULL && ifa->ifa_addr->sa_family == AF_INET && ft_strcmp(ifa->ifa_name, env->iface) == 0)
    	{
			ft_memcpy(env->localhost, (struct sockaddr_in *)ifa->ifa_addr, sizeof(struct sockaddr_in));
			break;
		}
		else if (!env->iface && ifa->ifa_addr != NULL && ifa->ifa_addr->sa_family == AF_INET)
		{
			env->iface = ft_strdup(ifa->ifa_name);
			ft_memcpy(env->localhost, (struct sockaddr_in *)ifa->ifa_addr, sizeof(struct sockaddr_in));
			break;
		}
    }
	if (ifa == NULL)
	{
		printf("ft_malcolm: iface %s not found.\n", env->iface);
		ret = -1;
	}
    freeifaddrs(id);
	if (getifaddrs(&id) == -1)
        return (-1);
	if ((env->local_mac = (t_mac*)malloc(sizeof(t_mac))) == NULL)
		return (-1);
	for (ifa = id; ifa != NULL; ifa = ifa->ifa_next)
    {
		if (strcmp(ifa->ifa_name, env->iface) == 0 && (ifa->ifa_addr->sa_family == AF_PACKET))
		{
			struct sockaddr_ll *s = (struct sockaddr_ll*)ifa->ifa_addr;
			ft_memcpy(env->local_mac->bytes, s->sll_addr, 6);
		}
	}
	freeifaddrs(id);
	return (ret);
}

int			init_sock(t_env *env)
{
	struct timeval	tv_out;

	tv_out.tv_sec = TIMEOUT;
	tv_out.tv_usec = 0;
	if ((env->sock_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP))) < 0)
	{
		printf("ft_malcolm: Error opening Socket.\n");
		return (-1);
	}
	if (setsockopt(env->sock_fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv_out, sizeof(tv_out)) != 0)
		return (-1);
	if (getlocalhost(env))
		return (-1);
	if (env->source_mac == NULL)
		env->source_mac = env->local_mac;
	printf("ft_malcolm: Spoof MAC : ");
	print_mac(env->source_mac);
	return (0);
}

void		sig_handler(int num_sig)
{
	if (num_sig == SIGINT)
	{
		printf("ft_malcolm: Stopping...\n");
		g_stop = true;
	}
}

int			ft_malcolm(t_env *env)
{
	size_t	buf_size = PKT_SIZE;
	char	buf[buf_size];
	struct ether_arp *arp_frame;

	ft_bzero(buf, buf_size);
	if (init_sock(env))
		return (-1);
	print_init(env);
	g_stop = false;
	signal(SIGINT, sig_handler);
	while (g_stop == false)
	{
		recv(env->sock_fd, buf, buf_size, 0);
		if ((((buf[12]) << 8) + buf[13]) == ETH_P_ARP)
		{
			arp_frame = (struct ether_arp *) (buf + 14);
			if (ntohs(arp_frame->arp_op) == ARPOP_REQUEST)
			{
				if (htonl(*(uint32_t*)arp_frame->arp_tpa) == htonl(env->target_ip->sin_addr.s_addr) &&
					htonl(*(uint32_t*)arp_frame->arp_spa) == htonl(env->source_ip->sin_addr.s_addr))
				{
					printf("Got an arp request for target with ip: %u.%u.%u.%u - mac: %02x:%02x:%02x:%02x:%02x:%02x\n\t\t\t\tfrom ip: %u.%u.%u.%u - mac: %02x:%02x:%02x:%02x:%02x:%02x\n", 
						arp_frame->arp_tpa[0], arp_frame->arp_tpa[1], arp_frame->arp_tpa[2], arp_frame->arp_tpa[3],
						arp_frame->arp_tha[0], arp_frame->arp_tha[1], arp_frame->arp_tha[2], arp_frame->arp_tha[3], arp_frame->arp_tha[4], arp_frame->arp_tha[5],
						arp_frame->arp_spa[0], arp_frame->arp_spa[1], arp_frame->arp_spa[2], arp_frame->arp_spa[3],
						arp_frame->arp_sha[0], arp_frame->arp_sha[1], arp_frame->arp_sha[2], arp_frame->arp_sha[3], arp_frame->arp_sha[4], arp_frame->arp_sha[5]);
					break;
				}
			}
		}
	}
	while (g_stop == false)
	{
		recv(env->sock_fd, buf, buf_size, 0);
		if ((((buf[12]) << 8) + buf[13]) == ETH_P_ARP)
		{
			arp_frame = (struct ether_arp *) (buf + 14);
			if (ntohs(arp_frame->arp_op) == ARPOP_REQUEST)
			{
				if (htonl(*(uint32_t*)arp_frame->arp_spa) == htonl(env->target_ip->sin_addr.s_addr) &&
					htonl(*(uint32_t*)arp_frame->arp_tpa) == htonl(env->source_ip->sin_addr.s_addr))
				{
					printf("Got an arp response for target with ip: %u.%u.%u.%u - mac: %02x:%02x:%02x:%02x:%02x:%02x\n\t\t\t\tfrom ip: %u.%u.%u.%u - mac: %02x:%02x:%02x:%02x:%02x:%02x\n", 
						arp_frame->arp_tpa[0], arp_frame->arp_tpa[1], arp_frame->arp_tpa[2], arp_frame->arp_tpa[3],
						arp_frame->arp_tha[0], arp_frame->arp_tha[1], arp_frame->arp_tha[2], arp_frame->arp_tha[3], arp_frame->arp_tha[4], arp_frame->arp_tha[5],
						arp_frame->arp_spa[0], arp_frame->arp_spa[1], arp_frame->arp_spa[2], arp_frame->arp_spa[3],
						arp_frame->arp_sha[0], arp_frame->arp_sha[1], arp_frame->arp_sha[2], arp_frame->arp_sha[3], arp_frame->arp_sha[4], arp_frame->arp_sha[5]);
					break;
				}
			}
		}
	}
	if (g_stop == false)
	{
		printf("Sending spoofed ARP to ip %u.%u.%u.%u - mac %02x:%02x:%02x:%02x:%02x:%02x\n\t\t\t\twith src ip %u.%u.%u.%u - mac %02x:%02x:%02x:%02x:%02x:%02x\n",
		arp_frame->arp_tpa[0], arp_frame->arp_tpa[1], arp_frame->arp_tpa[2], arp_frame->arp_tpa[3],
		arp_frame->arp_tha[0], arp_frame->arp_tha[1], arp_frame->arp_tha[2], arp_frame->arp_tha[3], arp_frame->arp_tha[4], arp_frame->arp_tha[5],
		arp_frame->arp_spa[0], arp_frame->arp_spa[1], arp_frame->arp_spa[2], arp_frame->arp_spa[3],
		env->source_mac->bytes[0], env->source_mac->bytes[1], env->source_mac->bytes[2], env->source_mac->bytes[3], env->source_mac->bytes[4], env->source_mac->bytes[5]);
		// TODO :
		// Wait for target ARP response and spoof by sending crafted ARP packet to target and why not to src too !
	}
	return (0);
}