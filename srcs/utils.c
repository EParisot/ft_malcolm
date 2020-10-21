/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   utils.c                                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: eparisot <eparisot@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2020/08/24 23:09:42 by eparisot          #+#    #+#             */
/*   Updated: 2020/08/24 23:11:02 by eparisot         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../includes/ft_malcolm.h"

void		print_usage()
{
	printf("usage: ./ft_malcolm [-i iface] src_IP src_MAC tgt_IP tgt_MAC\n\
	iface:   network interface (str)\n\
	src_IP:  host IP (XXX.XXX.XXX.XXX or hostname))\n\
	src_MAC: host MAC (XX:XX:XX:XX:XX:XX)\n\
	tgt_IP:  target IP (XXX.XXX.XXX.XXX or hostname)\n\
	tgt_MAC: target MAC (XX:XX:XX:XX:XX:XX)\n");
}

void		print_mac(unsigned char *mac)
{
	for (int i = 0; i < 6; i++)
	{
		printf("%02x", mac[i]);
		if (i < 5)
			printf(":");
		else
			printf("\n");		
	}
}

void		print_init(t_env *env)
{
	if (env->specific)
	{
		printf("Listening ARP packets on %s from %s ", env->iface, inet_ntoa(env->target_ip->sin_addr));
		printf("to %s\n", inet_ntoa(env->source_ip->sin_addr));
	}
	else
	{
		printf("Listening ARP packets on %s from %s ", env->iface, inet_ntoa(env->source_ip->sin_addr));
		printf("to %s\n", inet_ntoa(env->target_ip->sin_addr));
	}
	
	printf("Spoof MAC : ");
	print_mac(env->source_mac->bytes);
}