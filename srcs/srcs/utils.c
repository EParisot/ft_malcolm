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

void			print_usage()
{
	printf("usage: ./ft_malcolm src_IP src_MAC tgt_IP tgt_MAC [-i iface] [-t sec] [-s] [-b]\n\
	iface:   network interface (str)\n\
	src_IP:  host IP (XXX.XXX.XXX.XXX or hostname))\n\
	src_MAC: host MAC (XX:XX:XX:XX:XX:XX)\n\
	tgt_IP:  target IP (XXX.XXX.XXX.XXX or hostname)\n\
	tgt_MAC: target MAC (XX:XX:XX:XX:XX:XX)\n\
	-t sec:  timeout seconds to wait for reply\n\
	-s:      wait for specific IP source\n\
	-b:      send bi-directional spoof\n");
}

void			print_mac(unsigned char *mac)
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

void			print_init(t_env *env)
{
	uint8_t *ptr;
	if (env->specific == false)
	{
		ptr = (uint8_t*)&env->target_ip->sin_addr.s_addr;
		printf("Listening ARP packets on %s from %d.%d.%d.%d to broadcast\n", env->iface, ptr[0], ptr[1], ptr[2], ptr[3]);
	}
	else
	{
		ptr = (uint8_t*)&env->target_ip->sin_addr.s_addr;
		printf("Listening ARP packets on %s from %d.%d.%d.%d ", env->iface, ptr[0], ptr[1], ptr[2], ptr[3]);
		ptr = (uint8_t*)&env->source_ip->sin_addr.s_addr;
		printf("to %d.%d.%d.%d\n", ptr[0], ptr[1], ptr[2], ptr[3]);
	}
	printf("Spoof MAC : ");
	print_mac(env->source_mac->bytes);
}

static void		set_addr_info_struct(struct addrinfo *hints)
{
	ft_memset(hints, 0, sizeof(struct addrinfo));
	hints->ai_family = AF_UNSPEC;
	hints->ai_socktype = SOCK_DGRAM;
	hints->ai_flags = AI_PASSIVE | AI_CANONNAME;
	hints->ai_protocol = 0;
	hints->ai_canonname = NULL;
	hints->ai_addr = NULL;
	hints->ai_next = NULL;
}

static void		free_addr_info(struct addrinfo *result)
{
	struct addrinfo *tmp;

	while (result)
	{
		tmp = result;
		result = result->ai_next;
		free(tmp->ai_canonname);
		free(tmp);
	}
}

static int		dns_err(char *addr, struct addrinfo *hints, \
												struct addrinfo **result)
{
	int err;

	err = 0;
	if ((err = getaddrinfo(addr, NULL, hints, result)) != 0)
	{
		if (err != -5 && err != -2)
			fprintf(stderr, "ft_malcolm: %s: Temporary failure in name resolution\n", addr);
		else if (err == -5)
			fprintf(stderr, "ft_malcolm: %s: No address associated with hostname!\n", addr);
		else if (err == -2)
			fprintf(stderr, "ft_malcolm: %s: Name or service not known\n",addr);
		return (-1);
	}
	return (0);
}

static char		*dns_lookup_b(struct addrinfo *result)
{
	struct sockaddr_in	*addr_in;
	char				*str_addr;

	if (result->ai_addr->sa_family == AF_INET)
	{
		addr_in = (struct sockaddr_in *)result->ai_addr;
		if ((str_addr = (char *)malloc(INET_ADDRSTRLEN)) == NULL)
			return (NULL);
		ft_bzero(str_addr, INET_ADDRSTRLEN);
		uint8_t *ptr = (uint8_t*)&addr_in->sin_addr.s_addr;
		sprintf(str_addr, "%d.%d.%d.%d", ptr[0], ptr[1], ptr[2], ptr[3]);
	}
	else if (result->ai_addr->sa_family == AF_INET6)
	{
		fprintf(stderr, "ft_malcolm: IPV6 Not Implemented\n");
		return (NULL);
	}
	return (str_addr);
}

char	*dns_lookup(char *addr)
{
	struct addrinfo hints;
	struct addrinfo *result;
	char			*str_res;

	result = NULL;
	set_addr_info_struct(&hints);
	if (dns_err(addr, &hints, &result) == -1)
	{
		return (NULL);
	}
	if (result)
	{
		str_res = dns_lookup_b(result);
	}
	free_addr_info(result);
	return (str_res);
}