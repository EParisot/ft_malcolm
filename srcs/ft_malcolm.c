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
        return (1);
    for (ifa = id; ifa != NULL; ifa = ifa->ifa_next)
    {
        if(env->iface && (ifa->ifa_addr != NULL) && (ft_strcmp(ifa->ifa_name, env->iface) == 0) && (ifa->ifa_addr->sa_family == AF_INET))
    		break;
		else if (env->iface)
			continue;
		else
		{
			env->iface = ft_strdup(ifa->ifa_name);
			break;
		}
    }
	if (ifa == NULL)
	{
		printf("ft_malcolm: iface %s not found.\n", env->iface);
		ret = -1;
	}
	if ((env->localhost = (struct sockaddr_in *)malloc(sizeof(struct sockaddr_in))) == NULL)
		return (-1);
	ft_memcpy(env->localhost, (struct sockaddr_in *)ifa->ifa_addr, sizeof(struct sockaddr_in));
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
	int		received = 0;
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
		received = recv(env->sock_fd, buf, buf_size, 0);
		if (received > 0)
		{
			if (ft_strlen(buf) > 13 && (((buf[12]) << 8) + buf[13]) == ETH_P_ARP)
			{
				arp_frame = (struct ether_arp *) (buf + 14);
				printf("Got an arp pkt from host with ip: %u.%u.%u.%u\n", arp_frame->arp_spa[0],
																	arp_frame->arp_spa[1],
																	arp_frame->arp_spa[2],
																	arp_frame->arp_spa[3]);
			}
		}
	}
	return (0);
}