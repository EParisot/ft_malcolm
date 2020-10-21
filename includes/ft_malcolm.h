/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_malcolm.h                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: eparisot <eparisot@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2020/08/24 23:09:42 by eparisot          #+#    #+#             */
/*   Updated: 2020/08/24 23:11:02 by eparisot         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef FT_MALCOLM_H

# define FT_MALCOLM_H

# include "../libft/libft.h"
# include <stdlib.h>
# include <stdio.h>
# include <signal.h>
# include <unistd.h>
# include <sys/types.h>
# include <ifaddrs.h>
# include <netinet/if_ether.h>
# include <arpa/inet.h>
# include <netinet/ip.h>
# include <sys/socket.h>
# include <stdbool.h>
# include <netpacket/packet.h>

bool g_stop;

#define PKT_SIZE 1024
#define TIMEOUT 1

typedef struct			s_mac
{
   unsigned char 		bytes[6];
}						t_mac;

typedef struct			s_env
{
	struct sockaddr_in	*localhost;
	t_mac				*local_mac;
	struct sockaddr_in	*source_ip;
	t_mac				*source_mac;
	struct sockaddr_in	*target_ip;
	t_mac				*target_mac;
	bool				bi_directional;
	int					sock_fd;
	char				*iface;
}						t_env;

typedef struct 			s_arp_packet
{
  u_char				targ_hw_addr[ETHER_ADDR_LEN];
  u_char				src_hw_addr[ETHER_ADDR_LEN];
  u_short				frame_type;
  u_short				hw_type;
  u_short				prot_type;
  u_char				hw_addr_size;
  u_char				prot_addr_size;
  u_short				op;
  u_char					source_mac[ETHER_ADDR_LEN];
  u_char					source_ip[MAX_ADDR_LEN];
  u_char					target_mac[ETHER_ADDR_LEN];
  u_char					target_ip[MAX_ADDR_LEN];
  u_char				padding[18];
}						t_arp_packet;

int		ft_malcolm(t_env *env);

void	print_usage(void);
void	print_init(t_env *env);
void	print_mac(t_mac *mac);

#endif
