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
   uint8_t		 		bytes[6];
   char					str[18];
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
	bool				specific;
	int					sock_fd;
	char				*iface;
}						t_env;

typedef struct __attribute__((packed)) s_arp_packet
{
  uint8_t				targ_hw_addr[ETHER_ADDR_LEN];
  uint8_t				src_hw_addr[ETHER_ADDR_LEN];
  uint16_t				frame_type;
  uint16_t				hw_type;
  uint16_t				prot_type;
  uint8_t				hw_addr_size;
  uint8_t				prot_addr_size;
  uint16_t				op;
  uint8_t				source_mac[ETHER_ADDR_LEN];
  uint32_t				source_ip;
  uint8_t				target_mac[ETHER_ADDR_LEN];
  uint32_t				target_ip;
  unsigned char			padding[18];
}						t_arp_packet;

int		ft_malcolm(t_env *env);

void	print_usage(void);
void	print_init(t_env *env);
void	print_mac(unsigned char *mac);

#endif
