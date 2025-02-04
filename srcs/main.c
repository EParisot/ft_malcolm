/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   main.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: eparisot <eparisot@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2020/08/24 23:09:42 by eparisot          #+#    #+#             */
/*   Updated: 2020/08/24 23:11:02 by eparisot         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../includes/ft_malcolm.h"

void free_mac(char **mac)
{
	for (size_t i = 0; i < ft_tablen(mac); i++)
	{
		free(mac[i]);
	}
	free(mac);
}

static t_mac *parse_mac(char *str)
{
	char **mac_str;
	t_mac *mac;
	size_t mac_size;
	int test;

	if ((mac = (t_mac *)malloc(sizeof(t_mac))) == NULL)
		return (NULL);
	ft_strcpy(mac->str, str);
	mac_str = ft_strsplit(str, ':');
	if ((mac_size = ft_tablen(mac_str)) != 6)
	{
		printf("ft_malcolm: Error in address %s\n", str);
		free_mac(mac_str);
		free(mac);
		return (NULL);
	}
	for (size_t i = 0; i < mac_size; i++)
	{
		if ((test = ft_hextoint(mac_str[i])) == -1)
		{
			printf("ft_malcolm: Error reading MAC address %s\n", str);
			free_mac(mac_str);
			free(mac);
			return (NULL);
		}
		mac->bytes[i] = test;
	}
	free_mac(mac_str);
	return (mac);
}

static struct sockaddr_in *parse_ip(char *str)
{
	struct sockaddr_in *sa;
	char *str_ip;

	if (ft_strchr(str, ':'))
		return (NULL);
	if ((str_ip = dns_lookup(str)) == NULL)
		return (NULL);
	if ((sa = (struct sockaddr_in *)malloc(sizeof(struct sockaddr_in))) == NULL)
		return (NULL);

	char **tab = ft_strsplit(str_ip, '.');
	uint8_t n_tab[4];
	for (int t = 0; t < 4; t++)
	{
		n_tab[t] = (uint8_t)ft_atoi(tab[t]);
		free(tab[t]);
	}
	sa->sin_addr.s_addr = *(uint32_t *)n_tab;
	sa->sin_family = AF_INET;
	free(str_ip);
	free(tab);
	return (sa);
}

static int parse_opt(t_env *env, int ac, char **av)
{
	char *opt;
	struct sockaddr_in *ip;
	t_mac *mac;

	if (ac < 5)
	{
		print_usage();
		return (-1);
	}
	for (int i = 1; i < ac; i++)
	{
		opt = av[i];
		if (ft_strcmp(opt, "-i") == 0)
		{
			i++;
			env->iface = ft_strdup(av[i]);
			continue;
		}
		if (ft_strcmp(opt, "-t") == 0)
		{
			i++;
			env->timeout = ft_atoi(av[i]);
			continue;
		}
		if (ft_strcmp(opt, "-b") == 0)
		{
			env->bi_directional = true;
			continue;
		}
		if (ft_strcmp(opt, "-s") == 0)
		{
			env->specific = true;
			continue;
		}
		if (ft_strcmp(opt, "-f") == 0)
		{
			env->flood = true;
			continue;
		}
		if ((ip = parse_ip(opt)) == NULL)
		{
			if ((mac = parse_mac(opt)) == NULL)
				return (-1);
			if (env->target_ip == NULL && env->source_mac == NULL)
			{
				env->source_mac = mac;
			}
			else if (env->target_mac == NULL)
			{
				env->target_mac = mac;
			}
			else
			{
				print_usage();
				return (-1);
			}
		}
		else
		{
			if (env->source_ip == NULL)
			{
				env->source_ip = ip;
			}
			else if (env->target_ip == NULL)
			{
				env->target_ip = ip;
			}
			else
			{
				print_usage();
				return (-1);
			}
		}
	}
	return (0);
}

static void clean_env(t_env *env)
{
	if (env->localhost)
		free(env->localhost);
	if (env->local_mac)
		free(env->local_mac);
	if (env->source_ip)
		free(env->source_ip);
	if (env->target_ip)
		free(env->target_ip);
	if (env->source_mac && env->source_mac != env->local_mac)
		free(env->source_mac);
	if (env->target_mac)
		free(env->target_mac);
	if (env->iface)
		free(env->iface);
	free(env);
}

int main(int ac, char **av)
{
	int ret = 0;
	t_env *env;

	if (getuid() != 0)
	{
		printf("ft_malcolm: Insufficient Permission.\n");
		return (-1);
	}
	if ((env = (t_env *)malloc(sizeof(t_env))) == NULL)
		return (-1);
	env->timeout = TIMEOUT;
	env->localhost = NULL;
	env->local_mac = NULL;
	env->source_ip = NULL;
	env->source_mac = NULL;
	env->target_ip = NULL;
	env->target_mac = NULL;
	env->bi_directional = false;
	env->specific = false;
	env->flood = false;
	env->sock_fd = 0;
	env->iface = NULL;
	if ((ret = parse_opt(env, ac, av)))
	{
		clean_env(env);
		return (ret);
	}
	ret = ft_malcolm(env);
	if (ret)
		printf("Spoofing Failed\n");
	clean_env(env);
	return (ret);
}