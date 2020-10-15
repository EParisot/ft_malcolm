/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_hextoint.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: eparisot <eparisot@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/10/29 14:56:01 by eparisot          #+#    #+#             */
/*   Updated: 2018/03/19 19:07:00 by eparisot         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

int		ft_hextoint(const char *str)
{
	size_t	i;
	int	res;

	res = 0;
	i = 0;
	while (i < ft_strlen(str))
	{
		res *= 16;
		if(str[i] >= 'a' && str[i] <= 'f')
			res += (str[i] - 'a' + 10);
		else if(str[i] >= 'A' && str[i] <= 'F')
			res += (str[i] - 'A' + 10);
		else if(str[i] >= '0' && str[i] <= '9')
			res += (str[i] - '0');
		else
			return (-1);
		i++;
	}
	return (res);
}