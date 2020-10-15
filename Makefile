# **************************************************************************** #
#                                                                              #
#                                                         :::      ::::::::    #
#    Makefile                                           :+:      :+:    :+:    #
#                                                     +:+ +:+         +:+      #
#    By: eparisot <eparisot@student.42.fr>          +#+  +:+       +#+         #
#                                                 +#+#+#+#+#+   +#+            #
#    Created: 2020/08/24 23:09:54 by eparisot          #+#    #+#              #
#    Updated: 2020/08/24 23:09:56 by eparisot         ###   ########.fr        #
#                                                                              #
# **************************************************************************** #

NAME	=	ft_malcolm

SRCS	=	srcs/main.c				\
			srcs/ft_malcolm.c		\
			srcs/utils.c			\
			
INC		=	includes/ft_malcolm.h

OBJS	=	$(SRCS:.c=.o)

LIBS	=	libft/libft.a \

CFLAGS	=	-Wall -Wextra -Werror -g3

RM		=	rm -f

all		:	$(LIBS) $(NAME)

$(NAME)	:	$(OBJS) $(INC)
	gcc $(CFLAGS) $(OBJS) $(LIBS) -o $(NAME)

$(LIBS)	:
	@$(MAKE) -C libft

clean	:
	$(RM) $(OBJS) && $(MAKE) clean -C libft

fclean	:	clean
	$(RM) $(NAME) libft/libft.a

re		:	fclean all

.PHONY : all re clean fclean
