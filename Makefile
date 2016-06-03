#
# (C) Copyright 2016, TP-Link Inc, konstantin.mauch@tp-link.com
# 
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; either version 2 of
# the License, or (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston,
# MA 02111-1307 USA
#

CFLAGS :=

CC := gcc

MAJOR := 4
MIDDLE := 4
MINOR := 0

NAME:= ssh
NAME_A := ./access_srv1
PWD=$(shell pwd)



VERSION := $(MAJOR).$(MIDDLE).$(MINOR)

all: $(NAME_A)

lib: ./shared/lib$(NAME).so.$(VERSION)

$(NAME_A):	./shared/lib$(NAME).so
		$(CC) -I/home/mkn/_libssh/libssh/include  ./sample.c ./authentication.c ./knownhosts.c   -o $@ -L./shared -l$(NAME) \
		 -Wl,--rpath-link $(PWD)/shared  -Wl,--rpath $(PWD)/shared

clean:
	$(RM) $(NAME_A) *.o *.so* *~
