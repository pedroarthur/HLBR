#!/bin/bash

# iwatch-restart.sh - restart iwatch after a hlbr log rotate; it is
#                     activated by iwatch and is part of the hlbrw program.

# Copyright 2009-2010 Joao Eriberto Mota Filho <eriberto@eriberto.pro.br>

#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.

# There are a hlbrw?

if [ ! -x "/usr/bin/hlbrw" ]; then
    exit 0;
fi


# Get variables
source /etc/hlbrw.conf

[ "$HLBRLOG" ] || exit 1


# Waiting for new log creation...
while [ ! -f $HLBRLOG ]; do sleep 1; done


# Restart iwatch
/etc/init.d/iwatch restart > /dev/null
