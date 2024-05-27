/*
  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 3 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program. If not, see <https://www.gnu.org/licenses/>. 
*/

struct quartet;

struct quartet *alloc_q(int q_size);

int buffer_to_quartets(unsigned char *buffer, size_t buffer_size,
		       struct quartet *q, int q_size);

int quartets_to_buffer(struct quartet *q, int q_size,
		       unsigned char *buffer, size_t buffer_size);

long read_int(struct quartet **q, int nb);
long read_int_no_incr(struct quartet **q, int nb);
long read_int_flat(struct quartet **q, int nb);
long read_int_flat_no_incr(struct quartet **q, int nb);
char read_char(struct quartet **q);
int qposition(struct quartet *qref, struct quartet *q);
long write_int(struct quartet **q, long value, int nb);

void show_object(struct quartet *q, int q_size, int show_debug);
char qvalue(struct quartet *q, int i);
int string_to_object(unsigned char *buffer, size_t buffer_size,
		     struct quartet **q, int *q_size);
