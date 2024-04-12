/*
This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>. 
*/

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include "hptypes.h"
#include "asmdecode.h"

struct quartet {
	unsigned char value:4;
};

#define BUFFER_SIZE (500 * 1024)

struct quartet *alloc_q(int q_size)
{
	return calloc(sizeof(struct quartet), q_size);
}

int buffer_to_quartets(unsigned char *buffer, size_t buffer_size,
		       struct quartet *q, int q_size)
{
	int i, j;

	if (q_size < 2 * buffer_size)
		return -EINVAL;

	for (i = 0, j = 0; i < buffer_size; i++) {
		q[j++].value = buffer[i] & 0xF;
		q[j++].value = (buffer[i] & 0xF0) >> 4;
	}

	return 0;
}

int quartets_to_buffer(struct quartet *q, int q_size,
		       unsigned char *buffer, size_t buffer_size)
{
	int i, j;

	if (buffer_size < (q_size + q_size % 2) / 2)
		return -EINVAL;

	for (i = 0, j = 0; i < q_size; i++) {
		if (i % 2 == 0) {
			buffer[j] = (q[i].value) & 0x0F;
		} else {
			buffer[j] |= (q[i].value << 4) & 0xF0;
			j++;
		}
	}

	return 0;
}

long read_int(struct quartet **q, int nb)
{
	int i;
	long value = 0;

	for (i = 0; i < nb; i++)
		value |= ((long)(*q)[i].value) << (4 * i);

	(*q) += nb;

	return value;
}

long write_int(struct quartet **q, long value, int nb)
{
	int i;

	for (i = 0; i < nb; i++)
		(*q)[i].value = 0xF & (value >> (4 * i));

	(*q) += nb;

	return value;
}

long read_int_no_incr(struct quartet **q, int nb)
{
	int i;
	long value = 0;

	for (i = 0; i < nb; i++)
		value |= (*q)[i].value << (4 * i);

	return value;
}

long read_int_flat(struct quartet **q, int nb)
{
	int i;
	long value = 0;

	for (i = 0; i < nb; i++)
		value |= (*q)[nb - i].value << (4 * i);

	(*q) += nb;

	return value;
}

long read_int_flat_no_incr(struct quartet **q, int nb)
{
	int i;
	long value = 0;

	for (i = 0; i < nb; i++)
		value |= (*q)[nb - i].value << (4 * i);

	return value;
}

char read_char(struct quartet **q)
{
	char value = 0;

	value |= (*q)[0].value;
	value |= (*q)[1].value << 4;
	(*q) += 2;

	return value;
}

int qposition(struct quartet *qref, struct quartet *q)
{
	return q - qref;
}

char write_char(struct quartet **q, char value)
{
	(*q)[0].value = value & 0xF;
	(*q)[1].value = (value >> 4) & 0xF;
	(*q) += 2;

	return value;
}

char qvalue(struct quartet *q, int i)
{
	return q[i].value;
}

int string_to_object(unsigned char *buffer, size_t buffer_size,
		     struct quartet **q, int *q_size)
{
	struct quartet *new_q;
	struct quartet *ptr;
	int i;

	*q_size = 5 + 5 + 2 * buffer_size;
	new_q = calloc(*q_size, sizeof(struct quartet));
	if (new_q == NULL)
		return -EINVAL;
	ptr = new_q;
	write_int(&ptr, 0x2A2C, 5);
	write_int(&ptr, buffer_size * 2 + 5, 5);
	for (i = 0; i < buffer_size; i++)
		write_char(&ptr, buffer[i]);

	*q = new_q;
	return 0;
}

void show_object(struct quartet *q, int q_size, int show_debug)
{
	int type;
	int length;
	int i;
	int e, m, s;
	int name_length;
	int lib_number;
	struct quartet *p;
	unsigned char *buffer;
	/* variables for lib */
	struct quartet *hash_ptr;
	struct quartet *message_array_ptr;
	struct quartet *link_table_ptr;
	struct quartet *config_object_ptr;
	int value;

	if (q_size < 5) {
		printf("size to low for an object (%d)\n", q_size);
		return;
	}

	if (show_debug == 2) {
		p = q;
		printf("D9D20 ");
		for (i = 0; i < q_size; i++) {
			printf("%lX", read_int(&p, 1));
			if (i > 0 && (i + 1 + 5) % 40 == 0)
				printf("\n");
			else if (i > 0 && (i + 1) % 5 == 0)
				printf(" ");
		}
		printf("B2130\n"); /* epilogue */
		return;
	}

	/* 500KB enougth for any Saturn asm code */
	buffer = calloc(1, BUFFER_SIZE);
	if (buffer == NULL) {
		printf("Memory allocation error\n");
		return;
	}

	p = q;
	type = read_int(&p, 5);
	switch(type) {
	case 0x2A2C:
		length = read_int(&p, 5);
		if (length == 0) {
			printf("Empty String\n");
			break;
		}
		length -= 5;
		if (length > q_size - 5) {
			printf("invalid lenth %d, maximum %d\n",
			       length, q_size - 5);
			break;
		}
		/* read as bytes */
		length /= 2;
		printf("String (0x%x) length %d '", type, length);
		for (i = 0; i < length; i++)
			printf("%c", read_char(&p));
		printf("'\n");
		break;
	case 0x2933:
		e = read_int(&p, 3);
		m = read_int(&p, 12);
		s = read_int(&p, 1);
		printf("real (0x%x) e %d m %d s %d\n", type, e, m, s);
		break;
		break;
	case 0x2955:
		e = read_int(&p, 5);
		m = read_int(&p, 15);
		s = read_int(&p, 1);
		printf("long real (0x%x) e %d m %d s %d\n", type, e, m, s);
		break;
	case 0x2B40:
		length = read_int(&p, 5);
		if (length > q_size - 5) {
			printf("invalid lenth %d, expected %d\n",
			       q_size, length);
			break;
		}
		printf("library (0x%x) length %d\n", type, length);

		name_length = read_int(&p, 2);
		printf("Name: '");
		for (i = 0; i < name_length; i++)
			printf("%c", read_char(&p));
		printf("'\n");
		value = read_int(&p, 2);
		if (value != name_length) {
			printf("Invalid name size: %d vs %d\n",
			       name_length, value);
			break;
		}
		lib_number = read_int(&p, 3);
		printf("Library nb: %d\n", lib_number);

		value = read_int(&p, 5);
		hash_ptr = p + value;
		message_array_ptr = p + read_int(&p, 5);
		link_table_ptr = p + read_int(&p, 5);
		config_object_ptr = p + read_int(&p, 5);
		if (p != hash_ptr) {
			printf("hash invalid position %d vs config %d\n",
			       qposition(q, p), qposition(q, hash_ptr));
			break;
		}

		printf("todo ...\n");
		break;
	case 0x2DCC:
		length = read_int(&p, 5) - 5;
		if (length > q_size) {
			printf("invalid lenth %d, expected %d\n",
			       q_size, length);
			break;
		}
		printf("Code (0x%x) length %d\n", type, length);
		asm_decode(p, length, show_debug);
		break;
	default:
		printf("unhandled type  0x%x\n", type);
		break;
	}

	free(buffer);
}
