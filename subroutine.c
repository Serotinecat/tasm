/*
This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>. 
*/

#include <string.h>

#include "subroutine.h"

struct subr subroutines[] = {
	{ .addr = 0x0679B, .name = "SAVE_REG", .desc = "save RPL registers", .modified = "D0, Ca"},
	{ .addr = 0x0679B, .name = "SAVPTR", .desc = "save RPL registers", .modified = "D0, Ca"},
	{ .addr = 0x067D2, .name = "LOAD_REG", .desc = "get RPL registers saved by SAVE_REG",  .modified = "D0, D1, Ba, Ca, Da"},
	{ .addr = 0x06537, .name = "PUSHR0", .desc = "Push R0 on stack"},
	{ .addr = 0x067D2, .name = "GETPTR", .desc = "get RPL registers saved by SAVE_REG",  .modified = "D0, D1, Ba, Ca, Da"},
	{ .addr = 0x03991, .name = "B=A*C_A"},
	{ .addr = 0x05023, .name = "TOO_FEW_ARGS", .desc =  "too few arguments, error 0x201"},
	{ .addr = 0x05023, .name = "ERRJMP", .desc =  "too few arguments, error 0x201"},
	{ .addr = 0x03F24, .name = "C=A/C_A" },
	{ .addr = 0x12002, .name = "EXIT" },
	{ .addr = 0x03019, .name = "JUMPD0", .desc = "load, D0 goes after object" },
	{ .addr = 0x03019, .name = "SKIPOB", .desc = "load, D0 goes after object" },
	{ .addr = 0x05B7D, .name = "MAKE$N", .desc = "reserves a string Ca long" },
	{ .addr = 0x0670C, .name = "MOVEDOWN", .desc = "copy down" },
	{ .addr = 0x2D564, .name = "LOOP", .desc = "returns to RPL" },
	{ .addr = 0x05143, .name = "GETPTRLOOP", .desc = "recover saved register and exit"},
	{ .addr = 0x0115A, .name = "AIN", .desc = "A=IN"},
};

#ifndef SIZEOF_ARRAY
#define SIZEOF_ARRAY(a) ((sizeof(a) / (sizeof(*(a)))))
#endif

int subroutines_nb = SIZEOF_ARRAY(subroutines);

struct subr *get_subr(int addr)
{
	int i;

	for (i = 0; i < subroutines_nb; i++)
		if (subroutines[i].addr == addr)
			return &subroutines[i];

	return NULL;
}

int get_subr_addr(char *name)
{
	int i;
	char *searchname = name;

	if (searchname == NULL)
		return 0;
	if (*searchname == '=')
		searchname++;

	for (i = 0; i < subroutines_nb; i++)
		if (!strncasecmp(subroutines[i].name,
				 searchname,
				 strlen(subroutines[i].name)))
			return subroutines[i].addr;

	return 0;
}

void show_subr(struct subr *s)
{
	printf( " %s (0x%05x)", s->name, s->addr);
	if (s->desc != NULL)
		printf(" ; %s\n", s->desc);
	else
		printf("\n");
}

void list_subr()
{
	int i;

	for (i = 0; i < subroutines_nb; i++)
		printf("%05X: %s %s\n",
		       subroutines[i].addr,
		       subroutines[i].name,
		       subroutines[i].desc);

}
