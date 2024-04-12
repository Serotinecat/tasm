/*
This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>. 
*/

#include <stdio.h>
#include <stdlib.h>

/* special fields */
enum instr_flags {
	FLAG_ADDR2 = 0x10, /* adress on 2 quartets */
	FLAG_ADDR3,        /* adress on 3 quartets */
	FLAG_ADDR3SUB,     /* gosub adress on 3 quartets */
	FLAG_ADDR4,        /* adress on 4 quartets */
	FLAG_ADDR5,        /* adress on 5 quartets */
	FLAG_PTR2,         /* pointer on 5 quartets */
	FLAG_PTR3,         /* pointer on 5 quartets */
	FLAG_PTR4,         /* pointer on 5 quartets */
	FLAG_PTR5,         /* pointer on 5 quartets */
	FLAG_VAR,          /* param is variable hexa 3xh0..hx: #hx...h0 */
	FLAG_N,            /* param is n (n is quartet val) */
	FLAG_DEC,          /* param is decimal(in quartet val) */
	FLAG_N1,           /* param is n+1 (n is quartet val) */
	FLAG_X1,           /* param is x+1 (n is quartet val) */
	FLAG_A_FIELD,      /* field indication */
	FLAG_F_FIELD,      /* field indication */
	FLAG_B_FIELD,      /* field indication */
	FLAG_BIT_INDEX,    /* bit index */
};

struct instr {
	int sl; /* static instr length */
	unsigned int v[8];
	char *name;
};

extern char field_a[];
extern char field_f[];
extern char field_b[];


extern const struct instr instructions[];
extern int instructions_nb;
