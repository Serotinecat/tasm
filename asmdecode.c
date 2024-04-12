/*
This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>. 
*/

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include "hptypes.h"
#include "asmdefs.h"
#include "asmdecode.h"
#include "subroutine.h"

int instr_is_condition(struct instr inst)
{
	if (inst.name[0] == '?')
		return 1;

	return 0;
}

int inst_is_sub(struct instr inst)
{
	if (strstr(inst.name, "SUB"))
		return 1;

	return 0;
}

void print_instr(struct instr inst)
{
	char *tmp;

	for (tmp = inst.name; *tmp != '\0'; tmp++)
		if (*tmp != '$')
			printf("%c", *tmp);
}

int instr_match(struct instr inst, struct quartet *q)
{
	int i;

	/* check only static values */
	for (i = 0; i < inst.sl; i++) {
		if (inst.v[i] < 0x10 &&
		    inst.v[i] != qvalue(q, i))
			return 0;
		/* if field, check possibility */
		if (inst.v[i] == FLAG_A_FIELD &&
		    field_a[qvalue(q, i) * 2] == '-')
			return 0;
		if (inst.v[i] == FLAG_B_FIELD &&
		    field_b[qvalue(q, i) * 2] == '-')
			return 0;
		if (inst.v[i] == FLAG_F_FIELD &&
		    field_f[qvalue(q, i) * 2] == '-')
			return 0;
	}

	/* all match */
	return 1;
}

int get_addr_size(struct instr inst)
{
	int i;

	for (i = 0; i < inst.sl; i++) {
		switch (inst.v[i]) {
		case FLAG_ADDR2:
			return 2;
		case FLAG_ADDR3:
		case FLAG_ADDR3SUB:
			return 3;
		default:
			break;
		}
	}
	return 0;
}

int pointed_index(int current, struct instr inst, int value, int real_size)
{
	int pointed = current;
	int addr_size = get_addr_size(inst);

	/* special case for RTNYES */
	if (value == 0)
		return 0;

	if (addr_size == 2) {
		if (value & 0x80)
			pointed -= 0xFF - value;
		else
			pointed += value + real_size - 4;
	} else if (addr_size == 3) {
		if(value & 0x800)
			pointed -= 0xFFF - value;
		else
			pointed += value;
	} else {
		pointed += value + 1;
	}

	if (instr_is_condition(inst))
		pointed += 2;

	return pointed;
}

/* goto_value: filled if is_jump */
/* num_value: filled is is_num_value != 0 */
/* field_id: filled if is_dield_id */
void read_inst(struct instr *inst, struct quartet **q,
	       int *is_jump, int *is_ptr, int *goto_value,
	       int *is_num_value, int *variable_size, long *num_value,
	       int *is_field_id, char field_id[2])
{
	int i;
	int field_index;
	*is_jump = 0;
	*is_ptr = 0;
	*is_num_value = 0;
	*variable_size = 0;
	*is_field_id = 0;
	*goto_value = 0;

	for (i = 0; i < inst->sl; i++) {
		/* process only special fields */
		switch (inst->v[i]) {
		case FLAG_ADDR2:
			*goto_value = read_int(q, 2);
			*is_jump = 1;
			break;
		case FLAG_PTR2:
			*goto_value = read_int(q, 2);
			*is_ptr = 1;
			break;
		case FLAG_ADDR3:
		case FLAG_ADDR3SUB:
			*goto_value = read_int(q, 3);
			*is_jump = 1;
			break;
		case FLAG_PTR3:
			*goto_value = read_int(q, 3);
			*is_ptr = 1;
			break;
		case FLAG_ADDR4:
			*goto_value = read_int(q, 4);
			*is_jump = 2; /* 2 is long jump */
			break;
		case FLAG_PTR4:
			*goto_value = read_int(q, 4);
			*is_ptr = 1;
			break;
		case FLAG_ADDR5:
			*goto_value = read_int(q, 5);
			*is_jump = 2; /* 2 is long jump */
			break;
		case FLAG_PTR5:
			*num_value = read_int(q, 5);
			*is_ptr = 1;
			break;
		case FLAG_VAR:
			*variable_size = read_int(q, 1) + 1;
			*num_value = read_int(q, *variable_size);
			*is_num_value = 2;
			break;
		case FLAG_N:
			*num_value = read_int(q, 1);
			*is_num_value = 1;
			break;
		case FLAG_DEC:
		case FLAG_N1:
		case FLAG_X1:
			*num_value = read_int(q, 1) + 1;
			*is_num_value = 1;
			break;
		case FLAG_A_FIELD:
			field_index = read_int(q, 1);
			field_id[0] = field_a[field_index * 2];
			field_id[1] = field_a[field_index * 2 + 1];
			*is_field_id = 1;
			break;
		case FLAG_F_FIELD:
			field_index = read_int(q, 1);
			field_id[0] = field_f[field_index * 2];
			field_id[1] = field_f[field_index * 2 + 1];
			*is_field_id = 1;
			break;
		case FLAG_B_FIELD:
			field_index = read_int(q, 1);
			field_id[0] = field_b[field_index * 2];
			field_id[1] = field_b[field_index * 2 + 1];
			*is_field_id = 1;
			break;
		case FLAG_BIT_INDEX:
			*num_value = read_int(q, 1);
			*is_num_value = 1;
			break;
		default:
			/* just pass instruction already checked */
			read_int(q, 1);
			break;
		}
	}
}

void browse_instructions(struct quartet *q, int length,
			 int *labels, int *labels_is_subcalled,
			 int detect_labels, int dump,
			 int show_addr, int show_debug)
{
	int i, j;
	struct instr inst;
	int instr_index;
	int goto_value;
	long value;
	int instruction_processed;
	int pointed;
	int next_label = 1;
	struct quartet *qref;
	struct quartet *instr_start;
	int is_jump;
	int is_ptr;
	int is_num_value;
	int variable_size;
	int is_field_id;
	int real_size;
	char field_id[2];
	struct subr *subroutine;

	qref = q;
	while (qposition(qref, q) < length) {
		instr_index = qposition(qref, q);
		if (dump && labels[instr_index] > 0) {
			if (labels_is_subcalled[instr_index])
				printf("\n;function\n");
			if (show_addr)
				printf("LABEL%d (%x)\n",
				       labels[instr_index], instr_index);
			else
				printf("LABEL%d\n",
				       labels[instr_index]);
		}
		/* search in instructions */
		instruction_processed = 0;

		if (show_debug) {
			printf("%x: ", instr_index);
			for (i = 0; i < 8; i++)
				printf("%X", qvalue(q, i));
			printf("...\n");
		}

		for (j = 0; j < instructions_nb &&
			     instruction_processed == 0; j++) {
			inst = instructions[j];
			if (!instr_match(inst, q))
				continue;
			instruction_processed = 1;

			/* read instruction  */
			instr_start = q;
			read_inst(&inst, &q,
				  &is_jump, &is_ptr, &goto_value,
				  &is_num_value, &variable_size, &value,
				  &is_field_id, field_id);
			if (dump) {
				if (show_addr)
					printf("%x:", instr_index);
				printf("\t");
				print_instr(inst);
			}
			real_size = qposition(instr_start, q);

			if (is_num_value == 1) {
				if (dump)
					printf("%ld", value);
			} else if (is_num_value == 2 || is_ptr) {
				if (dump) {
					if (variable_size)
						printf("(%d)%lx",
						       variable_size, value);
					else
						printf("0x%05lx", value);
				}
			}

			if (is_field_id) {
				if (dump)
					printf(" %c%c",
					       field_id[0], field_id[1]);
			}

			/* process jump from addr unless it's long jump */
			if (is_jump == 1) {
				pointed = pointed_index(instr_index, inst,
							goto_value, real_size);
			} else if (is_jump == 2) {
				pointed = goto_value;
			} else {
				/* simple instuction */
				if (dump)
					printf("\n");
				pointed = 0;
				continue;
			}

			if (show_debug)
				printf("(pointed index: %x)", pointed);
			if (detect_labels && pointed > 0 && pointed < length) {
				if (labels[pointed] == 0) {
					labels[pointed] = next_label++;
					if (inst_is_sub(inst))
						labels_is_subcalled[pointed]++;
				}
			}
			if (dump) {
				if (instr_is_condition(inst)) {
					printf("\n");
					if (show_addr)
						printf("   ");
					if (pointed > 0)
						printf("\tGOYES");
					else
						printf("\tRTNYES\n");
				}

				if (pointed > 0) {
					if (pointed < length &&
					    labels[pointed] > 0) {
						if (show_addr)
							printf(" LABEL%d (%x)\n",
							       labels[pointed],
							       pointed);
						else
							printf(" LABEL%d\n",
							       labels[pointed]);
					} else {
						subroutine = get_subr(goto_value);
						if (subroutine == NULL)
							printf(" 0x%05x\n", goto_value);
						else
							show_subr(subroutine);
					}
				}
			}
		}
		if (!instruction_processed) {
			if (dump)
				printf("Unknow command starting by %01lX\n",
				       read_int(&q, 1));
			read_int(&q, 1);
		}
	}
}

int asm_decode(struct quartet *q, int length, int show_debug)
{
	int *labels;
	int *labels_is_subcalled;

	labels = calloc(sizeof(int), length);
	if (labels == NULL) {
		printf("label allocation error\n");
		return -ENOMEM;
	}
	labels_is_subcalled = calloc(sizeof(int), length);
	if (labels_is_subcalled == NULL) {
		printf("label allocation error\n");
		free(labels);
		return -ENOMEM;
	}
	browse_instructions(q, length, labels, labels_is_subcalled,
			    1, 0, 0, show_debug);
	browse_instructions(q, length, labels, labels_is_subcalled,
			    0, 1, 0, show_debug);

	free(labels);
	free(labels_is_subcalled);

	return 0;
}
