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

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include "hptypes.h"
#include "asmdefs.h"
#include "asmencode.h"
#include "subroutine.h"

static char hexlist[] = "0123456789ABCDEF";

/* 128K is much enough, and struct array size is not big on PC */
/* only adresses where instruction start will be used */
#define MAX_INST_NB (128 * 1024)

/* array match index in asm code, use only ones where a command start */
struct encoded_inst {
	const struct instr *definition;
	int real_size;
	long value;
	int value_size;
	int field;
	char label[16]; /* empty if no referenced */
	int label_line; /* can be different of instr line */
	int label_references;
	int is_jump;
	char target_label[16]; /* empty if no target */
	int origin_line;
};

int read_hex_val(char *line, long *value)
{
	if (sscanf((char *)line, "0x%lx", value) == 1)
		return 0;
	if (sscanf((char *)line, "%lx", value) == 1)
		return 0;
	if (sscanf((char *)line, "$%lx", value) == 1)
		return 0;
	if (sscanf((char *)line, "#%lx", value) == 1)
		return 0;

	return  -1;
}

/* for same than previous but for single quartet value */
/* can be sometime int value */
int read_x_val(char *line, long *value)
{
	if (sscanf((char *)line, "0x%lx", value) == 1)
		return 0;
	if (sscanf((char *)line, "$%lx", value) == 1)
		return 0;
	/* if syntax is '1x' must be set as an integer */
	if (strlen((char *)line) > 1 && sscanf((char *)line, "%ld", value) == 1)
		return 0;
	if (sscanf((char *)line, "%lx", value) == 1)
		return 0;

	return  -1;
}

int read_field_index(char *line, char field[33], int *value)
{
	int i;
	char *name = line;

	while (*name == ' ')
		name++;

	for (i = 0x0; i < 0x10; i++) {
		if (field[i * 2] == ' ') {
			if (field[i * 2 + 1] == *name) {
				*value = i;
				return 0;
			}
		} else {
			if (field[i * 2] == *name &&
			    field[i * 2 + 1] == *(name + 1)) {
				*value = i;
				return 0;
			}
		}
	}

	return -1;
}

int instr_match_string(const struct instr *instr, unsigned char *name,
		       int *match_size)
{
	char *ref_ptr, *buf_ptr;

	ref_ptr = &instr->name[0];
	buf_ptr = (char *)&name[0];
	*match_size = 0;

	while (*buf_ptr != '\0') {
		/* if not a space on ref, ignore spaces on buf */
		if (*ref_ptr != ' ') {
			while (*buf_ptr == ' ' || *buf_ptr == '\t') {
				(*match_size)++;
				buf_ptr++;
			}
		} else if (*buf_ptr == '\t') {
			*buf_ptr = ' '; /* \t is ok for space */
		}

		if (*ref_ptr == '#' &&
		    *buf_ptr == '!' && *(buf_ptr + 1) == '=') {
			buf_ptr++;
		} else if ((*buf_ptr != *ref_ptr) &&
		    !((*ref_ptr == '$') && !strncmp(buf_ptr, "CON", 3)) &&
			   !((*ref_ptr == '$') && strchr(hexlist, *buf_ptr))) {
			return 0;
		}

		buf_ptr++;
		ref_ptr++;
		(*match_size)++;

		/* if last char of ref is $, match size is allready ok */
		if (*ref_ptr == '$')
			return 1;

		/* compared all of ref successfully */
		if (*ref_ptr == '\0' && (*buf_ptr == '\0' ||
					 strchr(hexlist, *buf_ptr) ||
					 *buf_ptr == '(' ||
					 *buf_ptr == '#' ||
					 *buf_ptr == ' ' ||
					 *buf_ptr == '\t' ||
					 *buf_ptr == '\r' ||
					 *buf_ptr == '\n'))
			return 1;
	}

	return 0;
}

int encode_instr(unsigned char *line, int show_debug,
		 const struct instr *instr, struct encoded_inst *enc_inst,
		 int addr, int inst_line)
{
	int i;
	int size;
	char *tmp;
	char con_buffer[16];
	char con_field;
	char con_val;
	char *params;
	char *field_params;
	int match_size;
	char *goyes_label;
	int decimal_present;
	int field_present;

	if (!instr_match_string(instr, line, &match_size))
		return -1;

	line += match_size;
	while (*line == ' ' || *line == '\t')
		line++;

	goyes_label = strstr((char *)line, "GOYES");
	if (goyes_label != NULL)
		goyes_label += strlen("GOYES");
	if (goyes_label == NULL) {
		goyes_label = strstr((char *)line, "RTNYES");
	}
	if (goyes_label != NULL) {
		while (*goyes_label == ' ' || *goyes_label == '\t')
			goyes_label++;
	}
	if (sscanf((char *)line, "CON %c,%hhx", &con_field, &con_val) == 2) {
		sprintf((char *)con_buffer, "%x %c", con_val, con_field);
		params = con_buffer;
	} else {
		params = (char *)line;
	}

	field_params = params;

	decimal_present = 0;
	field_present = 0;
	for (i = 0; i < instr->sl; i++) {
		if (instr->v[i] == FLAG_DEC)
			decimal_present = 1;
		if (instr->v[i] == FLAG_A_FIELD ||
		    instr->v[i] == FLAG_B_FIELD ||
		    instr->v[i] == FLAG_F_FIELD)
			field_present = 1;
	}
	/* if decimal val is present, the field, if present, will be on second */
	if (decimal_present) {
		/* so, forward pointer */
		while(*field_params != ' ' &&
		      *field_params != '\t' &&
		      *field_params != '\0')
			field_params++;
		while ((*field_params == ' ' ||
			*field_params == '\t') &&
		       *field_params != '\0')
			field_params++;
	}

	/* if field present in flags, need to be present in src */
	if (field_present && *field_params == '\0')
		return -1;

	enc_inst->real_size = 0;
	/* on size, remove 1 when flag is on a quartet definition */
	for (i = 0; i < instr->sl; i++) {
		/* default is 1 read size for 1 */
		enc_inst->real_size++;
		/* process only special fields */
		switch (instr->v[i]) {
		case FLAG_ADDR2:
			read_hex_val(params, &enc_inst->value) ;
			/* must be a label */
			enc_inst->is_jump = 1;
			enc_inst->real_size += 2 - 1;
			break;
		case FLAG_PTR2:
			if (read_hex_val(params, &enc_inst->value) < 0)
				return -1;
			enc_inst->real_size += 2 - 1;
			break;
		case FLAG_ADDR3:
		case FLAG_ADDR3SUB:
			read_hex_val(params, &enc_inst->value);
			enc_inst->is_jump = 1;
			enc_inst->real_size += 3 - 1;
			break;
		case FLAG_PTR3:
			if (read_hex_val(params, &enc_inst->value) < 0)
				return -1;
			enc_inst->real_size += 3 - 1;
			break;
		case FLAG_ADDR4:
			read_hex_val(params, &enc_inst->value);
			enc_inst->is_jump = 1;
			enc_inst->real_size += 4 - 1;
			break;
		case FLAG_PTR4:
			if (read_hex_val(params, &enc_inst->value) < 0)
				return -1;
			enc_inst->real_size += 4 - 1;
			break;
		case FLAG_ADDR5:
			read_hex_val(params, &enc_inst->value);
			enc_inst->is_jump = 1;
			enc_inst->real_size += 5 - 1;
			break;
		case FLAG_PTR5:
			if (read_hex_val(params, &enc_inst->value) < 0)
				return -1;
			enc_inst->real_size += 5 - 1;
			break;
		case FLAG_VAR:
			size = 0;
			if (*params == '$' || *params == '#')
				params++;
			if (*params == '0' && *(params + 1) == '#')
				params += 2;
			tmp = params;
			/* cut after hexa values */
			while(strchr(hexlist, *tmp))
				tmp++;
			tmp = params;
			/* first try on 2 digits -> is decimal */
			if (sscanf(tmp, "(%2d)", &size) == 1 ||
			    sscanf(tmp, "(%1x)", &size) == 1) {
				tmp = strchr(params, ')');
				if (tmp != NULL)
					params = tmp + 1;
			} else {
				/* use as it, size is char nb */
				tmp = params;
				while(strchr(hexlist, *tmp) && *tmp != '\0')
					tmp++;
				size = tmp - params;
			}
			while (*params == ' ')
				params++;
			if (read_hex_val(params, &enc_inst->value) < 0)
				return -1;
			enc_inst->value_size = size;
			enc_inst->real_size += size;
			break;
		case FLAG_DEC:
			/* is at end */
			if (sscanf(params, "%ld ", &enc_inst->value) < 1)
				return -1;
		case FLAG_N:
		case FLAG_N1:
			if (read_x_val(params, &enc_inst->value) < 0)
				return -1;
			break;
		case FLAG_X1:
			if (sscanf(params, "%2ld", &enc_inst->value) < 1 &&
			    sscanf(params, "%1lx", &enc_inst->value) < 1)
				return -1;
			enc_inst->value -= 1;
			break;
		case FLAG_A_FIELD:
			if (read_field_index(field_params, field_a,
					     &enc_inst->field) < 0)
				return -1;
			break;
		case FLAG_B_FIELD:
			if (read_field_index(field_params, field_b,
					     &enc_inst->field) < 0)
				return -1;
			break;
		case FLAG_F_FIELD:
			if (read_field_index(field_params, field_f,
					     &enc_inst->field) < 0)
				return -1;
			break;
		case FLAG_BIT_INDEX:
			if (read_hex_val(params, &enc_inst->value) < 0)
				return -1;
			break;
		default:
			break;
		}
	}
	if (enc_inst->is_jump == 1) {
		if (goyes_label != NULL)
			params = goyes_label;
		strncpy(enc_inst->target_label, (char *)params, 15);
		enc_inst->target_label[15] = '\0';
		if (show_debug)
			printf("Jump to label '%s' \n", enc_inst->target_label);
		for (i = 0; i < 16; i++)
			if (enc_inst->target_label[i] == ' ' ||
			    enc_inst->target_label[i] == '\t'||
			    enc_inst->target_label[i] == ';')
				enc_inst->target_label[i] = '\0';
	}
	enc_inst->definition = instr;
	enc_inst->origin_line = inst_line;

	return 0;
}

int is_comment(char c)
{
	if (c == '%' || c == ';' || c == '!')
		return 1;
	return 0;
}

int is_line_to_ignore(char *line)
{
	if (!strncmp((char *)line, "Code", 4) ||
	    !strncmp((char *)line, "CODE", 4))
		return 1;
	if (!strncmp((char *)line, "COERCE", 4))
		return 1;
	if (!strncmp((char *)line, "::", 4))
		return 1;

	/* ignore comments */
	if (is_comment(*line))
		return 1;

	if (strstr(line, "equ")) {
		printf("no yet support for variable ignore '%s'\n",
		       line);
		return 1;
	}

	return 0;
}

int asm_source_process(unsigned char *start,
		       struct encoded_inst *enc_inst,
		       int show_debug)
{
	int i, j;
	const struct instr *instr;
	unsigned char *line;
	unsigned char *ptr;
	unsigned char *next_line = start;
	unsigned char *second_part;
	int instr_size;
	int instruction_processed = 0;
	int something_else_on_line = 0;
	int processing_second_part = 0;
	int certified_label;
	int addr = 0;
	int inst_line;
	int current_line;
	int is_on_comment;

	current_line = 0;
	while (*next_line != '\0') {
		processing_second_part = 0;
		if (something_else_on_line) {
			processing_second_part = 1;
			something_else_on_line = 0;
			ptr = second_part;
		} else {
			ptr = next_line;
			current_line++;
		}

		line = ptr;

		if (!processing_second_part) {
			/* go to end of line */
			while(*ptr != '\r' && *ptr != '\n' && *ptr != '\0')
				ptr++;
			/* compute next_line start */
			if (*ptr == '\r')
				*(ptr++) = '\0';
			if (*ptr == '\n')
				*(ptr++) = '\0';
			next_line = ptr;
		}

		/* pass any spaces before */
		while(*line == ' ' || *line == '\t')
			line++;

		/* ignore some type of lines */
		if (is_line_to_ignore((char *)line))
			continue;

		/* instruction */
		while (*line == ' ' || *line == '\t')
			line++;

		/* @ indicates end of code */
		if (*line == '@' &&
		    (*(line + 1) == '\n' || *(line + 1) == '\r'))
			return 0;

		inst_line = current_line;
		/* special case: conditional, GOYES or RTNYES on next line */
		if (*line == '?') {
			/* remove comments */
			is_on_comment = 0;
			for (ptr = line; ptr < next_line &&
				     *ptr != '\r' &&
				     *ptr != '\n' &&
				     *ptr != '\0'; ptr++) {
				if (is_comment(*ptr))
					is_on_comment = 1;
				if (is_on_comment)
					*ptr = ' ';
			}
			/* stick next line */
			for (ptr = line; ptr < next_line; ptr++)
				if (*ptr == '\r' || *ptr == '\n' || *ptr == '\0')
					*ptr = ' ';

			/* cut line and move ptr to next */
			while(*ptr != '\r' && *ptr != '\n' && *ptr != '\0')
				ptr++;
			next_line = ptr;
			while(*ptr == '\r' || *ptr == '\n') {
				*ptr = '\0';
				ptr++;
				next_line++;
			}

			if (show_debug)
				printf("conditional case, line merged '%s'\n",
				       line);
			current_line++;
		}
		if (*line == '\0')
			continue;

		if (show_debug && processing_second_part)
			printf("line %d as 2nd part  %s (addr %x)\n",
			       current_line,
			       line, addr);

		/* search if available */
		instruction_processed = 0;
		for (j = 0; j < instructions_nb &&
			     instruction_processed == 0; j++) {
			instr = &instructions[j];
			if(encode_instr(line, show_debug,
					instr, &enc_inst[addr],
					addr, inst_line) < 0)
				continue;
			instruction_processed = 1;
			instr_size = enc_inst[addr].real_size;
			if (show_debug)
				printf("line %d '%s' detected '%s': '%s' (addr %x) "
				       "size %d value %lx field param %x\n",
				       inst_line, line,
				       instr->name,
				       enc_inst[addr].definition->name,
				       addr, instr_size,
				       enc_inst[addr].value,
				       enc_inst[addr].field);
			addr += instr_size;
		}
		/* look forward if not already looking forward on a line */
		if (!instruction_processed && !processing_second_part) {
			/* use it as a LABEL */
			certified_label = 0;
			if (*line == '*') {
				certified_label = 1;
				line++;
			}

			/* consider as a label, and cut line */
			ptr = line;
			while (ptr < next_line && something_else_on_line == 0) {
				if (*ptr == ' ' || *ptr == '\t') {
					*ptr = '\0';
					second_part = ptr + 1;
					something_else_on_line = 1;
				}
				ptr++;
			}

			if (!certified_label)
				printf("line %d: not a known instruction: '%s', "
				       "use as label (for addr %x)\n",
				       inst_line, line, addr);
			if (enc_inst[addr].label[0] != '\0') {
				printf("Unknown instruction '%s' is used as a "
				       "label, but label %s allready present, "
				       "change one as comment\n",
				       line, enc_inst[addr].label);
				return -1;
			}

			if (something_else_on_line &&
			    *ptr != '\0' && *ptr != '\r' && *ptr != '\n' &&
			    ptr + 4 < next_line) {
				second_part = ptr;
				if (show_debug)
					printf("instr %s: something else "
					       "on line: '%s'\n",
					       line, second_part);
			}

			strncpy(enc_inst[addr].label, (char *)line, 15);
			enc_inst[addr].label[15] = '\0';
			enc_inst[addr].label_line = inst_line;
			enc_inst[addr].origin_line = inst_line;
			for (i = 0; i < 16; i++)
				if (enc_inst[addr].label[i] == ' ')
					enc_inst[addr].label[i] = '\0';
			if (certified_label)
				continue;

			continue;
		}
		something_else_on_line = 0;

	}

	return 0;
}

int search_label(struct encoded_inst *enc_instr, char *name,
		 int show_debug)
{
	int addr = 0;

	/* First search on local labels */
	while(enc_instr[addr].real_size > 0) {
		if (enc_instr[addr].label[0] != '\0' &&
		    !strcasecmp(enc_instr[addr].label, name)) {
			if (show_debug)
				printf(" line %d, '%s' ",
				       enc_instr[addr].origin_line,
				       enc_instr[addr].label);
			enc_instr[addr].label_references++;
			return addr;
		}
		addr += enc_instr[addr].real_size;
	}

	/* Might be a subroutine */
	addr = get_subr_addr(name);
	if (addr != 0)
		return addr;

	return -1;
}

int dump_missing_labels(struct encoded_inst *enc_instr)
{
	int missing_nb = 0;
	int addr = 0;

	while(enc_instr[addr].real_size > 0) {
		if (enc_instr[addr].label[0] != '\0' &&
		    enc_instr[addr].label_references == 0) {
			printf("addr %x label '%s' line %d not recognized as "
			       "an instruction and not referenced as "
			       "a pointed label. Maybe a comment ?\n",
			       addr,
			       enc_instr[addr].label,
			       enc_instr[addr].label_line);
			missing_nb++;
		}
		addr += enc_instr[addr].real_size;
	}

	return missing_nb;
}

int asm_instructions_to_quartet(struct encoded_inst *enc_instr,
				struct quartet **q, int qlength,
				int show_debug)
{
	int addr = 0;
	int computed_addr;
	int label_addr;
	int is_rtnyes;
	int i;
	struct encoded_inst *inst;
	const struct instr *def;
	struct quartet *ptr = *q;
	long value;
	int value_size_to_write;
	int related_value;

	while (enc_instr[addr].real_size > 0) {
		if (addr >= MAX_INST_NB) {
			printf("something wen wrong in instructions\n");
			return -1;
		}
		inst = &enc_instr[addr];
		def = inst->definition;
		if (def == NULL) {
			printf("no associated instruction "
			       "(line %d, addr %d)\n",
			       inst->origin_line, addr);
			return -1;
		}
		if (show_debug) {
			if (inst->label[0] != '\0')
				printf("*LABEL: %s (line %d)\n",
				       inst->label, inst->label_line);
			printf("%x (line %d)\t%s value %lx (size %d)%s %s",
			       addr, inst->origin_line, def->name,
			       inst->value, inst->value_size,
			       inst->is_jump ? " jump to" : "",
			       inst->target_label);
		}
		if (inst->is_jump) {
			label_addr = search_label(enc_instr,
						  inst->target_label,
						  show_debug);
			is_rtnyes = 0;
			if (label_addr == -1) {
				if (inst->value == 0) {
					if (def->name[0] != '?') {
						printf("error: line %d, %s did "
						       "not find label %s and "
						       "value is 0\n",
						       inst->origin_line,
						       def->name,
						       inst->target_label);
						return -1;
					}
					/* conditional jump and no goyes */
					/* 00 for rtnyes */
					is_rtnyes = 1;
				} else if (sscanf(inst->target_label, "%x",
						  &label_addr) < 1) {
					printf("%s: no label, and no value",
					       inst->target_label);
					return -1;
				}
			} else {
				if (show_debug)
					printf("addr %x ", label_addr);
			}
			value = label_addr;
		} else {
			/* not a jump */
			value = inst->value;
		}

		/* add quartets */
		value_size_to_write = 0;
		related_value = 0;
		for (i = 0; i < def->sl; i++) {
			if (def->v[i] < 0x10) {
				write_int(&ptr, def->v[i], 1);
				continue;
			}
			switch (def->v[i]) {
			case FLAG_ADDR2:
				related_value = addr + i;
				value_size_to_write = 2;
				break;
			case FLAG_ADDR3:
				related_value = addr + i;
				value_size_to_write = 3;
				break;
			case FLAG_ADDR3SUB:
				related_value = addr + i + 3;
				value_size_to_write = 3;
				break;
			case FLAG_ADDR4:
				value_size_to_write = 4;
				break;
			case FLAG_ADDR5:
				value_size_to_write = 5;
				break;
			case FLAG_PTR2:
				value_size_to_write = 2;
				break;
			case FLAG_PTR4:
				value_size_to_write = 4;
				break;
			case FLAG_PTR5:
				value_size_to_write = 5;
				break;
			case FLAG_VAR:
				write_int(&ptr, inst->value_size - 1, 1);
				value_size_to_write = inst->value_size;
			break;
			case FLAG_N:
				if (show_debug)
					printf("param is %ld ", inst->value);
				write_int(&ptr, inst->value, 1);
				break;
			case FLAG_DEC:
			case FLAG_N1:
				if (show_debug)
					printf("param is %ld - 1 ", inst->value);
				write_int(&ptr, inst->value - 1, 1);
				break;
			case FLAG_X1:
				if (show_debug)
					printf("param + 1 is %ld ", inst->value);
				write_int(&ptr, inst->value, 1);
				break;
			case FLAG_A_FIELD:
			case FLAG_B_FIELD:
			case FLAG_F_FIELD:
				if (show_debug)
					printf("(field %d) ", inst->field);
				write_int(&ptr, inst->field, 1);
				break;
			case FLAG_BIT_INDEX:
				if (show_debug)
					printf("(value %ld) ", inst->value);
				write_int(&ptr, inst->value, 1);
				break;
			default:
				printf("unknown flag %x ", def->v[i]);
				return -1;
				break;
			}
		}
		if (!is_rtnyes && related_value > 0) {
			if (show_debug)
				printf("to %x = %lx ", related_value,
				       value - related_value);
			value -= related_value;
		}
		if (is_rtnyes && value < 0)
			value = 0;

		write_int(&ptr, value, value_size_to_write);

		if (show_debug) {
			printf("-> [");
			for (i = 0; i < inst->real_size; i++)
				printf("%X", qvalue(*q, addr + i));
			printf("]\n");
		}
		addr += inst->real_size;
		computed_addr = qposition(*q, ptr);
		if (computed_addr != addr) {
			printf("encode error: for instr '%s' at line %d: "
			       "position is %x instead of %x\n",
			       def->name, inst->origin_line,
			       computed_addr, addr);
			return -1;
		}
		/* check if next instr will fit in big allowed size */
		if (addr + 16 > qlength) {
			printf("generated code seems too big\n");
			return -1;
		}
	}
	computed_addr = qposition(*q, ptr);
	printf("Total code size: %d\n", computed_addr);
	dump_missing_labels(enc_instr);

	return computed_addr;
}


int asm_encode(unsigned char *buffer, size_t buffer_size,
	       struct quartet **q, int *qlength,
	       int show_debug)
{
	int ret;
	struct encoded_inst *enc_instr;
	struct quartet *ptr;
	int generated_size;

	enc_instr = calloc(sizeof(struct encoded_inst), MAX_INST_NB);
	if (enc_instr == NULL) {
		printf("enc instr allocation error\n");
		return -ENOMEM;
	}
	/* 16 bytes for each inst is large, and needs only 14MB on PC */
	*qlength = 16 * MAX_INST_NB;
	*q = alloc_q(*qlength);
	if (*q == NULL) {
		printf("q allocation error\n");
		free(enc_instr);
		return -ENOMEM;
	}

	if (show_debug)
		printf("\n\n\n === PARSE SOURCES AS INSTRUCTIONS ===\n\n\n");

	ret = asm_source_process(buffer, enc_instr, show_debug);
	if (ret < 0) {
		printf("Failed to process source\n");
		free(enc_instr);
		free(*q);
		return ret;
	}

	if (show_debug)
		printf("\n\n\n === DUMP INSTRUCTIONS AS QUARTETS ===\n\n\n");

	/* ignore 10 first quartets reserved for header */
	ptr = *q;
	write_int(&ptr, 0, 10);
	generated_size = asm_instructions_to_quartet(enc_instr,
						     &ptr,
						     (*qlength) - 10,
						     show_debug);
	if (generated_size < 0) {
		printf("Failed to generate quartets\n");
		free(enc_instr);
		free(*q);
		return -1;
	}
	/* update header */
	ptr = *q;
	write_int(&ptr, 0x02DCC, 5);
	write_int(&ptr, generated_size + 5, 5);

	free(enc_instr);

	return generated_size + 10;
}
