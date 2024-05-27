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
#include <string.h>

#include "file.h"
#include "hptypes.h"
#include "asmencode.h"

int main(int argc, char *argv[])
{
	int ret;
	char *file_in;
	char *file_out;
	struct quartet *q;
	unsigned char *buffer;
	size_t buffer_size;
	int q_size;
	int generated_size;
	int show_debug = 0;

	if (argc < 3) {
		printf("enter filenames <in> <out>\n");
		return 0;
	}
	file_in = argv[1];
	file_out = argv[2];
	if (argc > 3) {
		if (!strcmp(argv[3], "-d")) {
			show_debug = 1;
		} else {
			printf("unknown option '%s'\n", argv[3]);
			return -1;
		}
	}

	if (file_out[0] == '-') {
		printf("invalid out file name '%s'\n", file_out);
		return -1;
	}

	ret = load_text_file(file_in, &buffer, &buffer_size);
	if (ret) {
		printf("Can't read input file %s\n", file_in);
		return -1;
	}
	generated_size = asm_encode(buffer, buffer_size, &q, &q_size,
				    show_debug);
	if (generated_size < 0) {
		printf("Can't create object\n");
		free(buffer);
		return -1;
	}
	free(buffer);

	/* for debug purpose */
	show_object(q, generated_size, 2);

	ret = save_q_to_file(file_out, q, generated_size);
	if (ret) {
		printf("Can't write %s\n", file_out);
		free(buffer);
		free(q);
		return -1;
	}

	printf("saved to file %s\n", file_out);
	free(q);

	return 0;
}
