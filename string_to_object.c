/*
This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>. 
*/

#include <stdio.h>
#include <stdlib.h>

#include "file.h"
#include "hptypes.h"

int main(int argc, char *argv[])
{
	int ret;
	char *file_in;
	char *file_out;
	struct quartet *q;
	unsigned char *buffer;
	size_t buffer_size;
	int q_size;

	if (argc < 3) {
		printf("enter filenames <in> <out>\n");
		return 0;
	}
	file_in = argv[1];
	file_out = argv[2];

	ret = load_text_file(file_in, &buffer, &buffer_size);
	if (ret) {
		printf("Can't read input file %s\n", file_in);
		return -1;
	}
	ret = string_to_object(buffer, buffer_size, &q, &q_size);
	if (ret) {
		printf("Can't create object\n");
		free(buffer);
		return -1;
	}
	free(buffer);

	show_object(q, q_size, 1);

	ret = save_q_to_file(file_out, q, q_size);
	if (ret) {
		printf("Can't write %s\n", file_out);
		free(buffer);
		free(q);
		return -1;
	}
	free(q);

	return 0;
}
