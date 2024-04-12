/*
This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>. 
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "file.h"
#include "hptypes.h"

int main(int argc, char *argv[])
{
	int ret;
	char *file_name;
	struct quartet *q;
	int q_size;
	int show_debug = 0;

	if (argc < 2) {
		printf("enter filename\n");
		return 0;
	}
	file_name = argv[1];
	/* d for debug, x for quartet dump */
	if (argc > 2 && !strcmp(argv[2], "-d"))
		show_debug = 1;
	else if (argc > 2 && !strcmp(argv[2], "-x"))
		show_debug = 2;
	ret = load_file_as_q(file_name, &q, &q_size);
	if (ret) {
		printf("Can't read %s\n", file_name);
		return 0;
	}
	show_object(q, q_size, show_debug);
	free(q);

	return 0;
}
