/*
This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>. 
*/

#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <errno.h>

#include "file.h"

int load_file_as_buffer(char *file_name, unsigned char **b, size_t *size)
{
	FILE *fp;
	size_t nb_read;
	struct stat st;
	char h[8];

	fp = fopen(file_name, "rb");
	if (!fp)
		return -EINVAL;

	nb_read = fread(h, 1, 8, fp);
	if (nb_read != 8) {
		fclose(fp);
		return -EINVAL;
	}

	/* at index 7, can differs, on mine is 'P' */
	if (h[0] != 'H' || h[1] != 'P' || h[2] != 'H' || h[3] != 'P' ||
	    h[4] != '4' || h[5] != '8' || h[6] != '-') {
		printf("invalid header\n");
		fclose(fp);
		return -EINVAL;
	}

	if (fstat(fileno(fp), &st) != 0) {
		fclose(fp);
		return -EINVAL;
	}
	*size = st.st_size - 8;

	*b = malloc(*size);
	if (*b == NULL) {
		fclose(fp);
		return -EINVAL;
	}

	nb_read = fread(*b, 1, *size, fp);
	if (nb_read != *size) {
		free(*b);
		fclose(fp);
		return -EINVAL;
	}

	fclose(fp);

	return 0;
}


int load_file_as_q(char *file_name, struct quartet **q, int *q_size)
{
	int ret;
	unsigned char *b;
	size_t b_size;

	ret = load_file_as_buffer(file_name, &b, &b_size);
	if (ret < 0)
		return ret;

	*q_size = 2 * b_size;
	*q = alloc_q(*q_size);
	if (*q == NULL) {
		free(b);
		return -ENOMEM;
	}
	ret = buffer_to_quartets(b, b_size, *q, *q_size);
	if (ret < 0) {
		free(b);
		return -ENOMEM;
	}

	free(b);

	return 0;
}

int load_text_file(char *file_name, unsigned char **b, size_t *size)
{
	FILE *fp;
	size_t nb_read;
	struct stat st;

	fp = fopen(file_name, "rb");
	if (!fp)
		return -EINVAL;
	if (fstat(fileno(fp), &st) != 0) {
		fclose(fp);
		return -EINVAL;
	}
	*size = st.st_size;

	*b = malloc(*size);
	if (*b == NULL) {
		fclose(fp);
		return -EINVAL;
	}

	nb_read = fread(*b, 1, *size, fp);
	if (nb_read != *size) {
		free(*b);
		fclose(fp);
		return -EINVAL;
	}

	fclose(fp);

	return 0;
}

int save_q_to_file(char *file_name, struct quartet *q, int q_size)
{
	FILE *fp;
	int ret;
	size_t buffer_size = (q_size + q_size % 2) / 2;
	unsigned char *buffer;
	char *header = "HPHP48-P";
	int header_size = 8;

	fp = fopen(file_name, "wb");
	if (!fp)
		return -EINVAL;

	if (fwrite(header, 1, header_size, fp) != header_size)
		printf("write failure\n");

	buffer = malloc(buffer_size);
	if (buffer == NULL) {
		fclose(fp);
		return -EINVAL;
	}
	ret = quartets_to_buffer(q, q_size, buffer, buffer_size);
	if (ret < 0) {
		fclose(fp);
		return -ENOMEM;
	}

	if (fwrite(buffer, 1, buffer_size, fp) != buffer_size)
		printf("warite failure\n");

	free(buffer);
	fclose(fp);

	return 0;
}
