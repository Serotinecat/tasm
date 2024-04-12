/*
This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>. 
*/

#include "hptypes.h"

int load_file_as_q(char *file_name, struct quartet **q, int *q_size);
int load_file_as_buffer(char *file_name, unsigned char **b, size_t *size);
int load_text_file(char *file_name, unsigned char **b, size_t *size);
int save_q_to_file(char *file_name, struct quartet *q, int q_size);
