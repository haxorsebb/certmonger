/*
 * Copyright (C) 2026 Red Hat, Inc.
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include <krb5.h>

#include "../../src/config.h"
#include "../../src/submit-u.h"
#include "../../src/submit-u.c"

int
main(int argc, char **argv)
{
    char *file_data = NULL;
    int result = 0;

    if (argc < 2){
        fprintf(stderr, "Usage: %s file1 [file]\n", argv[0]);
        return 1;
    }

    for(int i = 1; i < argc; i++){
        file_data = cm_submit_u_from_file(argv[i]);

        if (file_data == NULL){
            result = 1;
            continue;
        }

        free(file_data);
    }

    return result;
}