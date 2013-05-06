/**
 * @file curltest4.cpp
 *
 * Copyright (C) 2013  Metaswitch Networks Ltd
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
 *
 * The author can be reached by email at clearwater@metaswitch.com or by post at
 * Metaswitch Networks Ltd, 100 Church St, Enfield EN2 6BQ, UK
 */

#include <stdio.h>
#include "hssconnection.h"

int main(int argc, char* argv[])
{
    if (argc != 3)
    {
        fprintf(stderr, "Usage: %s <private user identity> <public user identity>\n", argv[0]);
        return 1;
    }

    HSSConnection hss(std::string("184.169.170.147"));

    Json::Value* data = hss.get_digest_data(std::string(argv[1]), std::string(argv[2]));

    if (data == NULL)
    {
        fprintf(stderr, "Failed to look up user\n");
        return 1;
    }

    // Get the value of the member of root named 'digest'.
    std::string digest = data->get("digest", "" ).asString();

    printf("digest: %s\n", digest.c_str());

    delete data;

    return 0;
}

