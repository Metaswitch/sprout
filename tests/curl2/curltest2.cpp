/**
 * @file curltest2.cpp
 *
 * Project Clearwater - IMS in the Cloud
 * Copyright (C) 2013  Metaswitch Networks Ltd
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version, along with the "Special Exception" for use of
 * the program along with SSL, set forth below. This program is distributed
 * in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR
 * A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details. You should have received a copy of the GNU General Public
 * License along with this program.  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 * The author can be reached by email at clearwater@metaswitch.com or by
 * post at Metaswitch Networks Ltd, 100 Church St, Enfield EN2 6BQ, UK
 *
 * Special Exception
 * Metaswitch Networks Ltd  grants you permission to copy, modify,
 * propagate, and distribute a work formed by combining OpenSSL with The
 * Software, or a work derivative of such a combination, even if such
 * copying, modification, propagation, or distribution would otherwise
 * violate the terms of the GPL. You must comply with the GPL in all
 * respects for all of the code used other than OpenSSL.
 * "OpenSSL" means OpenSSL toolkit software distributed by the OpenSSL
 * Project and licensed under the OpenSSL Licenses, or a work based on such
 * software and licensed under the OpenSSL Licenses.
 * "OpenSSL Licenses" means the OpenSSL License and Original SSLeay License
 * under which the OpenSSL Project distributes the OpenSSL toolkit software,
 * as those licenses appear in the file LICENSE-OPENSSL.
 */

#include <stdio.h>
#include <curl/curl.h>
#include <string.h>
#include <string>
extern "C" {
#include <yajl/yajl_tree.h>
}


static size_t string_store(void *ptr, size_t size, size_t nmemb, void *stream)
{
    ((std::string*)stream)->append((const char*)ptr, size*nmemb);
    return size*nmemb;
}


yajl_val tree_get(yajl_val n, const char ** path, yajl_type type)
{
    if (!path) return NULL;
    if (n->type != yajl_t_object) return NULL;
    while (n && *path) {
        yajl_val v;
        unsigned int i;

        for (i = 0; i < n->u.object.len; i++)
        {
            if (!strcmp(*path, n->u.object.keys[i]))
            {
                v = n->u.object.values[i];
                break;
            }
        }
        if (i == n->u.object.len) return NULL;
        path++;
        n = v;
    }
    if (n && type != yajl_t_any && type != n->type) n = NULL;

    return n;
}


static void print_yajl_value(yajl_val value, int indent)
{
    yajl_val_s* val_s = (yajl_val_s*)value;
    int i;

    switch (value->type)
    {
      case yajl_t_string: 	
        printf("%s\n", val_s->u.string);
        break;

      case yajl_t_number: 	
        printf("%s\n", val_s->u.number.r);
        break;

      case yajl_t_true: 	
        printf("true\n");
        break;

      case yajl_t_false: 	
        printf("false\n");
        break;

      case yajl_t_null: 	
        printf("null\n");
        break;

      case yajl_t_object: 	
        printf("Object {\n", indent, "");
        for (i = 0; i < val_s->u.object.len; ++i)
        {
            printf("%.*s%s: ", indent + 2, "", val_s->u.object.keys[i]);
            print_yajl_value(val_s->u.object.values[i], indent + 2);
        }
        printf("%.*s}\n", indent, "");
        break;

      case yajl_t_array: 	
        printf("Array [\n", indent, "");
        for (i = 0; i < val_s->u.array.len; ++i)
        {
            print_yajl_value(val_s->u.array.values[i], indent + 2);
        }
        printf("%.*s]\n", indent, "");
        break;
    }
}


static void walk_yajl_tree(yajl_val node)
{
    print_yajl_value(node, 0);
}


int main(int argc, char* argv[])
{
    CURL *curl;
    CURLcode res;
    std::string url;
    struct curl_slist* headers = NULL;
    std::string json_data;
    yajl_val node;
    char errbuf[1024];

    if (argc != 3)
    {
        fprintf(stderr, "Usage: curltest1 <private user identity> <public user identity>\n");
        return 1;
    }

    // Construct the URL for the query.
    url = "http://184.169.170.147/1/credentials/" + std::string(argv[1]) + "/" + std::string(argv[2]) + "/digest";

    curl = curl_easy_init();
    if (curl != NULL)
    {
        // Set the URL.
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());

        // Add the headers.
        res = curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        if (res != CURLE_OK)
        {
            fprintf(stderr, "curl_easy_setopt(CURLOPT_HTTPHEADER) failed: %s\n", curl_easy_strerror(res));
        }

        // send all data to a function to store it as a string.
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, string_store);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &json_data);

        // Perform the request
        res = curl_easy_perform(curl);

        if (res != CURLE_OK)
        {
            fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
            return 1;
        }

        curl_easy_cleanup(curl);

        printf("%s\n", json_data.c_str());

        // Now parse the JSON.
        node = yajl_tree_parse((const char *)json_data.c_str(), errbuf, sizeof(errbuf));

        if (node == NULL)
        {
            fprintf(stderr, "JSON parse_error: %s\n", errbuf);
            return 1;
        }

        walk_yajl_tree(node);

        const char *path[] = { "digest", (const char *) NULL };
        yajl_val v = tree_get(node, path, yajl_t_any);
        if (v != NULL)
        {
            printf("digest: %s\n", YAJL_GET_STRING(v));
        }
        else
        {
            printf("failed to find digest\n");
        }

        yajl_tree_free(node);
    }
    return 0;
}

