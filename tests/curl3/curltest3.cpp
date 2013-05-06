/**
 * @file curltest3.cpp
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
#include <curl/curl.h>
#include <string>
#include <json/value.h>
#include <json/reader.h>


static size_t string_store(void *ptr, size_t size, size_t nmemb, void *stream)
{
    ((std::string*)stream)->append((const char*)ptr, size*nmemb);
    return size*nmemb;
}


int main(int argc, char* argv[])
{
    CURL *curl;
    CURLcode res;
    std::string url;
    struct curl_slist* headers = NULL;
    std::string json_data;

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

        Json::Value root;   // will contains the root value after parsing.
        Json::Reader reader;
        bool parsingSuccessful = reader.parse(json_data, root);
        if (!parsingSuccessful)
        {
            // report to the user the failure and their locations in the document.
            printf("Failed to parse JSON:\n %s\n", reader.getFormatedErrorMessages().c_str());
            return 1;
        }

        // Get the value of the member of root named 'digest'.
        std::string digest = root.get("digest", "" ).asString();

        printf("digest: %s\n", digest.c_str());
    }
    return 0;
}

