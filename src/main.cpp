// Built-ins
#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <cstring>

// External libraries
#include <curl/curl.h>
#include "sha1/sha1.h"

using namespace std;

string url = "https://api.pwnedpasswords.com/range/";

size_t writeFunction(void *ptr, size_t size, size_t nmemb, string* data) {
    data->append((char*) ptr, size * nmemb);
    return size * nmemb;
}
vector<string> splitString(const string& str, const char _char)
{
    vector<string> tokens;
 
    string::size_type pos = 0;
    string::size_type prev = 0;
    while ((pos = str.find(_char, prev)) != string::npos) {
        tokens.push_back(str.substr(prev, pos - prev));
        prev = pos + 1;
    }
    tokens.push_back(str.substr(prev));
 
    return tokens;
}

string request(string url, string hash) {
    string response;
    auto curl = curl_easy_init();

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_0);
    curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
    curl_easy_setopt(curl, CURLOPT_FORBID_REUSE, 1L); 

    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &writeFunction);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 0L); // Disable debug printing

    curl_easy_perform(curl);
    curl_easy_cleanup(curl);

    char* effective_url;
    long response_code;
    double elapsed;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
    curl_easy_getinfo(curl, CURLINFO_TOTAL_TIME, &elapsed);
    curl_easy_getinfo(curl, CURLINFO_EFFECTIVE_URL, &effective_url);

    return response;
}

// Constants
int HASH_SIZE = 40;

int main() {
    cout << "Enter password: ";
    string line;
    getline(cin, line);;

    const char* str = line.c_str();

    sha1::sha1_t sha1;

    sha1.process(str, strlen(str));

    unsigned char sig[HASH_SIZE];

    sha1.finish(sig);

    char hashBuffer[HASH_SIZE];

    sha1::sig_to_string(sig, hashBuffer);

    // Uppercase
    for(int i=0;i<strlen(hashBuffer);i++){
        hashBuffer[i] = toupper(hashBuffer[i]);
    }

    string hash = string(hashBuffer);

    string subbedHash = hash.substr(0,5);
    string hashLeft = hash.substr(5,hash.size() - 5);

    string response = request(url + subbedHash, subbedHash);

    vector<string> hashes = splitString(response, '\n');

    // Loop through every hash returned
    for (unsigned int i = 0; i < hashes.size(); i++) {
        string line = hashes[i];

        vector<string> components = splitString(line, ':');
        string hash = components[0];

        if (hash == hashLeft) {
            // Oh noes! Our password has been exposed!! (kill me)
            stringstream temp;
            temp << components[1];
            int appearances;
            temp >> appearances;

            cout << "Your password has been pwned " << appearances << " times!\n\n";

            main();
        }
    }

    cout << "Your password hasn't been pwned yet!\n\n";
    
    main();
}