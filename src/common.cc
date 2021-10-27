/*  This file is part of nvlax.

    nvlax is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    THIS SOFTWARE IS PROVIDED 'AS-IS', WITHOUT ANY EXPRESS
    OR IMPLIED WARRANTY. IN NO EVENT WILL THE AUTHORS BE HELD
    LIABLE FOR ANY DAMAGES ARISING FROM THE USE OF THIS SOFTWARE.  */

#include <getopt.h>
#include <iostream>

#include "common.h"

bool
parse_args (int argc,
            char **argv,
            std::string_view &out_input,
            std::string_view &out_output)
{
    while (true) {
        switch (getopt(argc, argv, "i:o:h")) {
            case 'i':
                out_input = optarg;
                continue;
            case 'o':
                out_output = optarg;
                continue;
            case '?':
            case 'h':
            default :
                std::cout << "Usage: " << app_name << "-i '/path/to/" << lib_name << "' -o 'output.so'\n";
                break;
            case -1:
                break;
        }
        break;
    }

    bool success = true;

    if (out_input.empty()) {
        std::cerr << "Missing argument: input\n";
        success = false;
    }

    if (out_output.empty()) {
        std::cerr << "Missing argument: output\n";
        success = false;
    }

    if (!success) {
        std::cerr << "See '" << app_name << " -h'\n";
    }

    return success;
}
