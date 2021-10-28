/*  This file is part of nvlax.

    nvlax is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    THIS SOFTWARE IS PROVIDED 'AS-IS', WITHOUT ANY EXPRESS
    OR IMPLIED WARRANTY. IN NO EVENT WILL THE AUTHORS BE HELD
    LIABLE FOR ANY DAMAGES ARISING FROM THE USE OF THIS SOFTWARE.  */

#include <iostream>

#include <LIEF/ELF.hpp>
#include <Zydis/Zydis.h>
#include <ppk_assert.h>

#include "common.h"

using namespace LIEF::ELF;

const char *app_name = "nvlax_fbc";
const char *lib_name = "libnvidia-fbc.so.XXX";

int
main (int argc,
      char **argv)
{
    std::string_view input, output;
    if (!parse_args(argc, argv, input, output)) {
        return EXIT_FAILURE;
    }

    auto bin = Parser::parse(input.data());

    size_t offset;

    {
        auto s_rodata = bin->get_section(".rodata");
        offset = s_rodata.virtual_address() + s_rodata.search("This hardware does not support NvFBC");
    }

    bool found = false;

    {
        ZydisDecoder decoder;
        ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

        auto s_text = bin->get_section(".text");
        auto v_text_content = s_text.content();

        uint8_t *data = v_text_content.data();
        size_t length = v_text_content.size();

        // find the only x-ref to the string above
        ZydisDecodedInstruction instr;
        while (ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&decoder, data, length, &instr))) {
            if (instr.mnemonic == ZYDIS_MNEMONIC_LEA) {
                size_t temp = s_text.virtual_address() +
                              (data - v_text_content.data() + instr.length) +
                              instr.operands[1].mem.disp.value;

                if (temp == offset) {
                    found = true;
                    offset = s_text.virtual_address() + data - v_text_content.data();
                    break;
                }
            }

            data += instr.length;
            length -= instr.length;
        }
    }

    PPK_ASSERT_ERROR(found);

    // this makes both branches identical
    bin->patch_address(offset, { 0x48, 0x83, 0xC4, 0x08, 0xC3 });
    bin->write(output.data());

    return EXIT_SUCCESS;
}
