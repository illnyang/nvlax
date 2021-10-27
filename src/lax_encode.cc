/*  This file is part of nvlax.

    nvlax is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    THIS SOFTWARE IS PROVIDED 'AS-IS', WITHOUT ANY EXPRESS
    OR IMPLIED WARRANTY. IN NO EVENT WILL THE AUTHORS BE HELD
    LIABLE FOR ANY DAMAGES ARISING FROM THE USE OF THIS SOFTWARE.  */

#include <LIEF/ELF.hpp>
#include <Zydis/Zydis.h>

#include "common.h"

using namespace LIEF::ELF;

const char *app_name = "nvlax_encode";
const char *lib_name = "libnvidia-encode.so.XXX";

int
main (int argc,
      char **argv)
{
    std::string_view input, output;
    if (!parse_args(argc, argv, input, output)) {
        return EXIT_FAILURE;
    }

    auto bin = Parser::parse(input.data());

    ZydisDecoder decoder;
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

    uint64_t offset;

    {
        auto f_nvenc_ci = bin->get_symbol("NvEncodeAPICreateInstance");

        // 0x260 here is an approximation (we should never have to go past that address)
        auto v_func_bytes = bin->get_content_from_virtual_address(f_nvenc_ci.value(), 0x260);

        uint8_t *data = v_func_bytes.data();
        size_t length = v_func_bytes.size();

        ZydisDecodedInstruction instr;
        while (ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&decoder, data, length, &instr))) {
            if (instr.mnemonic == ZYDIS_MNEMONIC_LEA)
                offset = f_nvenc_ci.value() +
                         (data - v_func_bytes.data() + instr.length) +
                         instr.operands[1].mem.disp.value;

            // this should work forever if we assume that NV_ENCODE_API_FUNCTION_LIST will never change!
            if (instr.mnemonic == ZYDIS_MNEMONIC_MOV && instr.operands[0].mem.disp.value == 0xF0) {
                break;
            }

            data += instr.length;
            length -= instr.length;
        }
    }

    {
        // 0x235 here is an approximation (we should never have to go past that address)
        auto v_func_bytes = bin->get_content_from_virtual_address(offset, 0x235);

        uint8_t *data = v_func_bytes.data();
        size_t length = v_func_bytes.size();

        // look for the second instance of 'test eax, eax'
        uint8_t n = 0;
        ZydisDecodedInstruction instr;
        while (ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&decoder, data, length, &instr))) {
            if (instr.mnemonic == ZYDIS_MNEMONIC_TEST &&
                instr.operands[0].reg.value == ZYDIS_REGISTER_EAX &&
                instr.operands[1].reg.value == ZYDIS_REGISTER_EAX &&
                (++n) > 1)
            {
                offset += (data - v_func_bytes.data());
                break;
            }

            data += instr.length;
            length -= instr.length;
        }
    }

    // NOP the jump that happens after the test
    bin->patch_address(offset + 0x5, {0x90, 0x90, 0x90, 0x90, 0x90, 0x90});
    bin->write(output.data());

    return EXIT_SUCCESS;
}
