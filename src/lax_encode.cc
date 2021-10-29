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
#include <LIEF/PE.hpp>

#include <Zydis/Zydis.h>

#include <ppk_assert.h>

#include "common.h"

const char *app_name = "nvlax_encode";
const char *lib_name = "libnvidia-encode.so.XXX";

void
patch_linux (LIEF::ELF::Binary *bin)
{
    using namespace LIEF::ELF;

    PPK_ASSERT_ERROR(bin->imported_libraries().at(0) == "libnvcuvid.so.1");

    std::cout << "[+] libnvidia-encode.so\n";

    ZydisDecoder decoder;
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

    bool found = false;
    ZyanU64 offset;

    {
        auto f_nvenc_ci = bin->get_symbol("NvEncodeAPICreateInstance");

        // 0x260 here is an approximation (we should never have to go past that address)
        auto v_func_bytes = bin->get_content_from_virtual_address(f_nvenc_ci.value(), 0x260);

        uint8_t *data = v_func_bytes.data();
        size_t length = v_func_bytes.size();

        ZydisDecodedInstruction instr;
        while (ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&decoder, data, length, &instr))) {
            if (instr.mnemonic == ZYDIS_MNEMONIC_LEA) {
                offset = f_nvenc_ci.value() +
                         (data - v_func_bytes.data() + instr.length) +
                         instr.operands[1].mem.disp.value;
            }

            // this should work forever if we assume that NV_ENCODE_API_FUNCTION_LIST will never change!
            if (instr.mnemonic == ZYDIS_MNEMONIC_MOV && instr.operands[0].mem.disp.value / 8 == 30) {
                found = true;
                break;
            }

            data += instr.length;
            length -= instr.length;
        }
    }

    PPK_ASSERT_ERROR(found);
    found = false;

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
                found = true;
                break;
            }

            data += instr.length;
            length -= instr.length;
        }
    }

    PPK_ASSERT_ERROR(found);

    // test eax, eax -> xor eax, eax
    bin->patch_address(offset, 0x31, 0x1);
}

void
patch_windows (LIEF::PE::Binary *bin)
{
    using namespace LIEF::PE;

    enum {
        x64, x86
    } arch;

    std::cout << std::hex;

    if (bin->header().machine() == MACHINE_TYPES::IMAGE_FILE_MACHINE_AMD64) {
        PPK_ASSERT_ERROR(bin->get_export().name() == "nvEncodeAPI64.dll");
        arch = x64;
    }
    else if (bin->header().machine() == MACHINE_TYPES::IMAGE_FILE_MACHINE_I386) {
        PPK_ASSERT_ERROR(bin->get_export().name() == "nvEncodeAPI.dll");
        arch = x86;
    }
    else {
        PPK_ASSERT_ERROR("invalid architecture");
        return;
    }

    std::cout << "[+] " << bin->get_export().name() << "\n";

    ZydisFormatter fmt;
    ZydisFormatterInit(&fmt, ZYDIS_FORMATTER_STYLE_INTEL);

    ZydisDecoder decoder;
    arch == x64 ?
        ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64) :
        ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_COMPAT_32, ZYDIS_STACK_WIDTH_32);

    const auto follow_thunk = [bin, decoder] (uint64_t address) -> ZyanU64
    {
        ZyanU64 offset;

        auto v_thunk_bytes = bin->get_content_from_virtual_address(address, 0x5);

        ZydisDecodedInstruction instr;
        PPK_ASSERT_ERROR(ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&decoder,
                                                               v_thunk_bytes.data(),
                                                               v_thunk_bytes.size(),
                                                               &instr)));

        PPK_ASSERT_ERROR(instr.mnemonic == ZYDIS_MNEMONIC_JMP);


        PPK_ASSERT_ERROR(ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&instr,
                                                               &instr.operands[0],
                                                               address,
                                                               &offset)));
        return offset;
    };

    bool found = false;
    ZyanU64 offset;

    {
        auto export_entries = bin->get_export().entries();

        auto f_nvenc_ci = std::find_if(export_entries.begin(),
                                       export_entries.end(),
                                       [] (const ExportEntry &e) { return e.name() == "NvEncodeAPICreateInstance"; });

        PPK_ASSERT_ERROR(f_nvenc_ci != export_entries.end());

        offset = follow_thunk(f_nvenc_ci->address());

        auto v_func_bytes = bin->get_content_from_virtual_address(offset, arch == x64 ? 0x25B : 0x17E);

        uint8_t *data = v_func_bytes.data();
        size_t length = v_func_bytes.size();

        ZydisDecodedInstruction instr;

        if (arch == x64) {
            ZyanU64 temp = 0;
            while (ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&decoder, data, length, &instr))) {
                if (instr.mnemonic == ZYDIS_MNEMONIC_LEA &&
                    instr.operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY)
                {
                    temp = offset +
                           (data - v_func_bytes.data() + instr.length) +
                           instr.operands[1].mem.disp.value;
                }

                // this should work forever if we assume that NV_ENCODE_API_FUNCTION_LIST will never change!
                if (instr.mnemonic == ZYDIS_MNEMONIC_MOV &&
                    instr.operands[0].mem.disp.value / 8 == 30)
                {
                    found = true;
                    offset = follow_thunk(temp);
                    break;
                }

                data += instr.length;
                length -= instr.length;
            }
        }
        else {
            while (ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&decoder, data, length, &instr))) {
                // this should work forever if we assume that NV_ENCODE_API_FUNCTION_LIST will never change!
                if (instr.mnemonic == ZYDIS_MNEMONIC_MOV &&
                    instr.operands[0].mem.base == ZYDIS_REGISTER_ESI &&
                    instr.operands[0].mem.disp.value / 4 == 31)
                {
                    found = true;
                    offset = follow_thunk(bin->rva_to_offset(instr.operands[1].imm.value.u));
                    break;
                }

                data += instr.length;
                length -= instr.length;
            }
        }
    }

    PPK_ASSERT_ERROR(found);
    found = false;

    {
        auto v_func_bytes = bin->get_content_from_virtual_address(offset, arch == x64 ? 0x18E : 0x189);

        uint8_t *data = v_func_bytes.data();
        size_t length = v_func_bytes.size();

        uint8_t n = 0;
        ZydisDecodedInstruction instr;
        while (ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&decoder, data, length, &instr))) {
            if (instr.mnemonic == ZYDIS_MNEMONIC_TEST &&
                instr.operands[0].reg.value == ZYDIS_REGISTER_EAX &&
                instr.operands[1].reg.value == ZYDIS_REGISTER_EAX &&
                (++n) > (arch == x64 ? 0 : 1))
            {
                found = true;
                offset += data - v_func_bytes.data();
                break;
            }

            data += instr.length;
            length -= instr.length;
        }
    }

    PPK_ASSERT_ERROR(found);

    bin->patch_address(offset, 0x31, 1);
}

int
main (int argc,
      char **argv)
{
    std::string_view input, output;
    if (!parse_args(argc, argv, input, output)) {
        return EXIT_FAILURE;
    }

    auto bin = LIEF::Parser::parse(input.data());

    if (bin->format() == LIEF::FORMAT_ELF) {
        patch_linux((LIEF::ELF::Binary *)bin.get());
    }
    else if (bin->format() == LIEF::FORMAT_PE) {
        patch_windows((LIEF::PE::Binary *)bin.get());
    }
    else {
        std::cerr << "[-] invalid input file\n";
        return EXIT_FAILURE;
    }

    bin->write(output.data());

    std::cout << "[+] patched successfully\n";

    return EXIT_SUCCESS;
}
