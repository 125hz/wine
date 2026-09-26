/*
 * ARM64EC: recognise primary IAT slots that back public x64 export stubs
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/* Included from loader.c under __arm64ec__.
 *
 * An EC image can export a function to x64 callers as a plain x64 stub,
 *     FF 25 disp32        jmp qword ptr [rip + disp32]
 * whose memory operand is a slot of the image's own primary IAT. x64 code that
 * follows that jump (a hook resolver, for instance) reads the slot and expects
 * an x64-visible target there. Redirecting such a slot to the native body of
 * the import hands x64 code an ARM64 address, which it may then patch with x64
 * instructions. This answers whether slot_rva is the operand of such a stub,
 * so the loader can keep the x64-facing target for exactly those slots.
 *
 * Pure function of the image bytes and the metadata passed in; no state. */

#define ARM64EC_X64_STUB_LEN 6

/* TRUE when rva falls inside a native (ARM64 or ARM64EC) code range. */
static BOOL arm64ec_rva_is_native_code( const BYTE *base, ULONG code_map_rva, ULONG code_map_count, ULONG rva )
{
    const IMAGE_CHPE_RANGE_ENTRY *map;
    ULONG i;

    if (!code_map_rva) return FALSE;
    map = (const IMAGE_CHPE_RANGE_ENTRY *)(base + code_map_rva);
    for (i = 0; i < code_map_count; i++)
    {
        ULONG start = map[i].StartOffset & ~3u;
        ULONG type = map[i].StartOffset & 3;   /* 0 ARM64, 1 ARM64EC, 2 AMD64 */
        if (rva >= start && rva - start < map[i].Length) return type != 2;
    }
    return FALSE;
}

static BOOL arm64ec_iat_slot_is_x64_export( HMODULE module, ULONG size_of_image, ULONG_PTR slot_rva,
                                            ULONG_PTR export_dir_rva, ULONG export_size,
                                            ULONG code_map_rva, ULONG code_map_count )
{
    const BYTE *base = (const BYTE *)module;
    const IMAGE_EXPORT_DIRECTORY *exports;
    const DWORD *functions;
    ULONG i;

    if (slot_rva + sizeof(ULONG_PTR) > size_of_image) return FALSE;
    if (export_dir_rva + sizeof(*exports) > size_of_image) return FALSE;
    exports = (const IMAGE_EXPORT_DIRECTORY *)(base + export_dir_rva);
    if (!exports->AddressOfFunctions || !exports->NumberOfFunctions) return FALSE;
    if (exports->AddressOfFunctions + (ULONGLONG)exports->NumberOfFunctions * sizeof(DWORD) > size_of_image)
        return FALSE;
    functions = (const DWORD *)(base + exports->AddressOfFunctions);

    for (i = 0; i < exports->NumberOfFunctions; i++)
    {
        ULONG rva = functions[i];
        const BYTE *code;
        LONG disp;

        if (!rva || rva + ARM64EC_X64_STUB_LEN > size_of_image) continue;
        /* forwarders point back into the export directory */
        if (rva >= export_dir_rva && rva < export_dir_rva + export_size) continue;
        code = base + rva;
        if (code[0] != 0xff || code[1] != 0x25) continue;
        memcpy( &disp, code + 2, sizeof(disp) );
        if ((LONGLONG)rva + ARM64EC_X64_STUB_LEN + disp != (LONGLONG)slot_rva) continue;
        if (arm64ec_rva_is_native_code( base, code_map_rva, code_map_count, rva )) continue;
        return TRUE;
    }
    return FALSE;
}
