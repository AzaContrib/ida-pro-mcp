/*
 * wide_fixture.c – minimal ELF whose .rodata section contains several
 * UTF-16LE string literals, represented as uint16_t arrays.
 *
 * On little-endian platforms (x86 / x86-64 / ARM) a uint16_t value is
 * stored as two consecutive bytes in little-endian order, so initialising
 * the elements with ASCII code-points produces exact UTF-16LE byte
 * sequences in the compiled binary.  For example 'G' becomes 0x47 followed
 * by 0x00 – the correct UTF-16LE encoding of U+0047.
 *
 * The strings chosen here mirror common patterns in Windows PE binaries:
 *   - An API function name ("GetUserName")
 *   - A localised greeting ("Hello, World!")
 *   - A file-system path ("C:\Windows\System32")
 *
 * Compile with:
 *   gcc -O0 -o tests/wide_fixture.elf tests/wide_fixture.c
 */

#include <stdint.h>

const uint16_t g_wide_get_user_name[] = {
    'G','e','t','U','s','e','r','N','a','m','e', 0
};

const uint16_t g_wide_hello_world[] = {
    'H','e','l','l','o',',',' ','W','o','r','l','d','!', 0
};

const uint16_t g_wide_windows_path[] = {
    'C',':','\\','W','i','n','d','o','w','s','\\','S','y','s','t','e','m','3','2', 0
};

/* Reference the globals so the linker keeps them in the binary. */
int use_wide(void) {
    return (int)g_wide_get_user_name[0]
         + (int)g_wide_hello_world[0]
         + (int)g_wide_windows_path[0];
}

int main(void) {
    return use_wide();
}
