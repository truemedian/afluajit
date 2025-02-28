/*
** I/O library.
** Copyright (C) 2005-2025 Mike Pall. See Copyright Notice in luajit.h
**
** Major portions taken verbatim or adapted from the Lua interpreter.
** Copyright (C) 1994-2011 Lua.org, PUC-Rio. See Copyright Notice in lua.h
*/

#define lib_aflua_c
#define LUA_LIB

#include "lauxlib.h"
#include "lua.h"
#include "lualib.h"

#include "lj_buf.h"
#include "lj_err.h"
#include "lj_ff.h"
#include "lj_gc.h"
#include "lj_lib.h"
#include "lj_obj.h"
#include "lj_state.h"
#include "lj_str.h"
#include "lj_strfmt.h"

#define LJLIB_MODULE_aflua

void __afl_trace(const unsigned int x);
extern unsigned int __afl_map_size;

__AFL_FUZZ_INIT();
__AFL_COVERAGE();

/* https://github.com/jwilk/python-afl/blob/8df6bfefac5de78761254bf5d7724e0a52d254f5/afl.pyx#L74-L87 */
#define LHASH_INIT 0x811C9DC5
#define LHASH_MAGIC_MULT 0x01000193
#define LHASH_NEXT(x) h = ((h ^ (unsigned char)(x)) * LHASH_MAGIC_MULT)

static inline unsigned int lhash(const char* key, size_t offset) {
    const char* const last = &key[strlen(key) - 1];
    uint32_t h = LHASH_INIT;
    while (key <= last)
        LHASH_NEXT(*key++);
    for (; offset != 0; offset >>= 8)
        LHASH_NEXT(offset);
    return h;
}

LJLIB_CF(aflua_init) {
#ifdef __AFL_HAVE_MANUAL_CONTROL
    __AFL_INIT();
#endif

    return 0;
}

LJLIB_CF(aflua_skip) {
    __AFL_COVERAGE_SKIP();
    return 0;
}

void aflua_hook(lua_State* L, lua_Debug* ar) {
    lua_getinfo(L, "Sl", ar);
    if (ar->source && ar->currentline) {
        const unsigned int new_location = lhash(ar->source, ar->currentline);
        __afl_trace(new_location % __afl_map_size);
    }
}

LJLIB_CF(aflua_coverage_hook) {
    lua_toboolean(L, 1) ? lua_sethook(L, aflua_hook, LUA_MASKCALL | LUA_MASKLINE, 0) : lua_sethook(L, NULL, 0, 0);

    return 0;
}

LJLIB_CF(aflua_run) {
    luaL_checktype(L, 1, LUA_TFUNCTION);

    lua_getglobal(L, "debug");
    lua_getfield(L, -1, "traceback");
    lua_remove(L, -2);

    unsigned char* buf = __AFL_FUZZ_TESTCASE_BUF;
    while (__AFL_LOOP(10000)) {
        int len = __AFL_FUZZ_TESTCASE_LEN;

        lua_pushvalue(L, 1); // push the function
        lua_pushlstring(L, (const char*)buf, len); // push the input
        int ret = lua_pcall(L, 1, 0, -2); // call the function with 1 argument and no return value

        if (ret != 0) {
            const char* err = lua_tostring(L, -1);
            fprintf(stderr, "fatal: %s\n", err);
            abort();
        }
    }

    return 0;
}

#include "lj_libdef.h"

LUALIB_API int luaopen_aflua(lua_State* L) {
    LJ_LIB_REG(L, LUA_AFLUALIBNAME, aflua);
    return 1;
}
