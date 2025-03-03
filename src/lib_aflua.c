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

/* https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/afl-compiler-rt.o.c#L2814 */
void __afl_coverage_interesting(uint8_t val, uint32_t id);

/* https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/afl-compiler-rt.o.c#L245 */
void __afl_trace(const uint32_t x);

/* https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/afl-compiler-rt.o.c#L116 */
extern uint32_t __afl_map_size;

/* https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/afl-compiler-rt.o.c#L173 */
extern int __afl_connected;

unsigned char* afl_input_buf;
unsigned char* afl_input_cursor;
unsigned int afl_input_remaining;

__AFL_FUZZ_INIT();
__AFL_COVERAGE();

/* No reason to keep track of coverage as we work our way through luajit to get to the fuzzing */
__AFL_COVERAGE_START_OFF();

/* https://github.com/jwilk/python-afl/blob/8df6bfefac5de78761254bf5d7724e0a52d254f5/afl.pyx#L74-L87 */
#define LHASH_INIT 0x811C9DC5
#define LHASH_MAGIC_MULT 0x01000193
#define LHASH_NEXT(x) h = ((h ^ (unsigned char)(x)) * LHASH_MAGIC_MULT)

static inline uint32_t lhash(const char* key, size_t offset) {
    const char* const last = &key[strlen(key) - 1];
    uint32_t h = LHASH_INIT;
    while (key <= last)
        LHASH_NEXT(*key++);
    for (; offset != 0; offset >>= 8)
        LHASH_NEXT(offset);
    return h;
}

void aflua_hook(lua_State* L, lua_Debug* ar) {
    lua_getinfo(L, "Sl", ar);
    if (ar->source && ar->currentline) {
        const uint32_t new_location = lhash(ar->source, ar->currentline);

        __afl_trace(new_location % __afl_map_size);
    }
}

/* .mark(id, value)
 * Mark this region as especially interesting. The id integer will be mixed with the current source
 * location. The value is an 8-bit integer where only the highest set bit has meaning.
 */
LJLIB_CF(aflua_mark) {
    const uint32_t id = (uint32_t)luaL_checkinteger(L, 1);
    const uint8_t value = (uint8_t)luaL_checkinteger(L, 2);

    lua_Debug ar;
    if (lua_getstack(L, 1, &ar) == 0)
        return 0;

    lua_getinfo(L, "Sl", &ar);
    if (ar.source && ar.currentline) {
        const uint32_t location = lhash(ar.source, ar.currentline);

        __afl_coverage_interesting(value, location ^ id);
    } else {
        __afl_coverage_interesting(value, id);
    }

    return 0;
}

/* .init()
 * Initialize the fuzzing environment, should be after any shared setup but before run()
 */
LJLIB_CF(aflua_init) {
#ifdef __AFL_HAVE_MANUAL_CONTROL
    __AFL_INIT();
#endif
    return 0;
}

/* .skip()
 * Mark the current test as unimportant, whatever happens afl-fuzz will ignore
 */
LJLIB_CF(aflua_skip) {
    __AFL_COVERAGE_SKIP();
    return 0;
}

/* .coverage_discard()
 * Discard all coverage information gathered before this point
 */
LJLIB_CF(aflua_coverage_discard) {
    __AFL_COVERAGE_DISCARD();
    return 0;
}

/* .coverage_hook(enable[, count])
 * Enables or disables a debug hook that provides coverage information for Lua code.
 * The hook is invoked for every function call and line execution.
 *
 * If count is given, the hook will also be called every count instructions.
 */
LJLIB_CF(aflua_coverage_hook) {
    if (!lua_toboolean(L, 1)) {
        lua_sethook(L, NULL, 0, 0);
        return 0;
    }

    if (lua_isnumber(L, 2)) {
        int count = (int)lua_tointeger(L, 2);
        lua_sethook(L, aflua_hook, LUA_MASKCALL | LUA_MASKLINE | LUA_MASKCOUNT, count);
    } else {
        lua_sethook(L, aflua_hook, LUA_MASKCALL | LUA_MASKLINE, 0);
    }

    return 0;
}

/* .run(fn[, max_iterations[, error_handler]])
 * Run the given function with the input provided by AFL.
 * The function should be a Lua function that takes a single string argument.
 *
 * This function will run the given function multiple times, each time with a different input.
 */
LJLIB_CF(aflua_run) {
    luaL_checktype(L, 1, LUA_TFUNCTION);
    
    unsigned int max_iterations = (unsigned int)luaL_optinteger(L, 2, 10000);
    
    /* Optional error handler */
    int error_handler = lua_isfunction(L, 3) ? 3 : 0;

    if (error_handler == 0 && !__afl_connected) {
        lua_settop(L, 3);

        lua_getglobal(L, "debug");
        lua_getfield(L, -1, "traceback");
        lua_replace(L, 3);

        error_handler = 3;
        lua_pop(L, 1);
    }

    __AFL_COVERAGE_ON();

    afl_input_buf = __AFL_FUZZ_TESTCASE_BUF;
    while (__AFL_LOOP(max_iterations)) {
        afl_input_cursor = afl_input_buf;
        afl_input_remaining = __AFL_FUZZ_TESTCASE_LEN;

        lua_pushvalue(L, 1); // push the function
        lua_pushlstring(L, (const char*)afl_input_buf, afl_input_remaining); // push the input
        int ret = lua_pcall(L, 1, 0, error_handler); // call the function with 1 string argument and no return value

        if (ret != 0) {
            const char* err = lua_tostring(L, -1);
            fprintf(stderr, "fatal: %s\n", err);
            exit(1);
        }
    }

    __AFL_COVERAGE_OFF();
    return 0;
}

/* .consume_string(max_length)
 * Produces a string of at most max_length bytes from the input buffer.
 */
LJLIB_CF(aflua_consume_string) {
    lua_Integer max_length = luaL_optinteger(L, 1, 0);
    if (max_length < 0) {
        luaL_error(L, "max_length must be non-negative");
    }

    max_length = (max_length > afl_input_remaining) ? afl_input_remaining : max_length;
    lua_pushlstring(L, (const char*)afl_input_cursor, max_length);

    afl_input_cursor += max_length;
    afl_input_remaining -= max_length;

    return 1;
}

/* .consume_string_random(max_length)
 * Produces a string of at most max_length bytes from the input buffer.
 * The length of the string is chosen randomly between 0 and max_length.
 */
LJLIB_CF(aflua_consume_string_random) {
    lua_Integer max_length = luaL_optinteger(L, 1, 0);
    if (max_length < 0) {
        luaL_error(L, "max_length must be non-negative");
    }

    if (afl_input_remaining < sizeof(uint32_t)) {
        lua_pushlstring(L, NULL, 0);
        return 1;
    }

    uint32_t real_length = *(uint32_t*)afl_input_cursor;
    afl_input_cursor += sizeof(uint32_t);
    afl_input_remaining -= sizeof(uint32_t);

    real_length = real_length % max_length;
    real_length = (real_length > afl_input_remaining) ? afl_input_remaining : real_length;

    lua_pushlstring(L, (const char*)afl_input_cursor, real_length);
    afl_input_cursor += real_length;
    afl_input_remaining -= real_length;

    return 1;
}

/* .consume_integer(min, max)
 * Produces an integer between min and max from the input buffer.
 * The integer is chosen randomly between min and max but the value may not be uniformly distributed.
 */
LJLIB_CF(aflua_consume_integer) {
    lua_Integer min = luaL_checkinteger(L, 1);
    lua_Integer max = luaL_checkinteger(L, 2);

    if (min > max) {
        luaL_error(L, "min must not be greater than max");
    }

    lua_Integer range = max - min;
    lua_Integer result = 0;

    while (range > 0 && afl_input_remaining > 0) {
        range >>= 8;
        result <<= 8;
        result |= *afl_input_cursor;

        afl_input_cursor++;
        afl_input_remaining--;
    }

    range = max - min;
    result = min + (result % range);
    lua_pushinteger(L, result);

    return 1;
}

/* .consume_probability()
 * Produces a float between 0 and 1 from the input buffer.
 * The float is chosen randomly between 0 and 1 but the value may not be uniformly distributed.
 */
LJLIB_CF(aflua_consume_probability) {
    if (afl_input_remaining < sizeof(uint32_t)) {
        lua_pushnumber(L, 0); // return 0 if there's not enough input
        return 1;
    }

    uint32_t result = *(uint32_t*)afl_input_cursor;
    afl_input_cursor += sizeof(uint32_t);
    afl_input_remaining -= sizeof(uint32_t);

    lua_pushnumber(L, (double)result / (double)UINT32_MAX);

    return 1;
}

/* .consume_float(min, max)
 * Produces a float between min and max from the input buffer.
 * The float is chosen randomly between min and max but the value may not be uniformly distributed.
 */
LJLIB_CF(aflua_consume_float) {
    lua_Number min = luaL_checknumber(L, 1);
    lua_Number max = luaL_checknumber(L, 2);
    if (min > max) {
        luaL_error(L, "min must not be greater than max");
    }

    lua_Number range = max - min;

    if (afl_input_remaining < sizeof(uint32_t)) {
        lua_pushnumber(L, min); // return min if there's not enough input
        return 1;
    }

    uint32_t result = *(uint32_t*)afl_input_cursor;
    afl_input_cursor += sizeof(uint32_t);
    afl_input_remaining -= sizeof(uint32_t);

    lua_Number value = (double)result / (double)UINT32_MAX;
    lua_pushnumber(L, min + (value * range));

    return 1;
}

/* .consume_boolean()
 * Produces a boolean value from the input buffer.
 * The boolean is chosen randomly between true and false but the value may not be uniformly distributed.
 */
LJLIB_CF(aflua_consume_boolean) {
    if (afl_input_remaining < sizeof(uint8_t)) {
        lua_pushboolean(L, 0); // return false if there's not enough input
        return 1;
    }

    uint8_t result = *afl_input_cursor;
    afl_input_cursor += sizeof(uint8_t);
    afl_input_remaining -= sizeof(uint8_t);

    lua_pushboolean(L, result & 1);

    return 1;
}

/* .consume_rest()
 * Produces a string of the remaining input buffer.
 */
LJLIB_CF(aflua_consume_rest) {
    lua_pushlstring(L, (const char*)afl_input_cursor, afl_input_remaining);
    afl_input_cursor += afl_input_remaining;
    afl_input_remaining = 0;

    return 1;
}

#include "lj_libdef.h"

LUALIB_API int luaopen_aflua(lua_State* L) {
    LJ_LIB_REG(L, LUA_AFLUALIBNAME, aflua);
    return 1;
}
