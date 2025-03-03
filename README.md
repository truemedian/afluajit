
# AFLuaJIT

AFLuaJIT is a fork of the LuaJIT project with fuzzing via AFL++ in mind. It is a drop-in
replacement for the latest LuaJIT 2.1 release with an additional C library to integrate
AFL++ into Lua code.

## Features

- **AFL++ Integration**: AFLuaJIT provides a new library named `aflua` that exposes
    AFL++'s functionality to Lua scripts seamlessly.
- **Structured Fuzzing**: The `aflua` library allows for structured fuzzing of Lua
    scripts, enabling the generation of test cases that are more likely to uncover bugs.
- **Compatibility**: AFLuaJIT is designed to be a drop-in replacement for LuaJIT 2.1,
    ensuring compatibility with existing LuaJIT codebases.
- **Performance**: AFLuaJIT maintains the performance optimizations of LuaJIT while
    adding the necessary hooks for fuzzing.

## Documentation

The primary interface for AFLuaJIT is the `aflua` library. The following sections
describe the key components and usage of the library.

### Initialization and Fuzzing

AFLuaJIT is designed to be run in persistent-mode, which means as much initialization as
possible should be done *before* forking off into the fuzzing loop.

#### `aflua.init()`

This function initializes the AFL++ fuzzer and prepares the environment for fuzzing. This
is the point at which the program will fork if necessary, so any redundant initialization
should be done before this call.

#### `aflua.run(fn[, max_iterations[, error_handler]])`

Runs the given function with an input provided by AFL++. The function `fn` should accept
a single string argument, which is the input buffer provided by AFL++.

If `max_iterations` is provided, the fuzzer will run the function up to that many times
before reinitializing (by default this is 10000).

If `error_handler` is provided it will be the error handler function that will be called
when the fuzzing function throws an error. This behaves identically to the error handler
in the `xpcall` function, so `debug.traceback` is a good choice.

#### `aflua.skip()`

Marks the current test case as unimportant, so whatever happens AFL++ will ignore the
result. The fuzzing function should attempt to return as quickly as possible after this
call to avoid wasting time.

#### `aflua.coverage_discard()`

Discards all coverage information gathered so far. This is useful if the path up to this
function is unimportant and the coverage information is not needed.

This may both increase or decrease fuzzing stability, so use with caution.

#### `aflua.coverage_hook(enable[, count])`

Enables or disables the Lua coverage debug hook. If `enable` is true, the hook will be
enabled, and if `count` is provided, the hook will be called every `count` instructions.
If `enable` is false, the hook will be disabled.

This is a debug hook and will slow down the execution of the program, but it provides
necessary coverage information to effectively fuzz Lua code because otherwise AFL++ can
only trace the execution of the LuaJIT interpreter.

### Structured Fuzzing

#### `aflua.consume_string(max_length)`

Produces the longest possible string of at most `max_length` bytes from the input buffer.
If the input buffer is empty an empty string will be returned.

#### `aflua.consume_string_random(max_length)`

Produces a string of at most `max_length` bytes from the input buffer. The length of the
string is chosen randomly. If the input buffer is empty an empty string will be returned.

#### `aflua.consume_integer(min, max)`

Produces an integer between `min` and `max` (inclusive) from the input buffer. If the
input buffer is empty the value `min` will be returned.

#### `aflua.consume_probability()`

Produces a float between `0` and `1` (inclusive) from the input buffer. If the input
buffer is empty the value `0` will be returned.

#### `aflua.consume_float(min, max)`

Produces a float between `min` and `max` (inclusive) from the input buffer. If the
input buffer is empty the value `min` will be returned.

#### `aflua.consume_boolean()`

Produces a boolean value from the input buffer. If the input buffer is empty the value
`false` will be returned.

#### `aflua.consume_rest()`

Produces a string from the input buffer starting from the current position to the end of
the input buffer.

## Potential Future Enhancements

- **Improved Coverage**: Enhance the coverage analysis by directly instrumenting the
    LuaJIT VM, this would require a much deeper integration with the LuaJIT internals.
- **Additional Support**: While AFL++ is a powerful tool, integrating other fuzzing tools
    or techniques could provide more options for more comprehensive testing.
- **Documentation**: Expand the documentation to include more examples and best practices
    for using AFLuaJIT in various fuzzing scenarios.

## Copyright

AFLuaJIT is a software project that builds upon LuaJIT and is maintained to provide
enhancements suited for fuzz testing applications.

AFLuaJIT is Copyright (C) 2025 truemedian.  
AFLuaJIT is free software, released under the MIT license.  

LuaJIT is Copyright (C) 2005-2025 Mike Pall.  
LuaJIT is free software, released under the MIT license.  
See full Copyright Notice in the COPYRIGHT file or in luajit.h.  

The original LuaJIT project is available at <https://luajit.org/>.
