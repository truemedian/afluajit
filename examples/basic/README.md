
# Basic Example

This example demonstrates a very simple fuzz test that fails if the input starts with the
string `abab`.

## Running the Fuzzer

Since this fuzzer expects text as input we should use `-a text` so the fuzzer doesn't
waste time trying to find random binary that matches the input.

```bash
afl-fuzz -i input -o output -a text -- afluajit fuzz.lua
```

Where `-i input` designates the `input` directory as the input corpus, `-o output`
designates the `output` directory as the fuzzer synchronization directory (where the
results will end up), `-a text` is described above, and `--` separates the afl-fuzz
options from the program to be fuzzed.

The given input corpus is very close to the expected failing input, so AFL should find a
few failing inputs very quickly, which you can find in `output/default/crashes`.

## Verifying the Results

After collecting a few crashes we can see what actually happened by passing the crashing
test case directly to the program.

You will find crashing test cases in `output/default/crashes` in the form
`id:xxxxxx,sig:xx,src:xxxxx,time:xx,...`. This information describes how afl found the
crash but is otherwise not very useful.

The first crash AFL++ found for me was
`id:000000,sig:06,src:000001,time:25,execs:152,op:flip2,pos:3` and contained the input
`ababaa`. This is the input we will use to verify the results:

```bash
$ afluajit fuzz.lua < output/default/crashes/id:000000,sig:06,src:000001,time:25,execs:152,op:flip2,pos:3
fatal: fuzz.lua:15: starts with abab
stack traceback:
    [C]: in function 'error'
    fuzz.lua:15: in function <fuzz.lua:5>
    [C]: in function 'run'
    fuzz.lua:5: in main chunk
    [C]: at 0x555555574a80
```

As we can see, the program fails as expected when provided with a crashing test case and
provides a useful error message.
