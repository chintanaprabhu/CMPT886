#!/usr/bin/env python3

import angr
import claripy

def resolve_safe(state):
    # if the bytes of "SAFE" are found in stdout it returns true
    return  b"SAFE! You found my secrets!" in state.posix.dumps(1)

if __name__ == '__main__':

    # Declare project, load the binary
    proj = angr.Project('bin/ticktock')

    # Create a 32-bit symbolic bitvector named "password"
    arg = claripy.BVS('sym_arg', 8 * 8)  # maximum 8 * 8 bits

    # We construct an entry_state passing the two arguments
    st = proj.factory.entry_state(args=['bin/ticktock', "cprabhu", arg], add_options={"BYPASS_UNSUPPORTED_SYSCALL"})
    # resolve strings that are of 8 bytes
    st.libc.max_strtol_len = 8

    # create a simulation manager
    pg = proj.factory.simgr(st)

    # This can be read as: explore looking for the path p for which the current state
    # p.state contains the string "SAFE!" in its standard output (p.state.posix.dumps(1),
    # where 1 is the file descriptor for stdout).
    pg.explore(find=resolve_safe)

    print("solution found")
    s = pg.found[0]
    print(s.posix.dumps(1)) # dump stdout

    # Print and eval the argument
    print("Arg: ", s.solver.eval(arg, cast_to=bytes))


