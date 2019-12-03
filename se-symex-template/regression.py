#!/usr/bin/env python3

import angr
import claripy
import subprocess

def Diff(li1, li2): 
    return (list(set(li1) - set(li2))) 

def get_args_at_state(state, args):
    return [(arg._encoded_name, state.solver.eval(arg, cast_to=bytes))
            for arg in args]


def get_inputs_for_paths(program, program_1, num_args, bytes_per_arg):
    project = angr.Project(program)
    project_1 = angr.Project(program_1)
    # Get the entry point of the program and start the analysis there.
    # NOTE: It is also possible to start symbolic execution at an arbitrary
    # location inside a binary. This can be used both for focusing the
    # analysis and for improving overall scalability.
    #
    # In this case we want the command line arguments to be symbolic, and we
    # want symbolic arguments, so we specify them here. These arguments are
    # represented as symbolic bitvectors. The number of bits for each argument
    # is also specified.
    args = [program]
    args.extend(claripy.BVS('arg{}'.format(arg_num + 1), 8*bytes_per_arg)
                for arg_num in range(num_args))

    args_1 = [program_1]
    args_1.extend(claripy.BVS('arg{}'.format(arg_num + 1), 8*bytes_per_arg)
                for arg_num in range(num_args))

    list = ["12345678", "87654321", "12121212", "00000000"]
    args.extend(list)
    args_1.extend(list)
    print(args)
    print(args_1)
    input()
    state = project.factory.full_init_state(args=args)
    state_1 = project.factory.full_init_state(args=args_1)
    # The simulation manager provides an interface to control the symbolic
    # execution decisions and how we explore, prioritize, merge, and split
    # the paths during the process. Here we simply run all paths to
    # completion. Clearly this will not always be possible.
    sm = project.factory.simulation_manager(state)
    sm_1 = project.factory.simulation_manager(state_1)

    sm.explore()
    sm_1.explore()

    # Then we can extract the inputs associated with each individual path.
    state_inputs = [(state, get_args_at_state(state, args[1:2]))
                    for state in sm.deadended]
    state_inputs_1 = [(state_1, get_args_at_state(state_1, args_1[1:2]))
                     for state in sm_1.deadended]
    dump_found_inputs(state_inputs, state_inputs_1)
   # return state_inputs

def dump_found_inputs(state_inputs, state_inputs_1):
    output = []
    output_1 = []
    regression_output = []
    for i, (state,inputs) in enumerate(state_inputs):
        can_sat = state.satisfiable()
        if not can_sat:
            continue
        print(state.posix.dumps(1))
        output.append(state.posix.dumps(1))
    for k, (state1,inputs1) in enumerate(state_inputs_1):
        can_sat1 = state1.satisfiable()
        if not can_sat1:
            continue
        print(state1.posix.dumps(1))
        output_1.append(state1.posix.dumps(1))

    regression_output = Diff(output, output_1)
    print(len(regression_output))

    n = 0
    dict = {}
    values = []
    for j in regression_output:
#        print(j)
        for i, (state,inputs) in enumerate(state_inputs):
            if( j == state.posix.dumps(1)):
#                print(state.posix.dumps(1))
                for name, value in inputs:
#                    print(value)
#                    input()
                    values.append(value)

                dict[n] = values
                values = []
                n = n + 1 
    print(dict)

if __name__ == '__main__':
    print('Regression discovery via symex? I don\'t believe it exists.')
    PROGRAM_1 = 'bin/version1'
    PROGRAM_2 = 'bin/version2'
    NUM_ARGS = 1
    NUM_BYTES = 8
    STDOUT = 1

    get_inputs_for_paths(PROGRAM_1, PROGRAM_2, NUM_ARGS, NUM_BYTES)
    print("input states generated")
#    dump_found_inputs(state_inputs)

