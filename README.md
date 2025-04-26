# Python stack unwind tools

Example usage:

## Build

```bash
# The stack dumper
gcc dump_stack.c -o dump_stack

# The test payload
gcc test.c -gdwarf -o test -static -fomit-frame-pointer

# Generate stack mappings
python eh_elf_stack_map.py test mapping.json
```

## Run

```bash
# Run test and get pid
./test

# Dump stack using dumper
sudo ./dump_stack $PID

# Cut only given stack
dd if=stack of=stack.partial bs=1 skip=$CURRENT_LOC

# Parse stack!
python walk_stack.py stack.partial mapping.json $STACK_ADDR $CURR_PC
addr2line -e test -p -f -a $ADDRESSES
```
