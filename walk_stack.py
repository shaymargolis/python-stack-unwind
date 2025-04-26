import sys
import struct
from pathlib import Path
import json


def get_frame_info(mapping, address):
    for key, _map in mapping.items():
        if address >= int(_map["start_pc"], 16) and address <= int(_map["end_pc"], 16):
            return _map

    return None


if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python walk_stack.py <input.stack> <input.json> <curr_pc>")
        sys.exit(1)

    input_stack = sys.argv[1]
    input_json = sys.argv[2]
    curr_pc = int(sys.argv[3], 16)

    mapping = json.loads(Path(input_json).read_text())
    stack = Path(input_stack).read_bytes()
    stack_loc = 0

    while True:
        frame_info = get_frame_info(mapping, curr_pc)
        if frame_info is None or frame_info["return_address_offset"] is None:
            break

        next_ra_loc = frame_info["stack_size"] + frame_info["return_address_offset"]
        curr_pc = struct.unpack("<Q", stack[stack_loc+next_ra_loc:stack_loc+next_ra_loc+8])[0]
        stack_loc += frame_info["stack_size"]

        print(hex(curr_pc))
