import sys
import json
from elftools.elf.elffile import ELFFile
from elftools.dwarf.callframe import FDE
from collections import defaultdict

def get_stack_info_from_eh_cfi(filename):
    result = {}

    with open(filename, 'rb') as f:
        elf = ELFFile(f)

        if not elf.has_dwarf_info():
            raise Exception("No DWARF info found in the ELF file")

        dwarf_info = elf.get_dwarf_info()

        if not dwarf_info.has_EH_CFI():
            raise Exception("No EH Call Frame Information found")

        for entry in dwarf_info.EH_CFI_entries():
            if isinstance(entry, FDE):
                function_address = entry['initial_location']
                function_end = function_address + entry['address_range']

                frame_table = entry.get_decoded().table

                frame_ranges = []
                last_ra_rule = None

                for idx, row in enumerate(frame_table):
                    start_pc = row['pc']
                    end_pc = frame_table[idx + 1]['pc'] if idx + 1 < len(frame_table) else function_end
                    cfa = row['cfa']

                    # Carefully handle ra rule
                    if 30 in row:
                        ra_rule = row[30]
                        last_ra_rule = ra_rule
                    else:
                        ra_rule = last_ra_rule  # inherit

                    frame_ranges.append((start_pc, end_pc, cfa, ra_rule))

                for start_pc, end_pc, cfa, ra_rule in frame_ranges:
                    # Infer stack size
                    stack_offset = cfa.offset
                    
                    # Infer return address offset
                    return_address_offset = None
                    if ra_rule is not None:
                        return_address_offset = ra_rule.arg

                    result[hex(start_pc)] = {
                        "start_pc": hex(start_pc),
                        "end_pc": hex(end_pc),
                        "stack_size": stack_offset,
                        "return_address_offset": return_address_offset
                    }

    return result


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python eh_elf_stack_map.py <input.elf> <output.json>")
        sys.exit(1)

    input_elf = sys.argv[1]
    output_json = sys.argv[2]

    stack_map = get_stack_info_from_eh_cfi(input_elf)

    with open(output_json, 'w') as f:
        json.dump(stack_map, f, indent=2)

    print(f"Saved stack map with {len(stack_map)} entries to {output_json}")
