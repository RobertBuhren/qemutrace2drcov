import sys
from typing import BinaryIO, Tuple, List

modules = [
    {
        "id": 0,
        "base": 0x100,
        "end": 0xFFFFFF,
        "size": 0xFFFFFF,
    }
]


# See https://github.com/gaasedelen/lighthouse/blob/master/coverage/frida/frida-drcov.py
# take the module dict and format it as a drcov logfile header
def create_header(mods, base_module):
    header = b''
    header += b'DRCOV VERSION: 2\n'
    header += b'DRCOV FLAVOR: drcov\n'
    header += b'Module Table: version 2, count %d\n' % len(mods)
    header += b'Columns: id, base, end, entry, checksum, timestamp, path\n'

    entries = []

    for m in mods:
        # drcov: id, base, end, entry, checksum, timestamp, path
        # frida doesnt give us entry, checksum, or timestamp
        #  luckily, I don't think we need them.
        entry = b'%3d, %#016x, %#016x, %#016x, %#08x, %#08x, %s' % (
            m['id'], m['base'], m['end'], 0, 0, 0, base_module.encode('ascii'))

        entries.append(entry)

    header_modules = b'\n'.join(entries)

    return header + header_modules + b'\n'


# take the recv'd basic blocks, finish the header, and append the coverage
def create_coverage(data):
    bb_header = b'BB Table: %d bbs\n' % len(data)
    bb_header += b'module id, start, size:\n'
    return bb_header + b'\n'.join(data)


def parse_exec_tb_line(line: bytes) -> Tuple[int, int]:
    """
    Parses an exec_tb line from a qemu trace
    :param line:
    :return:
    """
    # exec_tb 1.991 pid=24415 tb=0x7fd75f70a4e0 pc=0x344
    segments = line.split()
    if not segments[0] == b'exec_tb':
        raise ValueError("Line is not an exec_tb info. Use parse_next_tb_line.")
    thread_id = int(segments[2].split(b'=')[1])
    pc = int(segments[4].split(b'=')[1], 16)
    return pc, thread_id


def parse_next_tb_line(file: BinaryIO) -> Tuple[int, int]:
    """
    :param file: the file handle to read from
    :return: pc, thread_id of next tb_line
    :raises EOFError if last line was read
    """
    line = b''
    while not line.startswith(b'exec_tb'):
        line = file.readline()
        if not line:
            raise EOFError("End of file.")
    return parse_exec_tb_line(line)


def read_qemu_trace(qemu_trace_file: str) -> List[bytes]:
    bbs = []
    with open(qemu_trace_file, "rb") as qemu_trace:
        start, threadid = parse_next_tb_line(qemu_trace)
        current_line = start
        hasdata = True
        while hasdata:
            try:
                next_line, next_threadid = parse_next_tb_line(qemu_trace)
                if next_threadid != threadid:
                    print("Ignoring thread {}".format(next_threadid))
                elif next_line == current_line + 4:
                    current_line = next_line
                    # Next line executed.
                else:
                    print("New block found at 0x{:x}.".format(next_line))
                    size = current_line - start + 1
                    bbs += [b'module[0]: 0x%x, %d' % (start, size)]
                    start = next_line
                    current_line = start

            except EOFError:
                size = current_line - start + 1
                bbs += [b'module[0]: 0x%x, %d' % (start, size)]

                print("Done parsing file.")
                hasdata = False
    return bbs


def translate_files(base_module, qemu_trace_file, drcov_out_file):
    header = create_header(modules, base_module)
    bbs = read_qemu_trace(qemu_trace_file)
    body = create_coverage(bbs)

    with open(drcov_out_file, 'wb') as h:
        h.write(header)
        h.write(body)


if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: qemu2driotrace <base_module> <infile> <outfile>")
        exit(1)
    translate_files(sys.argv[1], sys.argv[2], sys.argv[3])
    exit(0)
