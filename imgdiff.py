import bz2
import click
import struct

from collections import namedtuple

MAGIC_STRING = 'IMGDIFF2'


def _get_int32(fp):
    bytes = fp.read(4)
    return struct.unpack('I', bytes)[0]


def _get_int64(fp):
    bytes = fp.read(8)
    return struct.unpack('L', bytes)[0]


class BootReader:
    def __init__(self, fp):
        self.fp = fp


class RecoveryReader:
    def __init__(self, fp):
        self.fp = fp

    def int32(self):
        bytes = self.fp.read(4)
        return struct.unpack('I', bytes)[0]

    def int64(self):
        bytes = self.fp.read(8)
        return struct.unpack('L', bytes)[0]

    def text(self, count):
        chars = self.fp.read(count)
        return chars

    def raw(self, count):
        bytes = self.fp.read(count)
        return bytes


@click.command()
@click.argument('path-to-boot.img', type=click.File('rb'))
@click.argument('path-to-recovery-from-boot.p', type=click.File('rb'))
def main(**kwargs):
    boot_fp = kwargs.pop('path_to_boot.img')
    recovery_fp = kwargs.pop('path_to_recovery_from_boot.p')

    boot = BootReader(boot_fp)
    patch = RecoveryReader(recovery_fp)
    header = patch.text(len(MAGIC_STRING))
    if header != MAGIC_STRING:
        print('this is not an IMGDIFF2 file')
        exit(1)

    chunk_count = patch.int32()
    print('chunk count: %s' % chunk_count)

    chunks = []
    for _ in range(chunk_count):
        chunk_type = patch.int32()
        chunk_func = chunk_funcs[chunk_type]
        chunk = chunk_func(patch)
        chunks.append(chunk)

    for chunk in chunks:
        if isinstance(chunk, NormalChunk):
            header = patch.text(8)
            if header != 'BSDIFF40':
                print('This is an invalid BSDIFF40 chunk')
                exit(1)

            control_len = patch.int64()
            diff_len = patch.int64()
            len_new_file = patch.int64()
            bzip2_control_block = patch.raw(control_len)
            bzip2_diff_block = patch.raw(diff_len)

            extra_data_len = chunk.src_len - control_len
            bzip2_extra_block = patch.raw(extra_data_len)

            bzip2_control_block = bz2.decompress(bzip2_control_block)
            bzip2_diff_block = bz2.decompress(bzip2_diff_block)
            bzip2_extra_block = bz2.decompress(bzip2_extra_block)

            if len(bzip2_diff_block) != len_new_file:
                print('error processing block (%s != %s)'
                      % (len(bzip2_diff_block), len_new_file))
            print('finished processing normal chunk')
            import pdb; pdb.set_trace()

        exit(1)


NormalChunk = namedtuple('NormalChunk', ['src_start', 'src_len', 'patch_offset'])


def _normal_chunk(patch):
    print('--- normal chunk ---')
    return NormalChunk(
        src_start=patch.int64(),
        src_len=patch.int64(),
        patch_offset=patch.int64()
    )


DeflateChunk = namedtuple('DeflateChunk', ['src_start', 'src_len', 'offset',
                                           'uncompressed_len', 'len', 'level',
                                           'method', 'window_bits', 'mem_level',
                                           'strategy'])


def _deflate_chunk(patch):
    print('--- deflate chunk ---')
    return DeflateChunk(
        src_start=patch.int64(),
        src_len=patch.int64(),
        offset=patch.int64(),
        uncompressed_len=patch.int64(),
        len=patch.int64(),
        level=patch.int32(),
        method=patch.int32(),
        window_bits=patch.int32(),
        mem_level=patch.int32(),
        strategy=patch.int32(),
    )


def _raw_chunk(fp):
    raise NotImplementedError('--- raw chunk ---')


CHUNK_NORMAL = 0
CHUNK_GZIP = 1
CHUNK_DEFLATE = 2
CHUNK_RAW = 3

chunk_funcs = {
    CHUNK_NORMAL: _normal_chunk,
    CHUNK_DEFLATE: _deflate_chunk,
    CHUNK_RAW: _raw_chunk,
}


if __name__ == '__main__':
    main()
