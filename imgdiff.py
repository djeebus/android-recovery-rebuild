import bsdiff4
import click
import io
import locale
import os.path
import struct
import zipfile
import zlib

from collections import namedtuple

locale.setlocale(locale.LC_ALL, '')
MAGIC_STRING = b'IMGDIFF2'


class SourceReader:
    def __init__(self, fp: io.BytesIO):
        self.fp = fp
        self.len = len(fp.getvalue())

    @property
    def position(self):
        return self.fp.tell()

    @position.setter
    def position(self, value):
        self.fp.seek(value, io.SEEK_SET)

    def read(self, count=None):
        return self.fp.read(count)


class PatchReader:
    def __init__(self, fp):
        self.fp = fp
        self.len = len(fp.getvalue())

    @property
    def position(self):
        return self.fp.tell()

    @position.setter
    def position(self, value):
        self.fp.seek(value, io.SEEK_SET)

    def int32(self):
        data = self.fp.read(4)
        return struct.unpack('i', data)[0]

    def int64(self):
        data = self.fp.read(8)
        return struct.unpack('l', data)[0]

    def text(self, count):
        chars = self.fp.read(count)
        return chars

    def raw(self, count=None):
        data = self.fp.read(count)
        return data


class OutputWriter:
    def __init__(self, fp):
        self.fp = fp

    @property
    def position(self):
        return self.fp.tell()

    @position.setter
    def position(self, value):
        self.fp.seek(value, io.SEEK_SET)

    def write(self, data):
        self.fp.write(data)

    def close(self):
        self.fp.close()


def to_mem_stream(fp):
    mem = io.BytesIO()
    mem.write(fp.read())
    mem.seek(0)
    return mem


@click.group()
def cli():
    pass


@cli.command('from-ota')
@click.argument('ota_zip', type=click.File('rb'))
@click.option('-o', '--output', type=click.File('wb'), default='recovery.img')
def from_ota(ota_zip, output):
    ota_zip = zipfile.ZipFile(ota_zip)
    with ota_zip:
        zip_boot_fp = ota_zip.open('boot.img')
        with zip_boot_fp:
            boot_fp = to_mem_stream(zip_boot_fp)

        zip_patch_fp = ota_zip.open('recovery/recovery-from-boot.p')
        with zip_patch_fp:
            patch_fp = to_mem_stream(zip_patch_fp)

    source = SourceReader(boot_fp)
    patch = PatchReader(patch_fp)

    _make_recovery(output, source, patch)


@cli.command('from-dir')
@click.argument('path', default='.')
@click.option('-o', '--output', type=click.File('wb'), default='recovery.img')
def from_files(path, output):
    path = os.path.abspath(path)
    if not os.path.isdir(path):
        click.echo('%s is not a directory' % path)
        return exit(1)

    boot_path = os.path.join(path, 'boot.img')
    with open(boot_path, 'rb') as fp:
        boot_fp = to_mem_stream(fp)
        source = SourceReader(boot_fp)

    patch_path = os.path.join(path, 'recovery-from-boot.p')
    with open(patch_path, 'rb') as fp:
        patch_fp = to_mem_stream(fp)
        patch = PatchReader(patch_fp)

    bonus_path = os.path.join(path, 'recovery-resource.dat')
    if os.path.isfile(bonus_path):
        with open(bonus_path, 'rb') as fp:
            bonus_fp = to_mem_stream(fp)
            bonus = SourceReader(bonus_fp)
    else:
        bonus = None

    _make_recovery(output, source, patch, bonus)


def _make_recovery(output, source, patch, bonus=None):
    output = OutputWriter(output)
    source_bytes = source.read(source.len)
    output.write(source_bytes)
    output.position = 0

    header = patch.text(len(MAGIC_STRING))
    if header != MAGIC_STRING:
        print('this is not an IMGDIFF2 file: %s' % header)
        exit(1)

    chunk_count = patch.int32()
    print('chunk count: %s' % chunk_count)

    chunks = []
    for _ in range(chunk_count):
        chunk_type = patch.int32()
        chunk_func = read_chunk_funcs[chunk_type]
        chunk = chunk_func(patch)
        chunks.append(chunk)

    for chunk in chunks:
        print('-- processing %s --' % repr(chunk))
        patch.position = chunk.patch_offset

        process_chunk_func = process_chunk_funcs[type(chunk)]
        output_bytes = process_chunk_func(chunk, source, patch, bonus)
        print('>> %s ... [%s bytes] ... %s'
              % (fmt_num(output.position),
                 fmt_num(len(output_bytes)),
                 fmt_num(output.position + len(output_bytes))))
        output.write(output_bytes)

    output.close()


def fmt_num(num):
    return locale.format('%d', num, grouping=True)


NormalChunk = namedtuple('NormalChunk', ['src_start', 'src_len', 'patch_offset'])


def _read_normal_chunk(patch):
    print('--- normal chunk ---')
    return NormalChunk(
        src_start=patch.int64(),
        src_len=patch.int64(),
        patch_offset=patch.int64()
    )


DeflateChunk = namedtuple('DeflateChunk', [
    'src_start', 'src_len', 'patch_offset', 'src_expanded_len', 'target_expected_len',
    'level', 'method', 'window_bits', 'mem_level', 'strategy'])


def _read_deflate_chunk(patch):
    print('--- deflate chunk ---')
    return DeflateChunk(
        src_start=patch.int64(),
        src_len=patch.int64(),
        patch_offset=patch.int64(),
        src_expanded_len=patch.int64(),
        target_expected_len=patch.int64(),

        level=patch.int32(),
        method=patch.int32(),
        window_bits=patch.int32(),
        mem_level=patch.int32(),
        strategy=patch.int32(),
    )


def _read_raw_chunk(fp):
    raise NotImplementedError('--- raw chunk ---')


CHUNK_NORMAL = 0
CHUNK_GZIP = 1
CHUNK_DEFLATE = 2
CHUNK_RAW = 3

read_chunk_funcs = {
    CHUNK_NORMAL: _read_normal_chunk,
    CHUNK_DEFLATE: _read_deflate_chunk,
    CHUNK_RAW: _read_raw_chunk,
}


def _process_normal_chunk(chunk: NormalChunk, source, patch, bonus):
    source.position = chunk.src_start
    src_bytes = source.read(chunk.src_len)

    patch.position = chunk.patch_offset
    patch_bytes = patch.raw()

    output_bytes = bsdiff4.patch(src_bytes, patch_bytes)
    return output_bytes


def _process_deflate_chunk(chunk: DeflateChunk, old_data: SourceReader, patch, bonus):
    patch.position = chunk.patch_offset
    patch_bytes = patch.raw()

    old_data.position = chunk.src_start
    src_bytes = old_data.read(chunk.src_len)
    if len(src_bytes) != chunk.src_len:
        raise Exception('short read')

    decompressor = zlib.decompressobj(-15)
    raw_src_bytes = decompressor.decompress(
        src_bytes, chunk.src_expanded_len,
    )
    if bonus:
        raw_src_bytes += bonus.read()
    if len(raw_src_bytes) != chunk.src_expanded_len:
        raise Exception('uncompressed data is too short (%s != %s)'
                        % (len(raw_src_bytes), chunk.src_expanded_len))

    raw_output_bytes = bsdiff4.patch(raw_src_bytes, patch_bytes)
    if len(raw_output_bytes) != chunk.target_expected_len:
        raise Exception('final uncompressed data is too short: (%s != %s)'
                        % (len(raw_output_bytes), chunk.target_expected_len))

    compressor = zlib.compressobj(
        chunk.level,
        chunk.method,
        chunk.window_bits,
        chunk.mem_level,
        chunk.strategy,
    )
    compressed_output_bytes = compressor.compress(raw_output_bytes)

    return compressed_output_bytes


process_chunk_funcs = {
    NormalChunk: _process_normal_chunk,
    DeflateChunk: _process_deflate_chunk,
}


if __name__ == '__main__':
    cli()
