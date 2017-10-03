import struct
import sys


class ByteStream(object):
    """
    Class to read from little-endian formatted bytestream
    """

    LITTLE_ENDIAN_INT_FORMAT = "<i"
    LITTLE_ENDIAN_SHORT_FORMAT = "<h"
    LITTLE_ENDIAN_LONG_FORMAT = "<l"
    LITTLE_ENDIAN_FLOAT_FORMAT = "<f"
    LITTLE_ENDIAN_DOUBLE_FORMAT = "<d"
    LITTLE_ENDIAN_LONG_LONG_FORMAT = "<q"

    def __init__(self, path):
        self._path = path
        self._file = open(self._path, 'r+b')
        self._file.seek(0, 2)
        self._size = self._file.tell()
        self._file.seek(0)
        self._look_ahead = None
        self._look_ahead_pos = None
        self._look_ahead_index = None

    @property
    def size(self):
        return self._size

    def read_byte(self):
        """
        :return: single byte read from stream (incrementing position in stream)
        """
        return self._file.read(1)[0] if sys.version_info >= (3,) else ord(self._file.read(1)[0])

    def read_short(self):
        """
        :return: short read from stream, with proper endian-ness in mind
        """
        return struct.unpack(ByteStream.LITTLE_ENDIAN_SHORT_FORMAT, self._file.read(2))[0]

    def read_int(self):
        """
        :return: int read from stream, with proper endian-ness in mind
        """
        return struct.unpack(ByteStream.LITTLE_ENDIAN_INT_FORMAT, self._file.read(4))[0]

    def read_long_long(self):
        """
        :return: long read from stream, with proper endian-ness in mind
        """
        return struct.unpack(ByteStream.LITTLE_ENDIAN_LONG_LONG_FORMAT, self._file.read(8))[0]

    def read_float(self):
        """
        :return: float read from stream, with proper endian-ness in mind
        """
        return struct.unpack(ByteStream.LITTLE_ENDIAN_FLOAT_FORMAT, self._file.read(4))[0]

    def read_double(self):
        """
        :return: double read from stream, with proper endian-ness in mind
        """
        return struct.unpack(ByteStream.LITTLE_ENDIAN_DOUBLE_FORMAT, self._file.read(8))[0]

    def read_ints(self, count):
        """
        :param count: the number of ints to read
        :return: request tuple of int value read from stream, with proper endian-ness in mind
        """
        return struct.unpack("<%di" % count, self._file.read(count * 4))

    def read_leb128(self):
        result = 0
        shift = 0
        while True:
            current = self.read_byte()
            result |= ((current & 0x7f) << shift)
            if (current & 0x80) == 0:
                break
            shift += 7
            if shift >= 35:
                raise Exception("LEB128 sequence invalid")
        return result

    def read_bytes(self, byte_count):
        """
        :param byte_count: number of bytes to read
        :return: requested number of bytes read form stream
        """
        return bytes(self._file.read(byte_count))

    def read_string(self):
        """
        :return: null-treminated string read from stream
        """
        pos = self._file.tell()
        result = ""
        byte_data = self._file.read(128)
        while byte_data:
            fmt = "<%ds" % len(byte_data)
            delta = struct.unpack(fmt, byte_data)[0].decode('latin-1').split(chr(0))[0]
            result += delta
            if len(byte_data) == 128 and len(delta) == 128:
                byte_data = self._file.read(128)
            else:
                byte_data = None
        pos += len(result)
        self._file.seek(pos)
        return result

    def read_fixed_string(self, length):
        fmt = "<%ds" % length
        return struct.unpack(fmt, self._file.read(length))[0].decode('latin-1')

    def tell(self):
        return self._file.tell()

    def seek(self, pos):
        return self._file.seek(pos)

    def read(self, count):
        return self._file.read(count)

    def parse_items(self, count, offset, clazz):
        """
        :param count: number of iteams of type clazz to parse
        :param offset: osffset within file to start parsing, or None to start at current location
        :param clazz: `DexParser.Item` subclass to parse into
        :return: collection of requested number of clazz instances parsed from bytestream
        """
        if count == 0:
            return []
        if offset is not None:
            self._file.seek(offset)
        return clazz.get(self, count)

    def parse_one_item(self, offset, clazz):
        if offset is not None:
            self._file.seek(offset)
        return clazz.get(self, 1)[0]

    def parse_descriptor(self, string_id):
        """
        :param string_id: string id to look up
        :return: string value read from byte stream associated with provided string_id
        """
        self._file.seek(string_id.data_offset)
        # read past unused:
        self.read_leb128()
        return self.read_string()

    def parse_method_name(self, method_id):
        """
        :param method_id: id for lookup
        :return: string name of method associated with provided method_id
        """
        string_id = method_id._string_ids[method_id.name_index]
        return self.parse_descriptor(string_id)
