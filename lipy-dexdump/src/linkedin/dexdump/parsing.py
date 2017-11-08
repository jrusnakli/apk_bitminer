import os
import shutil
import sys
import tempfile
import zipfile
from abc import ABCMeta, abstractmethod
from ..dexdump import junit3
from . import ByteStream


WORD_LENGTH = 4


class DexParser(object):
    class FormatException(Exception):
        pass

    class DexMagic(object):
        """
        Magic numbers for validation of dex file
        """
        SIZE_MAGIC_DEX = 3
        SIZE_MAGIC_VERSION = 3

        EXPECTED_DEX = bytes([0x64, 0x65, 0x78]) if sys.version_info >= (3,) else 'dex'
        EXPECTED_VERSION = bytes([0x30, 0x33, 0x35]) if sys.version_info >= (3,) else '035'

        def __init__(self, bytestream):
            self._dex = bytestream.read_bytes(DexParser.DexMagic.SIZE_MAGIC_DEX)
            self._newline = bytestream.read_byte()
            self._version = bytestream.read_bytes(DexParser.DexMagic.SIZE_MAGIC_VERSION)
            self._zero = bytestream.read_byte()

        def validate(self):
            return (self._dex == DexParser.DexMagic.EXPECTED_DEX and
                    self._newline == 0x0A and
                    self._version == DexParser.DexMagic.EXPECTED_VERSION and
                    self._zero == 0x00)

    class Header(object):
        """
        class holding header information from a dex file
        """
        SIZE_SIGNATURE = 20
        EXPECTED_ENDIAN_TAG = 0x12345678

        def __init__(self, bytestream):
            self._magic = DexParser.DexMagic(bytestream)
            self._checksum = bytestream.read_int()
            self._signature = bytestream.read_bytes(DexParser.Header.SIZE_SIGNATURE)
            (self._file_size, self._header_size, self._endian_tag, self._link_size, self._link_offset,
             self._map_offset) = bytestream.read_ints(6)
            self._size_and_offset = {}
            for clazz in [DexParser.StringIdItem, DexParser.TypeIdItem, DexParser.ProtoIdItem,
                          DexParser.FieldIdItem, DexParser.MethodIdItem, DexParser.ClassDefItem,
                          DexParser.ClassDefData]:
                # define for each data class the size and offset of where that class's data is stored
                size, offset = bytestream.read_ints(2)
                self._size_and_offset[clazz] = (size, offset)

        def size_and_offset(self, clazz):
            return self._size_and_offset.get(clazz)

        def validate(self):
            """
            :raises: `DexParser.FormatException` if data read from dex file fails validation checks
            """
            if not self._magic.validate():
                raise DexParser.FormatException("Invalid dex magic in dex file")
            if self._endian_tag != DexParser.Header.EXPECTED_ENDIAN_TAG:
                raise DexParser.FormatException("Invalid endian-ness/tag in dex file")

    ######################################################
    # Various data classes for holding dex-item data
    # These basically pull byte data out of the dex file to be interpreted into various classes of data
    # See Drew Hannay's excellent work in Kotlin on this same feature set on linkedin github:
    #   https://github.com/linkedin/dex-test-parser
    # These classes give a break down of how Android dex files are formatted.  For the curious, feel
    # free to checkout out the android repo and peruse the code to understand the structure :-)
    #

    class Item(object):
        """
        base class for all data items
        """
        __metaclass__ = ABCMeta

        # FORMAT attributes defined here are in convention of Python's struct package, with the
        # exception that "*" at beginning means a variable-sized entity
        FORMAT = "*"

        def __init__(self, bytestream):
            self._bytestream = bytestream

        @classmethod
        def get(cls, bytestream, count):
            import struct
            if cls.FORMAT[0] == '*':
                # have variant-sized or un-type-able objects
                return [cls(bytestream) for _ in range(count)]
            else:
                size = struct.calcsize("<" + cls.FORMAT)
                fmt = "<" + cls.FORMAT
                return [cls(bytestream, item) for item in struct.iter_unpack(fmt, bytestream.read(count * size))] if \
                    sys.version_info >= (3,) else \
                    [cls(bytestream, struct.unpack(fmt, bytestream.read(size))) for _ in range(count)]

    class DescribableItem(Item):
        """
        an Item that has a descriptor associated with it via its type
        """
        __metaclass__ = ABCMeta

        def __init__(self, bytestream):
            super(DexParser.DescribableItem, self).__init__(bytestream)

        @abstractmethod
        def _type_index(self):
            pass

        @property
        def descriptor(self):
            type_id = self._type_ids[self._type_index()]
            string_id = self._string_ids[type_id.descriptor_index]
            return self._bytestream.parse_descriptor(string_id)

    class Annotation(Item):
        FORMAT = "ii"

        def __init__(self, bytestream, vals):
            super(DexParser.Annotation, self).__init__(bytestream)
            self.index, self.annotations_offset = vals

    class AnnotationItem(Item):
        FORMAT = "*b*"

        def __init__(self, bytestream):
            super(DexParser.AnnotationItem, self).__init__(bytestream)
            self.visibility = bytestream.read_byte()
            self.encoded_annotation = bytestream.parse_one_item(None, DexParser.EncodedAnnotation)

    class AnnotationOffsetItem(Item):
        FORMAT = "i"

        def __init__(self, bytestream, vals):
            super(DexParser.AnnotationOffsetItem, self).__init__(bytestream)
            self.annotation_offset = vals[0]

    class AnnotationSetItem(Item):
        FORMAT = "*i*"

        def __init__(self, bytestream):
            super(DexParser.AnnotationSetItem, self).__init__(bytestream)
            size = bytestream.read_int()
            self.entries = self._bytestream.parse_items(size, None, DexParser.AnnotationOffsetItem)

        def __iter__(self):
            for item in self.entries:
                yield item

    class AnnotationElement(Item):
        FORMAT = "*i*"

        def __init__(self, bytestream):
            super(DexParser.AnnotationElement, self).__init__(bytestream)
            self.name_index = bytestream.read_leb128()
            self.value = bytestream.parse_one_item(None, DexParser.EncodedValue)

    class AnnotationsDirectoryItem(Item):
        FORMAT = "*i*"

        def __init__(self, bytestream):
            super(DexParser.AnnotationsDirectoryItem, self).__init__(bytestream)
            self.class_annotations_offset, field_size, annotated_method_size, annotated_parameter_size = \
                bytestream.read_ints(4)
            self.field_annotations = DexParser.Annotation.get(bytestream, field_size)
            self.method_annotations = DexParser.Annotation.get(bytestream, annotated_method_size)
            self.parameter_annotations = DexParser.Annotation.get(bytestream, annotated_parameter_size)

        def get_methods_with_annotation(self, target_descriptor, method_ids):
            """
            :param target_descriptor: annotation of interest, in descriptor format
            :param method_ids: list of MethodIdItems for querying name
            :return: all vritual methods int his directory of that ar annotated with given descriptor
            """
            results = []
            for annotation in self.method_annotations:
                if annotation.annotations_offset == 0:
                    continue
                entries = self._bytestream.parse_one_item(annotation.annotations_offset, DexParser.AnnotationSetItem)
                for entry in entries:
                    item = self._bytestream.parse_one_item(entry.annotation_offset, DexParser.AnnotationItem)
                    if target_descriptor == item.encoded_annotation.descriptor:
                        method_id = method_ids[annotation.index]
                        method_descriptor = self._bytestream.parse_method_name(method_id)
                        results.append(method_descriptor)
                        break
            return set(results)

    class ClassDefItem(DescribableItem):
        FORMAT = "iiiiiiii"

        def __init__(self, bytestream, ints):
            super(DexParser.ClassDefItem, self).__init__(bytestream)
            (self.class_index, self.access_flags, self.super_class_index, self.interfaces_offset,
             self.source_file_index, self.annotations_offset, self.class_data_offset, self.static_values_offset) = ints
            self._super_type = None
            self._descriptor = None
            self._super_descriptor = None

        def _type_index(self):
            return self.class_index

        def super_descriptor(self):
            """
            :return: the string descriptor (cached) of the super class of this class def
            """
            if not self._super_descriptor:
                self._super_descriptor = self.super_type().descriptor
            return self._super_descriptor

        def super_type(self):
            """
            :return: type TypeIdItem of the super class or None if no inheritance
            """
            if self.super_class_index < 0:
                return None
            return self._type_ids[self.super_class_index]

        def has_direct_super_class(self, descriptors):
            """
            :param descriptors: list of descriptor-style class names
            :return: whether this class inherits from one of the classes defined by the given descriptors
            """
            if self.super_class_index < 0:
                return False
            desc = self.super_descriptor()
            return desc in descriptors

    class ClassDefData(Item):
        FORMAT = "*"

        def __init__(self, bytestream):
            super(DexParser.ClassDefData, self).__init__(bytestream)
            static_fields_size = bytestream.read_leb128()
            instance_fields_size = bytestream.read_leb128()
            direct_methods_size = bytestream.read_leb128()
            virtual_methods_size = bytestream.read_leb128()
            self.static_fields = bytestream.parse_items(static_fields_size, None, DexParser.EncodedField)
            self.instance_fields = bytestream.parse_items(instance_fields_size, None, DexParser.EncodedField)
            self.direct_methods = bytestream.parse_items(direct_methods_size, None, DexParser.EncodedMethod)
            self.virtual_methods = bytestream.parse_items(virtual_methods_size, None, DexParser.EncodedMethod)

    class EncodedAnnotation(DescribableItem):
        FORMAT = "*i*"

        def __init__(self, bytestream):
            super(DexParser.EncodedAnnotation, self).__init__(bytestream)
            self.type_index = bytestream.read_leb128()
            size = bytestream.read_leb128()
            self.elements = bytestream.parse_items(size, None, DexParser.AnnotationElement)

        def _type_index(self):
            return self.type_index

    class EncodedItem(Item):
        FORMAT = "*"

        def __init__(self, bytestream):
            super(DexParser.EncodedItem, self).__init__(bytestream)
            self.index_diff = bytestream.read_leb128()
            self.access_flags = bytestream.read_leb128()

    EncodedField = EncodedItem

    class EncodedMethod(EncodedItem):
        FORMAT = "*"

        def __init__(self, bytestream):
            super(DexParser.EncodedMethod, self).__init__(bytestream)
            self.code_offset = bytestream.read_leb128()

        def method_name(self, method_ids):
            method_id = method_ids[self.index_diff]
            return self._bytestream.parse_method_name(method_id)

    class EncodedArray(Item):
        FORMAT = "*"

        def __init__(self, bytestream):
            super(DexParser.EncodedArray, self).__init__(bytestream)
            self.size = bytestream.read_leb128()
            self.value = bytestream.parse_items(self.size, None, DexParser.EncodedValue)

    class EncodedValue(Item):
        FORMAT = "*"

        VALUE_BYTE = 0x00
        VALUE_SHORT = 0x02
        VALUE_CHAR = 0x03
        VALUE_INT = 0x04
        VALUE_LONG = 0x06
        VALUE_FLOAT = 0x10
        VALUE_DOUBLE = 0x11
        VALUE_STRING = 0x17
        VALUE_TYPE = 0x18
        VALUE_FIELD = 0x19
        VALUE_METHOD = 0x1A
        VALUE_ENUM = 0x1B
        VALUE_ARRAY = 0x1C
        VALUE_ANNOTATION = 0x1D
        VALUE_NULL = 0x1E
        VALUE_BOOLEAN = 0x1F

        def __init__(self, bytestream):
            super(DexParser.EncodedValue, self).__init__(bytestream)
            arg_and_type = bytestream.read_byte()
            value_arg = arg_and_type >> 5
            value_type = arg_and_type & 0x1F

            if value_type not in [getattr(self, name) for name in dir(self) if name.startswith("VALUE_")]:
                raise Exception("Value type invalid: %s" % value_type)
            elif value_type == DexParser.EncodedValue.VALUE_BYTE and value_arg + 1 == 1:
                self._value = bytestream.read_byte()
            elif value_type == DexParser.EncodedValue.VALUE_SHORT and value_arg + 1 == 2:
                self._value = bytestream.read_short()
            elif value_type == DexParser.EncodedValue.VALUE_INT and value_arg + 1 == 4:
                self._value = bytestream.read_int()
            elif value_type == DexParser.EncodedValue.VALUE_LONG and value_arg + 1 == 8:
                self._value = bytestream.read_long_long()  # encoding value for long is 8 byte long long
            elif value_type == DexParser.EncodedValue.VALUE_CHAR and value_arg + 1 == 1:
                self._value = chr(bytestream.read_byte())
            elif value_type == DexParser.EncodedValue.VALUE_ENUM:
                self._value = 0
                for index, byte in enumerate(bytestream.read_bytes(value_arg + 1)):
                    base = ord(byte) if sys.version_info <= (3,) else byte
                    self._value += base << index*8  # LITTLE ENDIAN
            elif value_type == DexParser.EncodedValue.VALUE_FLOAT and value_arg + 1 == 4:
                self._value = bytestream.read_float()
            elif value_type == DexParser.EncodedValue.VALUE_DOUBLE and value_arg + 1 == 8:
                self._value = bytestream.read_double()
            elif value_type == DexParser.EncodedValue.VALUE_STRING:
                self._value = bytestream.read_fixed_string(value_arg + 1)
            elif value_type == DexParser.EncodedValue.VALUE_ARRAY:
                self._value = bytestream.parse_one_item(None, DexParser.EncodedArray)
            elif value_type == DexParser.EncodedValue.VALUE_ANNOTATION:
                self._value = bytestream.parse_one_item(None, DexParser.EncodedAnnotation)
            elif value_type == DexParser.EncodedValue.VALUE_NULL:
                self._value = bytes([])
            elif value_type == DexParser.EncodedValue.VALUE_BOOLEAN:
                self._value = bytestream.read_bytes(value_arg) != 0
            else:
                self._value = bytestream.read_bytes(value_arg + 1)

        @property
        def value(self):
            return self._value

    class MemberIdItem(Item):
        FORMAT = "hhi"

        def __init__(self, bytestream, vals):
            super(DexParser.MemberIdItem, self).__init__(bytestream)
            self.class_index, self.type_index, self.name_index = vals

    FieldIdItem = MethodIdItem = MemberIdItem

    class ProtoIdItem(Item):
        FORMAT = "iii"

        def __init__(self, bytestream, ints):
            super(DexParser.ProtoIdItem, self).__init__(bytestream)
            self.shorty_index, self.return_type_index, self.parameters_offset = ints

    class StringIdItem(Item):
        FORMAT = "i"

        def __init__(self, bytestream, offset):
            super(DexParser.StringIdItem, self).__init__(bytestream)
            self.data_offset = offset[0]

    class TypeIdItem(Item):
        FORMAT = "i"

        def __init__(self, bytestream, index):
            super(DexParser.TypeIdItem, self).__init__(bytestream)
            self.descriptor_index = index[0]

        @property
        def descriptor(self):
            string_id = self._string_ids[self.descriptor_index]
            return self._bytestream.parse_descriptor(string_id)

    #
    ##########################################################

    @staticmethod
    def parse(apk_file_name, package_names=None):
        """
        parse all dex files for a given apk
        :param apk_file_name: path to apk to parse
        :param package_names: optional list of packages to filter results
        :return: all test method names for JUnit3 and JUnit4 style tests
        """
        tempd = tempfile.mkdtemp()
        tests = []
        with zipfile.ZipFile(apk_file_name, mode="r") as zf:
            for item in [it for it in zf.filelist if it.filename.endswith('.dex')]:
                path = os.path.join(tempd, item.filename)
                zf.extract(item, tempd)
                parser = DexParser(path, package_names)
                tests += list(parser.find_junit3_tests()) + list(parser.find_junit4_tests())
        shutil.rmtree(tempd)
        return tests

    def __init__(self, file_name, package_names=None):
        self._bytestream = ByteStream(file_name)
        self._headers = DexParser.Header(self._bytestream)
        self._headers.validate()
        self._package_filters = package_names or []
        self._ids = {}
        for clazz in [DexParser.StringIdItem, DexParser.TypeIdItem, DexParser.ProtoIdItem,
                      DexParser.FieldIdItem, DexParser.MethodIdItem, DexParser.ClassDefItem]:
            size, offset = self._headers.size_and_offset(clazz)
            self._ids[clazz] = self._bytestream.parse_items(size, offset, clazz)
            if clazz == DexParser.TypeIdItem:
                DexParser.Item._type_ids = self._ids[clazz]
            elif clazz == DexParser.StringIdItem:
                DexParser.Item._string_ids = self._ids[clazz]

    def find_classes_directly_inherited_from(self, descriptors):
        """
        :param descriptors: descriptor-style list of class names
        :return: all classes that are directly inherited form one of the classes described by the descriptors
        """
        matching_classes = []
        fixed_set = set(descriptors)
        for clazz in [c for c in self._ids[DexParser.ClassDefItem] if c.has_direct_super_class(fixed_set)]:
            type_id = self._ids[DexParser.TypeIdItem][clazz.class_index]
            matching_classes.append(clazz)
            string_id = self._ids[DexParser.StringIdItem][type_id.descriptor_index]
            descriptors.append(self._bytestream.parse_descriptor(string_id))
        return matching_classes

    def find_method_names(self, class_def):
        """
        :param class_def: `DexParser.ClassDefItem` from which to find names
        :return: all method names for a given class def
        """
        class_data = self._bytestream.parse_one_item(class_def.class_data_offset, DexParser.ClassDefData)
        return [m.method_name(self._ids[DexParser.MethodIdItem]) for m in class_data.virtual_methods]

    @staticmethod
    def _descriptor2name(name):
        """
        :return: the name reformatted into the format expected for parameter-passing to an adb am isntrument command
        """
        return name[1:-1].replace('/', '.')

    def find_junit3_tests(self, descriptors=list(junit3.Junit3Processor.DEFAULT_DESCRIPTORS)):
        """
        :param descriptors:  which test classes to look for as proper test case classes
        :return: all test methods per Junit3 conventions
        """
        test_classes = self.find_classes_directly_inherited_from(descriptors)
        method_names = []

        for class_def in test_classes:
            dot_sep_name = self._descriptor2name(class_def.descriptor)
            if self._package_filters and all([dot_sep_name not in f for f in self._package_filters]):
                continue
            method_names += [m for m in self.find_method_names(class_def) if m.startswith("test")]

        return set(method_names)

    def find_junit4_tests(self):
        """
        :return: all tests annotated under Junit4 conventions
        """
        test_annotation_descriptor = "Lorg/junit/Test;"
        ignored_annotation_descriptor = "Lorg/junit/Ignore;"
        result = []
        for class_def in [c for c in self._ids[DexParser.ClassDefItem] if c.annotations_offset != 0]:
            dot_sep_name = self._descriptor2name(class_def.descriptor)
            if self._package_filters and all([f not in dot_sep_name for f in self._package_filters]):
                continue
            directory = self._bytestream.parse_one_item(class_def.annotations_offset,
                                                        DexParser.AnnotationsDirectoryItem)
            names = directory.get_methods_with_annotation(test_annotation_descriptor,
                                                          self._ids[DexParser.MethodIdItem])
            ignored_names = directory.get_methods_with_annotation(ignored_annotation_descriptor,
                                                                  self._ids[DexParser.MethodIdItem])
            result += [dot_sep_name + "#" + name for name in names if name not in ignored_names]

        return set(result)


class AXMLParser(object):

    XML_END_DOC_TAG = 0x00100101
    XML_START_TAG = 0x00100102
    XML_START_END_TAG = 0x00100103

    START_NS = 0x00100100
    END_NS = 0x00100101

    # These classes mimic the AndroidManifest.xml structure

    class Instrumentation(object):
        """
        Class to capture content of <instrumentation/> tag in AndroidManifest XML
        """

        def __init__(self, runner, functional_test, handle_profiling, label, target_package):
            self._runner = runner
            self._functional_test = functional_test
            self._handle_profiling = handle_profiling
            self._label = label
            self._target_package = target_package

        @property
        def runner(self):
            return self._runner

        @property
        def functional_test(self):
            return self._functional_test

        @property
        def handle_profiling(self):
            return self._handle_profiling

        @property
        def label(self):
            return self._label

        @property
        def target_package(self):
            return self._target_package

    class UsesSdk(object):
        """
        Class to capture content of <uses-sdk/> tag in AndroidManifest XML
        """

        def __init__(self, min_sdk_version, target_sdk_version):
            self._min_sdk_version = min_sdk_version
            self._target_sdk_version = target_sdk_version

        @property
        def min_sdk_version(self):
            return self._min_sdk_version

        @property
        def target_sdk_version(self):
            return self._target_sdk_version

    def __init__(self, bytestream):
        self._header = AXMLParser.Header(bytestream)
        tag_list = self.parse_items(bytestream=bytestream)
        #  ns_list = [item for item in tag_list if isinstance(item, AXMLParser.NSRecord)]
        xml_tag_list = [item for item in tag_list if isinstance(item, AXMLParser.XMLTag)]
        self._xml_tag = xml_tag_list[0] if xml_tag_list else None
        self._instrumentation = None
        self._uses_sdk = None
        self._permissions = []
        if self._xml_tag:
            current_tag = self._xml_tag
            for tag in xml_tag_list[1:]:
                if tag.is_start_tag:
                    current_tag.children.append(tag)
                    tag.parent_tag = current_tag
                    current_tag = tag
                elif not current_tag.parent_tag:
                    break
                else:  # end tag
                    current_tag = current_tag.parent_tag
        self._process_tags()

    def parse_items(self, bytestream):
        items = []
        while True:
            first_word = bytestream.read_int()
            bytestream.read_int()  # unused chunk size
            bytestream.read_int()  # unused line number
            bytestream.read_int()  # unused, unknown
            if first_word in [AXMLParser.XML_START_TAG, AXMLParser.XML_START_END_TAG]:
                items.append(AXMLParser.XMLTag(self, bytestream, first_word == AXMLParser.XML_START_TAG))
            elif first_word == AXMLParser.XML_END_DOC_TAG:
                break
            elif first_word in [AXMLParser.START_NS, AXMLParser.END_NS]:
                items.append(AXMLParser.NSRecord(bytestream, first_word == AXMLParser.START_NS))
            else:
                raise Exception("Invalid XML element start code %d in android xml" % first_word)
        return items

    def _process_tags(self):
        # for now, only process instrumentation tag if present
        if not self._xml_tag or self._xml_tag.name != "manifest":
            print("No manifest tag at root level found")
            self._instrumentation = None
        else:
            attrs_dict = {attr.name: attr.value for attr in self._xml_tag.attributes}
            self._package_name = attrs_dict.get('package')
            for child in self._xml_tag.children:
                attrs_dict = {attr.name: attr.value for attr in child.attributes}
                if child.name == "instrumentation":
                    runner = attrs_dict.get("name")
                    functional_test = attrs_dict.get("functionalTest") in ["true", True]
                    handle_profiling = attrs_dict.get("handleProfiling") == ["true", True]
                    label = attrs_dict.get("label")
                    target_package = attrs_dict.get("targetPackage")
                    self._instrumentation = AXMLParser.Instrumentation(runner=runner,
                                                                       functional_test=functional_test,
                                                                       handle_profiling=handle_profiling,
                                                                       label=label,
                                                                       target_package=target_package)
                elif child.name == "uses-sdk":
                    target_sdk_version = attrs_dict.get("targetSdkVersion")
                    min_sdk_version = attrs_dict.get("minSdkVersion")
                    target_sdk_version = int(target_sdk_version.split(' ')[1], 16)
                    min_sdk_version = int(min_sdk_version.split(' ')[1], 16)
                    self._uses_sdk = AXMLParser.UsesSdk(target_sdk_version=target_sdk_version,
                                                        min_sdk_version=min_sdk_version)
                elif child.name == "uses-permission":
                    self._permissions.append(attrs_dict["name"])

    @property
    def instrumentation(self):
        return self._instrumentation

    @property
    def uses_sdk(self):
        return self._uses_sdk

    @property
    def permissions(self):
        return self._permissions

    @property
    def package_name(self):
        return self._package_name

    @property
    def xml_head(self):
        return self._xml_tag

    class Header(object):
        # Format:
        # 9 32 bit words in header (little endian)
        #  0th word: always 0x00080003 (EXPECTED_TAG)
        #  3rd word: Offest at end of String Table
        #  4th word: number of string in string table
        #  other words:  unknown and unused
        EXPECTED_TAG = 0x00080003
        EXPECTED_STRING_TAG = 0x001c0001
        EXPECTED_RESOURCE_TAG = 0x00080180

        def __init__(self, bytestream):
            self._tag = bytestream.read_int()
            if self._tag != AXMLParser.Header.EXPECTED_TAG:
                raise Exception("Poorly formatted android XML binary file")
            self._file_size = bytestream.read_int()
            if bytestream.read_int() != AXMLParser.Header.EXPECTED_STRING_TAG:
                raise Exception("Poorly formatted android XML binary file")
            string_chunk_size = bytestream.read_int()  # unused
            self._string_count = bytestream.read_int()
            self._style_count = bytestream.read_int()
            bytestream.read_int()  # unused
            self._string_raw_data_offset = bytestream.read_int()
            self._style_raw_data_offset = bytestream.read_int()
            self._string_offset = [bytestream.read_int() for _ in range(self._string_count)]
            # skip style offset table
            bytestream.seek(bytestream.tell() + self._style_count * WORD_LENGTH)
            # skip string raw data:
            length = (string_chunk_size if self._style_raw_data_offset == 0 else self._style_raw_data_offset) - self._string_raw_data_offset
            self._string_raw_data_offset = bytestream.tell()
            bytestream.seek(bytestream.tell() + length)
            # skip style raw data
            if self._style_raw_data_offset != 0:
                bytestream.seek(bytestream.tell() + (string_chunk_size - self._style_raw_data_offset)*WORD_LENGTH)
            tag = bytestream.read_int()
            if tag != AXMLParser.Header.EXPECTED_RESOURCE_TAG:
                raise Exception("Poorly formatted android XML binary file")
            self._resource_chunk_size = bytestream.read_int()
            if self._resource_chunk_size % 4 != 0:
                raise Exception("Poorly formatted android XML binary file")
            self.no_entries = self._resource_chunk_size/4
            bytestream.seek(bytestream.tell() + self._resource_chunk_size - 8)

    class StringItem(object):

        def __init__(self, bytestream):
            self._length = bytestream.read_short()
            if int(self._length/256) == self._length % 256:
                self._length = self._length % 256  # newer Axml seems to dup the length (??)
                bytes = bytestream.read_bytes(self._length)
                text = bytes.decode('utf-8')
            else:
                bytes = bytestream.read_bytes(self._length*2)
                text = bytes.decode('utf-16')
            self._value = text

        @classmethod
        def get(cls, bytestream, count):
            return [cls(bytestream) for _ in range(count)]

        def __str__(self):
            return self._value if self._value is not None else ""

    class XMLAttr(object):
        # 0th word: string index of attribute's namespace name or -1 if default namespace
        # 1st word: string index of attribute's name
        # 2nd word: string index of attribute's value of -1 if resource id is to be used
        # 3rd word: unused (flags of some sort?)
        # 4th word: resource id, if used

        def __init__(self, parser, bytestream):
            ns_offset = bytestream.read_int()
            name_offset = bytestream.read_int()
            val_offset = bytestream.read_int()
            bytestream.read_int()  # unused
            resourceId = bytestream.read_int()
            self._ns = parser._get_string(bytestream, ns_offset) if ns_offset >= 0 else ""
            self._name = parser._get_string(bytestream, name_offset)
            self._value = parser._get_string(bytestream, val_offset) if val_offset >= 0 else None
            if self._value is None and resourceId >= 0:
                self._value = "resourceID " + hex(resourceId)

        @property
        def name(self):
            return str(self._name)

        @property
        def value(self):
            return str(self._value)

        @classmethod
        def get(cls, parser, bytestream, count):
            return [cls(parser, bytestream) for _ in range(count)]

        def __str__(self):
            return "%s='%s'" % (self._name, self._value) if self._value is not None else str(self._name)

    class XMLTag(object):

        # All tags have:
        #   0th word: indicates XML_START_TAG or end XML_END_TAG
        #   1st word: unused flag
        #   2nd word: line in original text source file
        #   3rd word: unused
        #   4th word: string index of namespace name
        #   5th word: string index of element name
        # Start tags only:
        #   6th word: unused
        #   7th word: number of attributes in element
        #   8th word: unused

        def __init__(self, parser, bytestream, is_start_tag):
            self._is_start_tag = is_start_tag
            ns_offset = bytestream.read_int()
            element_name_offset = bytestream.read_int()
            if self._is_start_tag:  # elements have 3 more words:
                bytestream.read_int()  # unused
                self._attr_count = bytestream.read_int()
                bytestream.read_int()  # unused
                self._attributes = AXMLParser.XMLAttr.get(parser, bytestream, self._attr_count)
            else:
                self._attributes = []
            self._ns_name = parser._get_string(bytestream, ns_offset) if ns_offset >= 0 else ""
            self._element_name = parser._get_string(bytestream, element_name_offset)
            self.children = []
            self.parent_tag = None

        @property
        def attributes(self):
            return self._attributes

        @property
        def is_start_tag(self):
            return self._is_start_tag

        @property
        def is_end_tag(self):
            return not self._is_start_tag

        @property
        def name(self):
            return str(self._element_name)

        @classmethod
        def get(cls, bytestream, count):
            tags = []
            while True:
                tag = cls(bytestream)
                tags.append(tag)
            return tags

        def __str__(self):
            content = " ".join([str(attr) for attr in self._attributes])
            child_content = "\n  ".join([str(child) for child in self.children])
            text = "<%(name)s  %(content)s>\n  %(children)s\n</%(name)s>" % {
                'name': self._element_name,
                'content': content,
                'children': child_content
            }
            return text

    class NSRecord(object):

        def __init__(self, bytestream, is_start):
            self._is_start = is_start
            self._prefix = bytestream.read_int()
            self._uri = bytestream.read_int()

    def _get_string(self, bytestream, str_index):
        if str_index < 0:
            return None
        if str_index >= len(self._header._string_offset):
            return ""
        offset = bytestream.tell()
        try:
            bytestream.seek(self._header._string_raw_data_offset + self._header._string_offset[str_index])
            return AXMLParser.StringItem(bytestream)
        finally:
            bytestream.seek(offset)

    @staticmethod
    def parse(apk_file_name):
        """
        parse manifest file for a given apk
        :param apk_file_name: path to apk to parse
        :return: all xml tags
        """
        tempd = tempfile.mkdtemp()
        with zipfile.ZipFile(apk_file_name, mode="r") as zf:
            zf.extract("AndroidManifest.xml", tempd)
            bytestream = ByteStream(os.path.join(str(tempd), "AndroidManifest.xml"))
            parser = AXMLParser(bytestream)
        shutil.rmtree(tempd)
        return parser

    @property
    def xml(self):
        return str(self.xml_head)


def main():
    if len(sys.argv) < 2:
        print("Usage: dexdump <apk-file-name> [package-name1] [package-name2]...")
        sys.exit(-1)
    else:
        for test in DexParser.parse(sys.argv[1], sys.argv[2:]):
            print(test)


def main_axml():
    if len(sys.argv) < 2:
        sys.exit(-1)
    else:
        parser = AXMLParser.parse(sys.argv[1])
        sys.stdout.write(parser.xml)
