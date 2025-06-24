
# Name: vdump.py
# Version: 1.0.0
# Author: RenardDev (zeze839@gmail.com)

# --------------------
# Imports
# --------------------

# Python

import argparse
import hashlib
import sys
import os
import configparser
import collections
import copy
import struct
import re

from pathlib import Path

# IDA

IDALIB_MODE = False
try:
    import ida_pro
except (ImportError, ModuleNotFoundError):
    try:
        import idapro
        IDALIB_MODE = True
    except (ImportError, ModuleNotFoundError):
        pass

import ida_idaapi
import ida_ua
import ida_bytes
import ida_pro
import ida_auto
import ida_ida
import ida_funcs
import ida_nalt
import ida_kernwin
import ida_name
import ida_xref
import ida_segment
import ida_idp
import ida_hexrays
import ida_idc
import ida_typeinf
import ida_loader

# --------------------
# Base functions
# --------------------

def print_message(*args, **kwargs):
    message = ' '.join(map(str, args))
    if IDALIB_MODE:
        print(f'[vdump] {message}', **kwargs)
    else:
        ida_kernwin.msg(f'[vdump] {message}\n')

def is_valid_address(address, min_address = None, max_address = None):
    min_address = ida_ida.inf_get_min_ea() if min_address is None else min_address
    max_address = ida_ida.inf_get_max_ea() if max_address is None else max_address
    return address and address != ida_idaapi.BADADDR and min_address <= address <= max_address

def find_pattern(pattern, min_address = None, max_address = None):
    if not pattern:
        return 0

    min_address = ida_ida.inf_get_min_ea() if min_address is None else min_address
    max_address = ida_ida.inf_get_max_ea() if max_address is None else max_address

    patterns = ida_bytes.compiled_binpat_vec_t()
    encoding = ida_nalt.get_default_encoding_idx(ida_nalt.BPU_1B)

    if ida_bytes.parse_binpat_str(patterns, 0, pattern, 16, encoding):
        return 0

    address, _ = ida_bytes.bin_search(min_address, max_address, patterns, ida_bytes.BIN_SEARCH_FORWARD | ida_bytes.BIN_SEARCH_NOBREAK | ida_bytes.BIN_SEARCH_NOSHOW)
    return address if is_valid_address(address) else 0

def format_name(name):
    name = name.replace('const', '')
    name = name.replace('volatile', '')
    name = re.sub('`[^`\']*\'', '', name)
    name = name.replace('::', '_')
    name = name.replace('(', '_')
    name = name.replace('<', '_')
    name = name.replace(',', '_')
    name = name.replace('>', '_')
    name = name.replace('&', '_')
    name = name.replace('?', '_')
    name = name.replace('@', '_')
    name = name.replace(')', '_')
    name = name.replace('[', '_')
    name = name.replace(']', '_')
    name = re.sub('\\s+', '_', name)
    name = re.sub('\\(.*\\*\\)\\(.*\\)', '', name)
    name = name.replace('*', '')
    name = re.sub('\\_+', '_', name)
    name = name.removeprefix('__')
    name = name.removeprefix('_')
    name = name.removesuffix('__')
    name = name.removesuffix('_')
    return name

def normalize_tinfo(t):
    if not t.is_correct() or not t.is_well_defined():
        return 'void*'
    
    if (t.is_ptr() or
        t.is_array() or
        t.is_func() or
        t.is_funcptr() or
        t.is_sue() or
        t.is_udt() or
        t.is_typedef() or
        t.is_typeref() or
        t.is_aliased() or
        t.is_complex() or
        t.is_bitfield() or
        t.is_enum() or
        t.is_struct() or
        t.is_union() or
        t.is_forward_decl() or
        t.is_forward_enum() or
        t.is_forward_struct() or
        t.is_forward_union() or
        t.is_varstruct() or
        t.is_varmember() or
        t.is_vftable() or
        t.is_sse_type() or
        t.is_tbyte() or
        t.is_unknown() or
        t.is_decl_array() or
        t.is_decl_bitfield() or
        t.is_decl_complex() or
        t.is_decl_enum() or
        t.is_decl_func() or
        t.is_decl_ptr() or
        t.is_decl_struct() or
        t.is_decl_sue() or
        t.is_decl_typedef() or
        t.is_decl_udt() or
        t.is_decl_unknown() or
        t.is_decl_paf() or
        t.is_decl_partial() or
        t.is_decl_tbyte() or
        t.is_anonymous_udt() or
        t.is_bitmask_enum() or
        t.is_empty_enum() or
        t.is_empty_udt() or
        t.is_fixed_struct() or
        t.is_from_subtil() or
        t.is_high_func() or
        t.is_purging_cc() or
        t.is_shifted_ptr() or
        t.is_small_udt() or
        t.is_user_cc() or
        t.is_vararg_cc() or
        t.is_frame()):
        return 'void*'

    if t.is_void() or t.is_decl_void():
        return 'void'

    if t.is_bool() or t.is_decl_bool():
        return 'bool'

    if t.is_char() or t.is_decl_char():
        return 'char' if t.is_signed() else 'unsigned char'
    
    if t.is_uchar() or t.is_decl_uchar():
        return 'unsigned char'

    if t.is_float() or t.is_decl_float():
        return 'float'
    
    if t.is_double() or t.is_decl_double():
        return 'double'
    
    if t.is_ldouble():
        return 'long double'

    size = t.get_size()
    if t.is_integral() or t.is_arithmetic() or t.is_decl_arithmetic():
        if t.is_signed() or (not t.is_unsigned() and not t.is_decl_uint()):
            if t.is_int16() or t.is_decl_int16():
                return 'short'
            if t.is_int32() or t.is_decl_int32():
                return 'int'
            if t.is_int64() or t.is_decl_int64():
                return 'long long'
            if t.is_int128() or t.is_decl_int128():
                return 'void*'
            if t.is_int() or t.is_decl_int():
                return 'int' if size != 1 else 'char'

            return {1: 'chat', 2: 'short', 4: 'int', 8: 'long long', 16: 'void*'}.get(size, 'int')

        else:
            if t.is_uint16() or t.is_decl_uint16():
                return 'unsigned short'
            if t.is_uint32() or t.is_decl_uint32():
                return 'unsigned int'
            if t.is_uint64() or t.is_decl_uint64():
                return 'unsigned long long'
            if t.is_uint128() or t.is_decl_uint128():
                return 'void*'
            if t.is_uint() or t.is_decl_uint():
                return 'unsigned int' if size != 1 else 'unsigned char'

            return {1: 'unsigned char', 2: 'unsigned short', 4: 'unsigned int', 8: 'unsigned long long', 16: 'void*'}.get(size, 'unsigned int')

    if t.is_floating() or t.is_decl_floating():
        return {4: 'float', 8: 'double', 10: 'long double', 16: 'long double'}.get(size, 'double')

    return 'void*'

class DeclarationConverter:
    def __init__(self):
        self.reset_state()

    def reset_state(self):
        self.class_map = {}
        self.reverse_graph = {}
        self.in_degree = {}
        self.declare = set()
        self.used_func_names = {}
        self.class_vfuncs = {}

    def convert(self, trees, class_vfuncs):
        self.reset_state()
        self.class_vfuncs = class_vfuncs
        
        for tree in trees:
            if tree is not None:
                self.process_tree(tree)
                
        return self.generate_declarations()

    def process_tree(self, root_node):
        stack = [root_node]
        while stack:
            node = stack.pop()
            class_name = format_name(node[1])

            if class_name in self.class_map:
                continue

            base_names = []
            for base_node in node[2]:
                if base_node is None:
                    continue
                base_name = format_name(base_node[1])
                base_names.append(base_name)
                if base_name not in self.class_map:
                    stack.append(base_node)

            self.class_map[class_name] = base_names
            for base in base_names:
                self.reverse_graph.setdefault(base, []).append(class_name)
            self.in_degree[class_name] = len(base_names)
            
            for base in base_names:
                if base not in self.in_degree:
                    self.in_degree[base] = 0

    def generate_declarations(self):
        queue = collections.deque([cls for cls, deg in self.in_degree.items() if deg == 0])
        sorted_classes = []
        while queue:
            cls = queue.popleft()
            sorted_classes.append(cls)
            for derived in self.reverse_graph.get(cls, []):
                self.in_degree[derived] -= 1
                if self.in_degree[derived] == 0:
                    queue.append(derived)
        
        forward_decls = set()
        class_declarations = []
        class_name_map = {}
        
        for cls in sorted_classes:
            if cls in self.class_vfuncs:
                for offset in self.class_vfuncs[cls]:
                    offset_name = f'{cls}_{offset:08X}'
                    class_name_map[(cls, offset)] = offset_name

                    forward_decls.add(f'class {offset_name}; // OFFSET: {offset:08X}')
                    
                    decl_lines = [
                        f'class {offset_name} {{ // OFFSET: {offset:08X}',
                        'public:'
                    ]
                    
                    for idx, (func, demangled) in enumerate(self.class_vfuncs[cls][offset]):
                        if not demangled:
                            continue
    
                        demangled = demangled.replace('`non-virtual thunk to\'', '')

                        decl = self.process_function(idx, func, demangled, cls, offset)
                        decl_lines.append(f'    // {idx:>10} - {demangled}')
                        decl_lines.append(f'    {decl}\n')
                    
                    decl_lines.extend([
                        '};'
                    ])
                    
                    class_declarations.append('\n'.join(decl_lines))
        
        for cls in self.declare:
            if cls not in sorted_classes:
                forward_decls.add(f'class {cls} {{}};')
        
        return '\n' + \
               '\n'.join(sorted(forward_decls)) + \
               '\n\n' + \
               '\n\n'.join(class_declarations)

    def process_function(self, idx, func, demangled, cls, offset):

        if demangled[:19] == '___cxa_pure_virtual' or demangled[:10] == '__purecall':
            return f'virtual void PureStub_{idx:010}() = 0;'

        type = None
        decompiled = ida_hexrays.decompile(func)
        if decompiled:
            type = decompiled.type
            ret_type = type.get_rettype()
            ret_type.clr_decl_const_volatile()
            ret_str = self.simplify_type(ret_type)
        else:
            if f := ida_funcs.get_func(func):
                type = f.prototype
            ret_str = 'void'

        if not type or '?' in demangled or '@' in demangled or '$' in demangled:
            return f'virtual void InvalidStub_{idx:010}() = 0;'

        args = []
        for i in range(1, type.get_nargs()):
            arg = type.get_nth_arg(i)
            arg.clr_decl_const_volatile()
            arg_str = self.simplify_type(arg)
            if i > 1 and arg_str == 'void':
                arg_str = 'void*'
            elif i == 1 and type.get_nargs() > 1 and arg_str == 'void':
                arg_str = 'void*'
            args.append(arg_str)

        if demangled.count('(') > 1:
            return f'virtual void TupleStub_{idx:010}({', '.join(args)}) = 0;'

        if ida_bytes.has_dummy_name(ida_bytes.get_flags(func)):
            return f'virtual void Stub_{idx:010}({', '.join(args)}) = 0;'

        if demangled[:8] == 'nullsub_':
            return f'virtual void NullStub_{idx:010}({', '.join(args)}) = 0;'

        if demangled.startswith('~') or 'destructor' in demangled or '~' in demangled:
            return f'virtual ~{cls}_{offset:08X}() = 0;'

        func_name = demangled.split('(')[0].split('::')[-1]

        #if '<' in func_name or '>' in func_name:
        #    return f'virtual void TemplateStub_{idx:010}({', '.join(args)}) = 0;'

        self.used_func_names.setdefault((cls, offset), {}).setdefault(func_name, 0)
        self.used_func_names[(cls, offset)][func_name] += 1
        count = self.used_func_names[(cls, offset)][func_name]
        final_name = f'{func_name}{count}' if count > 1 else func_name

        return f'virtual {ret_str} {final_name}({', '.join(args)}) = 0;'

    def is_known_type(self, tif):
        if not tif:
            return False

        if tif.is_ptr():
            return True

        tif = ida_typeinf.remove_pointer(tif)
        if tif:
            if tif.is_void():
                return True

            return tif.get_realtype(full=True)

        return False

    def simplify_type(self, tif):
        if not tif:
            return 'void'
            
        tif.clr_decl_const_volatile()

        name = normalize_tinfo(tif)
        name = name.replace('_anonymous_namespace_::', '')
        if not self.is_known_type(tif):
            name = format_name(name)
            self.declare.add(name)
        return name

def get_vtable_functions(vtable):

    funcs = []
    is_64bit = ida_ida.inf_is_64bit()
    i = 0
    destructor_count = 0

    filetype = ida_ida.inf_get_filetype()

    if filetype == ida_ida.f_ELF or filetype == ida_ida.f_MACHO: # ELF / MACHO
        ___cxa_pure_virtual = ida_name.get_name_ea(0, '___cxa_pure_virtual')

    while True:
        if is_64bit:
            if not ida_bytes.is_off(ida_bytes.get_flags(vtable + 8 * i), 0):
                break
        else:
            if not ida_bytes.is_off(ida_bytes.get_flags(vtable + 4 * i), 0):
                break

        if is_64bit:
            func = ida_bytes.get_qword(vtable + 8 * i)
        else:
            func = ida_bytes.get_dword(vtable + 4 * i)

        if not ida_funcs.get_func(func):
            if filetype == ida_ida.f_ELF or filetype == ida_ida.f_MACHO:
                if func != ___cxa_pure_virtual:
                    break
            elif filetype == ida_ida.f_PE:
                flags = ida_bytes.get_flags(func)
                if not ida_bytes.is_code(flags):
                    break

        demangled = ida_name.get_demangled_name(func, 0, 0)
        if not demangled:
            i += 1
            continue

        if demangled and '::~' in demangled:
            destructor_count += 1
            if destructor_count == 2:
                i += 1
                continue
        else:
            destructor_count = 0

        funcs.append((func, demangled))
        i += 1

    return funcs

# --------------------
# ELF / MACHO
# --------------------

def find_type_infos():
    type_infos = []

    filetype = ida_ida.inf_get_filetype()
    is_64bit = ida_ida.inf_is_64bit()

    if filetype == ida_ida.f_ELF or filetype == ida_ida.f_MACHO: # ELF / MACHO
        type_addresses = (
            ida_name.get_name_ea(ida_idaapi.BADADDR, '__ZTVN10__cxxabiv117__class_type_infoE'),    # Single
            ida_name.get_name_ea(ida_idaapi.BADADDR, '__ZTVN10__cxxabiv120__si_class_type_infoE'), # One parent
            ida_name.get_name_ea(ida_idaapi.BADADDR, '__ZTVN10__cxxabiv121__vmi_class_type_infoE') # Multiple parents
        )

        # Iterate all types

        for type_address in type_addresses:
            if not is_valid_address(type_address):
                continue

            type_reference = ida_xref.get_first_dref_to(type_address)
            while is_valid_address(type_reference):

                if is_64bit:
                    name_address = ida_bytes.get_qword(type_reference + 8)
                else:
                    name_address = ida_bytes.get_dword(type_reference + 4)

                if not is_valid_address(name_address):
                    type_reference = ida_xref.get_next_dref_to(type_address, type_reference)
                    continue

                name = ida_bytes.get_strlit_contents(name_address, -1, 0)

                name = name.decode()
                demangled_name = ida_name.demangle_name('__ZTI' + name, ida_name.MNG_NOECSU | ida_name.MNG_ZPT_SPACE)
                if not demangled_name:
                    type_reference = ida_xref.get_next_dref_to(type_address, type_reference)
                    continue
                demangled_name = demangled_name.replace('`typeinfo for\'', '')
                type_infos.append((type_reference, demangled_name))

                type_reference = ida_xref.get_next_dref_to(type_address, type_reference)

    return type_infos

def get_typeinfo_bases(typeinfo_address, type_infos, visited=None):
    if visited is None:
        visited = set()

    if typeinfo_address in visited:
        return None
    visited.add(typeinfo_address)
    
    TYPE_INFO_ADDRESSES = [
        ida_name.get_name_ea(ida_idaapi.BADADDR, '__ZTVN10__cxxabiv117__class_type_infoE'),
        ida_name.get_name_ea(ida_idaapi.BADADDR, '__ZTVN10__cxxabiv120__si_class_type_infoE'),
        ida_name.get_name_ea(ida_idaapi.BADADDR, '__ZTVN10__cxxabiv121__vmi_class_type_infoE'),
    ]
    
    is_64bit = ida_ida.inf_is_64bit()
    type_base = ida_name.get_name_base_ea(typeinfo_address, 0)
    bases = []
    name = None

    for address, demangled in type_infos:
        if address == typeinfo_address:
            name = demangled
            break

    if not name:
        return None

    if type_base == TYPE_INFO_ADDRESSES[0]:
        pass
    elif type_base == TYPE_INFO_ADDRESSES[1]:
        if is_64bit:
            base_address = ida_bytes.get_qword(typeinfo_address + 16)
        else:
            base_address = ida_bytes.get_dword(typeinfo_address + 8)
        
        base_node = get_typeinfo_bases(base_address, type_infos, visited)
        if base_node:
            bases.append(base_node)
    elif type_base == TYPE_INFO_ADDRESSES[2]:
        if is_64bit:
            base_count = ida_bytes.get_dword(typeinfo_address + 20)
            base_offset = 24
            entry_size = 16
        else:
            base_count = ida_bytes.get_dword(typeinfo_address + 12)
            base_offset = 16
            entry_size = 8
        
        for i in range(base_count):
            if is_64bit:
                base_address = ida_bytes.get_qword(typeinfo_address + base_offset + i * entry_size)
            else:
                base_address = ida_bytes.get_dword(typeinfo_address + base_offset + i * entry_size)

            if base_address == typeinfo_address:
                continue

            base_node = get_typeinfo_bases(base_address, type_infos, visited)
            if base_node:
                bases.append(base_node)
    
    visited.remove(typeinfo_address)
    return [typeinfo_address, name, bases]

def find_vtables_typeinfo(typeinfo):
    vtables = []

    filetype = ida_ida.inf_get_filetype()
    is_64bit = ida_ida.inf_is_64bit()

    if filetype == ida_ida.f_ELF or filetype == ida_ida.f_MACHO: # ELF / MACHO
        vtable_reference = ida_xref.get_first_dref_to(typeinfo)
        while is_valid_address(vtable_reference):
            if is_64bit:
                offset = ida_bytes.get_qword(vtable_reference - 8)
            else:
                offset = ida_bytes.get_dword(vtable_reference - 4)

            if offset != 0 and offset <= 0x7FFFFFFF:
                if is_64bit:
                    if not ida_bytes.is_off(ida_bytes.get_flags(vtable_reference - 8), 0):
                        vtable_reference = ida_xref.get_next_dref_to(typeinfo, vtable_reference)
                        continue
                else:
                    if not ida_bytes.is_off(ida_bytes.get_flags(vtable_reference - 4), 0):
                        vtable_reference = ida_xref.get_next_dref_to(typeinfo, vtable_reference)
                        continue

            if is_64bit:
                offset = offset.to_bytes(8, byteorder='little', signed=False)
            else:
                offset = offset.to_bytes(4, byteorder='little', signed=False)

            offset = int(-1 * int.from_bytes(offset, byteorder='little', signed=True))
            if offset < 0: # HACK: NOT GOOD! But works...
                vtable_reference = ida_xref.get_next_dref_to(typeinfo, vtable_reference)
                continue

            if is_64bit:
                if not ida_bytes.is_off(ida_bytes.get_flags(vtable_reference + 8), 0):
                    vtable_reference = ida_xref.get_next_dref_to(typeinfo, vtable_reference)
                    continue
                if not ida_funcs.get_func(ida_bytes.get_qword(vtable_reference + 8)):
                    vtable_reference = ida_xref.get_next_dref_to(typeinfo, vtable_reference)
                    continue
            else:
                if not ida_bytes.is_off(ida_bytes.get_flags(vtable_reference + 4), 0):
                    vtable_reference = ida_xref.get_next_dref_to(typeinfo, vtable_reference)
                    continue
                if not ida_funcs.get_func(ida_bytes.get_dword(vtable_reference + 4)):
                    vtable_reference = ida_xref.get_next_dref_to(typeinfo, vtable_reference)
                    continue

            if is_64bit:
                vtables.append([offset, vtable_reference + 8])
            else:
                vtables.append([offset, vtable_reference + 4])
            
            vtable_reference = ida_xref.get_next_dref_to(typeinfo, vtable_reference)

    return vtables

# --------------------
# PE
# --------------------

def find_typeinfo_vtable():
    filetype = ida_ida.inf_get_filetype()
    is_64bit = ida_ida.inf_is_64bit()

    if filetype == ida_ida.f_PE: # PE
        min_address = ida_ida.inf_get_min_ea()
        while True:
            address = find_pattern('2E 3F 41 56 74 79 70 65 5F 69 6E 66 6F 40 40 00', min_address=min_address) # .?AVtype_info@@
            if not is_valid_address(address):
                break

            min_address = address + 16

            if is_64bit:
                if not ida_bytes.is_off(ida_bytes.get_flags(address - 16), 0):
                    continue

                typeinfo_vtable_address = ida_bytes.get_qword(address - 16)

                if not ida_bytes.is_qword(ida_bytes.get_flags(address - 8)): # spare == qword
                    continue

                spare = ida_bytes.get_qword(address - 8) # spare only for runtime (must be 0)
            else:
                if not ida_bytes.is_off(ida_bytes.get_flags(address - 8), 0):
                    continue

                typeinfo_vtable_address = ida_bytes.get_dword(address - 8)

                if not ida_bytes.is_dword(ida_bytes.get_flags(address - 4)): # spare == dword
                    continue

                spare = ida_bytes.get_dword(address - 4) # spare only for runtime (must be 0)

            if not is_valid_address(typeinfo_vtable_address) or spare != 0:
                continue

            return typeinfo_vtable_address

def find_type_descriptions(typeinfo_vtable):
    type_descriptors = []

    filetype = ida_ida.inf_get_filetype()
    is_64bit = ida_ida.inf_is_64bit()

    if filetype == ida_ida.f_PE:
        vtable_reference = ida_xref.get_first_dref_to(typeinfo_vtable)
        while is_valid_address(vtable_reference):
            if not ida_bytes.has_xref(ida_bytes.get_flags(vtable_reference)):
                vtable_reference = ida_xref.get_next_dref_to(typeinfo_vtable, vtable_reference)
                continue

            if is_64bit:
                if not ida_bytes.is_qword(ida_bytes.get_flags(vtable_reference + 8)): # spare == qword
                    vtable_reference = ida_xref.get_next_dref_to(typeinfo_vtable, vtable_reference)
                    continue

                spare = ida_bytes.get_qword(vtable_reference + 8) # spare only for runtime (must be 0)
            else:
                if not ida_bytes.is_dword(ida_bytes.get_flags(vtable_reference + 4)): # spare == dword
                    vtable_reference = ida_xref.get_next_dref_to(typeinfo_vtable, vtable_reference)
                    continue

                spare = ida_bytes.get_dword(vtable_reference + 4) # spare only for runtime (must be 0)

            if spare != 0:
                vtable_reference = ida_xref.get_next_dref_to(typeinfo_vtable, vtable_reference)
                continue

            if is_64bit:
                name = ida_bytes.get_strlit_contents(vtable_reference + 16, -1, 0)
            else:
                name = ida_bytes.get_strlit_contents(vtable_reference + 8, -1, 0)

            if not name:
                vtable_reference = ida_xref.get_next_dref_to(typeinfo_vtable, vtable_reference)
                continue

            if name[:2] != b'.?':
                vtable_reference = ida_xref.get_next_dref_to(typeinfo_vtable, vtable_reference)
                continue

            name = name[2:].decode()
            demangled_name = ida_name.demangle_name('??_R0?' + name, ida_name.MNG_NOECSU | ida_name.MNG_ZPT_SPACE)
            demangled_name = demangled_name.replace(' `RTTI Type Descriptor\'', '')
            type_descriptors.append((vtable_reference, demangled_name))

            vtable_reference = ida_xref.get_next_dref_to(typeinfo_vtable, vtable_reference)

    return type_descriptors

def find_base_class_descriptor(type_descriptor):
    
    filetype = ida_ida.inf_get_filetype()

    if filetype == ida_ida.f_PE:
        type_descriptor_reference = ida_xref.get_first_dref_to(type_descriptor)
        while is_valid_address(type_descriptor_reference):
            if not ida_bytes.has_xref(ida_bytes.get_flags(type_descriptor_reference)):
                type_descriptor_reference = ida_xref.get_next_dref_to(type_descriptor, type_descriptor_reference)
                continue

            if not ida_bytes.is_off(ida_bytes.get_flags(type_descriptor_reference + 0x18), 0):
                type_descriptor_reference = ida_xref.get_next_dref_to(type_descriptor, type_descriptor_reference)
                continue

            return type_descriptor_reference

def find_complete_objects(type_descriptor):
    complete_objects = []

    filetype = ida_ida.inf_get_filetype()
    is_64bit = ida_ida.inf_is_64bit()
    imagebase = ida_nalt.get_imagebase()

    if filetype == ida_ida.f_PE:
        type_descriptor_reference = ida_xref.get_first_dref_to(type_descriptor)
        while is_valid_address(type_descriptor_reference):
            if not ida_bytes.is_dword(ida_bytes.get_flags(type_descriptor_reference - 0xC)):
                type_descriptor_reference = ida_xref.get_next_dref_to(type_descriptor, type_descriptor_reference)
                continue

            signature = ida_bytes.get_dword(type_descriptor_reference - 0xC)
            if signature != 0 and signature != 1: # COL_SIG_REV0 | COL_SIG_REV1
                type_descriptor_reference = ida_xref.get_next_dref_to(type_descriptor, type_descriptor_reference)
                continue

            offset = ida_bytes.get_dword(type_descriptor_reference - 0x8)

            if not ida_bytes.is_off(ida_bytes.get_flags(type_descriptor_reference + 0x4), 0):
                type_descriptor_reference = ida_xref.get_next_dref_to(type_descriptor, type_descriptor_reference)
                continue

            if is_64bit:
                if imagebase + ida_bytes.get_dword(type_descriptor_reference + 0x8) != type_descriptor_reference - 0xC:
                    type_descriptor_reference = ida_xref.get_next_dref_to(type_descriptor, type_descriptor_reference)
                    continue

            complete_objects.append([offset, type_descriptor_reference - 0xC])

            type_descriptor_reference = ida_xref.get_next_dref_to(type_descriptor, type_descriptor_reference)
            continue

    return complete_objects

def get_bases_from_base_class_descriptor(base_class_descriptor, type_descriptions):
    bases = []

    filetype = ida_ida.inf_get_filetype()
    is_64bit = ida_ida.inf_is_64bit()
    imagebase = ida_nalt.get_imagebase()

    if filetype == ida_ida.f_PE:
        if is_64bit:
            class_hierarchy_descriptor = imagebase + ida_bytes.get_dword(base_class_descriptor + 24)
        else:
            class_hierarchy_descriptor = ida_bytes.get_dword(base_class_descriptor + 24)

        signature = ida_bytes.get_dword(class_hierarchy_descriptor)
        if signature != 0 and signature != 1:
            return bases

        number_of_bases = ida_bytes.get_dword(class_hierarchy_descriptor + 8)

        if is_64bit:
            array_of_bases = imagebase + ida_bytes.get_dword(class_hierarchy_descriptor + 12)
        else:
            array_of_bases = ida_bytes.get_dword(class_hierarchy_descriptor + 12)

        for i in range(number_of_bases):
            if is_64bit:
                based_class_descriptor = imagebase + ida_bytes.get_dword(array_of_bases + 4 * i)
            else:
                based_class_descriptor = ida_bytes.get_dword(array_of_bases + 4 * i)

            if is_64bit:
                based_class_descriptor_type_descriptor = imagebase + ida_bytes.get_dword(based_class_descriptor)
            else:
                based_class_descriptor_type_descriptor = ida_bytes.get_dword(based_class_descriptor)

            if based_class_descriptor == base_class_descriptor:
                continue

            for address, name in type_descriptions:
                if address == based_class_descriptor_type_descriptor:
                    bases.append((based_class_descriptor, name))

    return bases

def get_bases_from_complete_object(complete_object, type_descriptions):
    bases = []

    filetype = ida_ida.inf_get_filetype()
    is_64bit = ida_ida.inf_is_64bit()
    imagebase = ida_nalt.get_imagebase()

    if filetype == ida_ida.f_PE:
        if is_64bit:
            complete_object_type_descriptor = imagebase + ida_bytes.get_dword(complete_object + 12)
            class_hierarchy_descriptor = imagebase + ida_bytes.get_dword(complete_object + 16)
        else:
            complete_object_type_descriptor = ida_bytes.get_dword(complete_object + 12)
            class_hierarchy_descriptor = ida_bytes.get_dword(complete_object + 16)

        signature = ida_bytes.get_dword(class_hierarchy_descriptor)
        if signature != 0 and signature != 1:
            return bases

        number_of_bases = ida_bytes.get_dword(class_hierarchy_descriptor + 8)

        if is_64bit:
            array_of_bases = imagebase + ida_bytes.get_dword(class_hierarchy_descriptor + 12)
        else:
            array_of_bases = ida_bytes.get_dword(class_hierarchy_descriptor + 12)

        for i in range(number_of_bases):
            if is_64bit:
                based_class_descriptor = imagebase + ida_bytes.get_dword(array_of_bases + 4 * i)
            else:
                based_class_descriptor = ida_bytes.get_dword(array_of_bases + 4 * i)

            if is_64bit:
                based_class_descriptor_type_descriptor = imagebase + ida_bytes.get_dword(based_class_descriptor)
            else:
                based_class_descriptor_type_descriptor = ida_bytes.get_dword(based_class_descriptor)

            if based_class_descriptor_type_descriptor == complete_object_type_descriptor:
                continue

            for address, name in type_descriptions:
                if address == based_class_descriptor_type_descriptor:
                    bases.append((based_class_descriptor, name))

    return bases

def get_type_bases_tree(type_descriptor_address, type_descriptions, visited=None, base_visited=None):
    if visited is None:
        visited = set()
    if base_visited is None:
        base_visited = set()

    if type_descriptor_address in visited:
        return None
    visited.add(type_descriptor_address)

    imagebase = ida_nalt.get_imagebase()
    is_64bit = ida_ida.inf_is_64bit()
    bases = []
    name = None

    for address, demangled in type_descriptions:
        if address == type_descriptor_address:
            name = demangled
            break

    if not name:
        visited.remove(type_descriptor_address)
        return None

    complete_objects = find_complete_objects(type_descriptor_address)
    if not complete_objects:
        visited.remove(type_descriptor_address)
        return [type_descriptor_address, name, bases]

    processed_bases = set()

    for _, col in complete_objects:
        base_list = get_bases_from_complete_object(col, type_descriptions)

        for base_class_descriptor, _ in base_list:
            if is_64bit:
                base_type_descriptor = imagebase + ida_bytes.get_dword(base_class_descriptor)
            else:
                base_type_descriptor = ida_bytes.get_dword(base_class_descriptor)

            if (not base_type_descriptor or 
                base_type_descriptor == type_descriptor_address or
                base_type_descriptor in processed_bases):
                continue

            processed_bases.add(base_type_descriptor)

            if base_type_descriptor not in base_visited:
                base_visited.add(base_type_descriptor)
                base_node = get_type_bases_tree(base_type_descriptor, type_descriptions, visited, base_visited)
                if base_node:
                    bases.append(base_node)

    visited.remove(type_descriptor_address)
    return [type_descriptor_address, name, bases]

def find_complete_object_vtable(complete_object):
    
    filetype = ida_ida.inf_get_filetype()
    is_64bit = ida_ida.inf_is_64bit()

    if filetype == ida_ida.f_PE: # PE
        vtable_reference = ida_xref.get_first_dref_to(complete_object)
        while is_valid_address(vtable_reference):
            if is_64bit:
                if not ida_bytes.is_off(ida_bytes.get_flags(vtable_reference + 8), 0):
                    vtable_reference = ida_xref.get_next_dref_to(complete_object, vtable_reference)
                    continue
            else:
                if not ida_bytes.is_off(ida_bytes.get_flags(vtable_reference + 4), 0):
                    vtable_reference = ida_xref.get_next_dref_to(complete_object, vtable_reference)
                    continue

            if is_64bit:
                return vtable_reference + 8
            else:
                return vtable_reference + 4

# --------------------
# Plugin
# --------------------

class vdump_t(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_MOD
    wanted_name = 'vdump'
    wanted_hotkey = 'Ctrl+F12'
    comment = 'vdump - VTable Dumper\n'
    help = ''

    def init(self):
        if ida_pro.IDA_SDK_VERSION < 900:
            print_message('ERROR: Optimal IDA version for vdump is 9.0')
            return ida_idaapi.PLUGIN_SKIP

        return ida_idaapi.PLUGIN_KEEP

    def run(self, arg = None):
        if not ida_auto.auto_is_ok():
            print_message('INFO: The analysis is not finished!')
            return
        
        if not ida_hexrays.init_hexrays_plugin():
            print_message('ERROR: Failed to initialize hexrays plugin!\n')
            return

        filetype = ida_ida.inf_get_filetype()
        if filetype != ida_ida.f_PE and filetype != ida_ida.f_ELF and filetype != ida_ida.f_MACHO:
            print_message('ERROR: This file type is not supported!\n')
            return

        filetype = ida_ida.inf_get_filetype()
        trees = []
        class_vfuncs = {}

        if filetype in (ida_ida.f_ELF, ida_ida.f_MACHO):
            type_infos = find_type_infos()
            for address, name in type_infos:
                name = format_name(name)
                tree = get_typeinfo_bases(address, type_infos)
                if tree is not None:
                    trees.append(tree)
                    vtables = find_vtables_typeinfo(address)
                    for offset, vtable in vtables:
                        vfuncs = get_vtable_functions(vtable)
                        if name not in class_vfuncs:
                            class_vfuncs[name] = {}
                        class_vfuncs[name][offset] = vfuncs

        elif filetype == ida_ida.f_PE:
            typeinfo_vtable = find_typeinfo_vtable()
            if typeinfo_vtable is None:
                print_message('ERROR: Failed to find typeinfo vtable for PE')
                return
            type_descriptions = find_type_descriptions(typeinfo_vtable)
            for address, name in type_descriptions:
                name = format_name(name)
                tree = get_type_bases_tree(address, type_descriptions)
                if tree is not None:
                    trees.append(tree)
                    cols = find_complete_objects(address)
                    for offset, col in cols:
                        vtable = find_complete_object_vtable(col)
                        if vtable:
                            vfuncs = get_vtable_functions(vtable)
                            if name not in class_vfuncs:
                                class_vfuncs[name] = {}
                            class_vfuncs[name][offset] = vfuncs

        else:
            print_message('ERROR: Unsupported file type')
            return

        converter = DeclarationConverter()
        output = converter.convert(trees, class_vfuncs)
        path = Path(ida_loader.get_path(ida_loader.PATH_TYPE_IDB))
        output_path = path.stem + '.h'
        with open(output_path, 'w') as f:
            f.write(output)
        print_message(f'NOTE: VTable declarations written to {output_path}')

    @staticmethod
    def main():
        if ida_pro.IDA_SDK_VERSION < 900:
            print_message('ERROR: Optimal IDA version for vdump is 9.0')
            return 1

        vd = vdump_t()
        vd.run()

        return 0

_vdump = None
is_plugin_mode = False
def PLUGIN_ENTRY():
    global _vdump
    global is_plugin_mode
    if not _vdump:
        _vdump = vdump_t()
    is_plugin_mode = True
    return _vdump

if __name__ == '__main__':
    if not is_plugin_mode:
        if IDALIB_MODE:
            sys.exit(vdump_t.main())
        else:
            if ida_pro.IDA_SDK_VERSION < 900:
                print_message('ERROR: Optimal IDA version for vdump is 9.0')
            else:
                vdump_t().run()
