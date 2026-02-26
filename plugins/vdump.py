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
from functools import lru_cache

from pathlib import Path
from datetime import datetime

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

VDUMP_VERSION = '4.0.2'
DUMP_FOR_SOURCE_PYTHON = False

################################################################################
# Base functions
################################################################################

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


################################################################################
# Small helpers & caches (performance critical)
################################################################################

_FILETYPE = None
_IS64 = None
_IMGBASE = None

# fast demangle cleanup
_NONVT = '`non-virtual thunk to\''
def _sanitize_demangled(d: str) -> str:
    if not d:
        return d
    if _NONVT in d:
        d = d.replace(_NONVT, '')
    return d.strip()

# compact formatter with translation table
_re_backticks = re.compile(r'`[^`\']*\'')
_trans = str.maketrans({
    '(':'_', ')':'_', '<':'_', '>':'_', ',':'_', '&':'_', '?':'_', '@':'_', '[':'_', ']':'_',
})
_ws_multi = re.compile(r'\s+')
_us_multi = re.compile(r'_+')

def format_name(name: str) -> str:
    if not name:
        return name
    name = name.replace('const','').replace('volatile','')
    name = _re_backticks.sub('', name)
    name = name.replace('::','_').translate(_trans)
    name = _ws_multi.sub('_', name)
    name = re.sub(r'\(.*\*\)\(.*\)', '', name)  # strip FP pattern
    name = name.replace('*','')
    name = _us_multi.sub('_', name)
    if name.startswith('__'): name = name[2:]
    if name.startswith('_'):  name = name[1:]
    if name.endswith('__'):   name = name[:-2]
    if name.endswith('_'):    name = name[:-1]
    return name

# parse_decl cache (expensive)
@lru_cache(maxsize=8192)
def _parse_type_cached(s: str):
    tif = ida_typeinf.tinfo_t()
    if ida_typeinf.parse_decl(tif, None, s, ida_typeinf.PT_SIL | ida_typeinf.PT_TYP | ida_typeinf.PT_SEMICOLON) is None:
        return None
    if tif.is_ptr():
        t = tif
        lt = tif
        while t and t.is_ptr():
            lt = t
            t = t.get_pointed_object()
        tif = lt
    return tif

def _scalar_name(t: ida_typeinf.tinfo_t) -> str:
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
    if t.is_integral() or t.is_arithmetic():
        if t.is_signed() or (not t.is_unsigned() and not t.is_decl_uint()):
            if t.is_int16() or t.is_decl_int16(): return 'short'
            if t.is_int32() or t.is_decl_int32(): return 'int'
            if t.is_int64() or t.is_decl_int64(): return 'long long'
            if t.is_int128() or t.is_decl_int128(): return 'void*'
            if t.is_int() or t.is_decl_int(): return 'int' if size != 1 else 'char'
            return {1:'char',2:'short',4:'int',8:'long long',16:'void*'}.get(size,'int')
        else:
            if t.is_uint16() or t.is_decl_uint16(): return 'unsigned short'
            if t.is_uint32() or t.is_decl_uint32(): return 'unsigned int'
            if t.is_uint64() or t.is_decl_uint64(): return 'unsigned long long'
            if t.is_uint128() or t.is_decl_uint128(): return 'void*'
            if t.is_uint() or t.is_decl_uint(): return 'unsigned int' if size != 1 else 'unsigned char'
            return {1:'unsigned char',2:'unsigned short',4:'unsigned int',8:'unsigned long long',16:'void*'}.get(size,'unsigned int')

    if t.is_floating() or t.is_decl_floating():
        return {4:'float',8:'double',10:'long double',16:'long double'}.get(size,'double')

    return 'void*'

def is_builtin_type(t: ida_typeinf.tinfo_t) -> bool:
    if t.is_ptr():
        t = ida_typeinf.remove_pointer(t)
        t.clr_decl_const_volatile()

    if (not t.is_correct()) or (not t.is_well_defined()):
        return False

    if any((
        t.is_ptr(), t.is_array(), t.is_func(), t.is_funcptr(), t.is_sue(),
        t.is_udt(), t.is_typedef(), t.is_typeref(), t.is_aliased(), t.is_complex(),
        t.is_bitfield(), t.is_enum(), t.is_struct(), t.is_union(), t.is_forward_decl(),
        t.is_forward_enum(), t.is_forward_struct(), t.is_forward_union(), t.is_varstruct(),
        t.is_varmember(), t.is_vftable(), t.is_sse_type(), t.is_tbyte(), t.is_unknown(),
        t.is_decl_array(), t.is_decl_bitfield(), t.is_decl_complex(), t.is_decl_enum(),
        t.is_decl_func(), t.is_decl_ptr(), t.is_decl_struct(), t.is_decl_sue(),
        t.is_decl_typedef(), t.is_decl_udt(), t.is_decl_unknown(), t.is_decl_paf(),
        t.is_decl_partial(), t.is_decl_tbyte(), t.is_anonymous_udt(), t.is_bitmask_enum(),
        t.is_empty_enum(), t.is_empty_udt(), t.is_fixed_struct(), t.is_from_subtil(),
        t.is_high_func(), t.is_purging_cc(), t.is_shifted_ptr(), t.is_small_udt(),
        t.is_user_cc(), t.is_vararg_cc(), t.is_frame()
    )):
        return False

    if t.is_void() or t.is_decl_void(): return True
    if t.is_bool() or t.is_decl_bool(): return True
    if t.is_char() or t.is_decl_char(): return True
    if t.is_uchar() or t.is_decl_uchar(): return True
    if t.is_float() or t.is_decl_float(): return True
    if t.is_double() or t.is_decl_double(): return True
    if t.is_ldouble(): return True

    if t.is_integral() or t.is_arithmetic():
        if t.is_signed() or (not t.is_unsigned() and not t.is_decl_uint()):
            if t.is_int16() or t.is_decl_int16(): return True
            if t.is_int32() or t.is_decl_int32(): return True
            if t.is_int64() or t.is_decl_int64(): return True
            if t.is_int128() or t.is_decl_int128(): return True
            if t.is_int() or t.is_decl_int(): return True
            return False
        else:
            if t.is_uint16() or t.is_decl_uint16(): return True
            if t.is_uint32() or t.is_decl_uint32(): return True
            if t.is_uint64() or t.is_decl_uint64(): return True
            if t.is_uint128() or t.is_decl_uint128(): return True
            if t.is_uint() or t.is_decl_uint(): return True
            return False

    if t.is_floating() or t.is_decl_floating(): return True
    return False

def normalize_tinfo(t: ida_typeinf.tinfo_t) -> str:
    if not t.is_correct() or not t.is_well_defined():
        return 'void*'

    if t.is_func() or t.is_funcptr():
        return 'void*'

    if t.is_ptr():
        pt = ida_typeinf.remove_pointer(t)
        if is_builtin_type(pt):
            qualifiers = []
            try:
                if pt.is_const(): qualifiers.append('const')
                if pt.is_volatile(): qualifiers.append('volatile')
            except Exception:
                pass
            base = _scalar_name(pt)
            if qualifiers:
                base = ' '.join(qualifiers + [base])
            return base + '*'
        return 'void*'

    if t.is_array():
        try:
            et = ida_typeinf.tinfo_t()
            if t.get_array_element(et) and is_builtin_type(et):
                qualifiers = []
                if et.is_const(): qualifiers.append('const')
                if et.is_volatile(): qualifiers.append('volatile')
                base = _scalar_name(et)
                if qualifiers:
                    base = ' '.join(qualifiers + [base])
                return base + '*'
        except Exception:
            pass
        return 'void*'

    if any((
        t.is_sue(), t.is_udt(), t.is_typedef(), t.is_typeref(), t.is_aliased(),
        t.is_complex(), t.is_bitfield(), t.is_enum(), t.is_struct(), t.is_union(),
        t.is_forward_decl(), t.is_forward_enum(), t.is_forward_struct(),
        t.is_forward_union(), t.is_varstruct(), t.is_varmember(), t.is_vftable(),
        t.is_sse_type(), t.is_tbyte(), t.is_unknown(), t.is_decl_array(),
        t.is_decl_bitfield(), t.is_decl_complex(), t.is_decl_enum(),
        t.is_decl_func(), t.is_decl_struct(), t.is_decl_sue(), t.is_decl_typedef(),
        t.is_decl_udt(), t.is_decl_unknown(), t.is_decl_paf(), t.is_decl_partial(),
        t.is_decl_tbyte(), t.is_anonymous_udt(), t.is_bitmask_enum(),
        t.is_empty_enum(), t.is_empty_udt(), t.is_fixed_struct(), t.is_from_subtil(),
        t.is_high_func(), t.is_purging_cc(), t.is_shifted_ptr(), t.is_small_udt(),
        t.is_user_cc(), t.is_vararg_cc(), t.is_frame()
    )):
        return 'void*'

    return _scalar_name(t)

################################################################################
# AST Node Classes
################################################################################

class ParserError(Exception):
    pass

class BaseNode:
    def apply_rules(self, rules):
        new_self = self
        for rule in rules:
            out = rule(new_self)
            if out is None:
                return None
            elif out is not new_self:
                return out.apply_rules(rules)
        self._apply_rules_to_children(rules)
        return new_self

    def _apply_rules_to_children(self, rules):
        pass

    def __str__(self, indent=0):
        return ' ' * indent + '<BaseNode>'

class TypeNode(BaseNode):
    def __init__(
        self,
        namespaces=None,
        typename=None,
        template_args=None,
        leading_mods=None,
        trailing_mods=None,
        tuple_args=None,
        nested_types=None,
        special_suffix='',
        has_typename_prefix=False,
        has_template_keyword=False
    ):
        super().__init__()
        self.namespaces = namespaces or []
        self.typename = typename
        self.template_args = template_args or []
        self.leading_mods = leading_mods or []
        self.trailing_mods = trailing_mods or []
        self.tuple_args = tuple_args or []
        self.nested_types = nested_types or []
        self.special_suffix = special_suffix
        self.has_typename_prefix = has_typename_prefix
        self.has_template_keyword = has_template_keyword

    def _apply_rules_to_children(self, rules):
        self.template_args = [a2 for a in self.template_args if (a2 := a.apply_rules(rules)) is not None]
        self.tuple_args    = [p2 for p in self.tuple_args    if (p2 := p.apply_rules(rules)) is not None]
        self.nested_types  = [n2 for n in self.nested_types  if (n2 := n.apply_rules(rules)) is not None]

    def __str__(self, indent=0):
        lines = []
        curr = indent

        for ns in self.namespaces:
            lines.append(' ' * curr + f'namespace: {ns}')
            curr += 4

        if self.leading_mods or self.typename:
            if any(mod in {'class', 'struct', 'enum'} for mod in self.leading_mods):
                mods = ' '.join(self.leading_mods) if self.leading_mods else ''
                if self.typename:
                    lines.append(' ' * curr + f'{mods}: {self.typename}')
            else:
                if self.leading_mods:
                    lines.append(' ' * curr + 'leading_mods: ' + ', '.join(self.leading_mods))
                    curr += 4
                if self.typename:
                    lines.append(' ' * curr + f'type: {self.typename}')

        if self.template_args:
            lines.append(' ' * (curr + 4) + 'template arguments:')
            for arg in self.template_args:
                lines.append(arg.__str__(curr + 8))

        if self.trailing_mods:
            lines.append(' ' * (curr + 4) + 'trailing_mods: ' + ', '.join(self.trailing_mods))

        if self.tuple_args:
            lines.append(' ' * (curr + 4) + 'tuple arguments:')
            for p in self.tuple_args:
                lines.append(p.__str__(curr + 8))

        if self.special_suffix:
            lines.append(' ' * (curr + 4) + f'suffix: {self.special_suffix}')

        if self.has_typename_prefix:
            lines.append(' ' * (curr + 4) + 'has_typename_prefix: True')
        if self.has_template_keyword:
            lines.append(' ' * (curr + 4) + 'has_template_keyword: True')

        for nt in self.nested_types:
            lines.append(nt.__str__(curr + 4))

        return '\n'.join(lines)

class FunctionPointerNode(BaseNode):
    def __init__(self, return_type=None, calling_convention=None, parameters=None, trailing_mods=None):
        super().__init__()
        self.return_type = return_type
        self.calling_convention = calling_convention
        self.parameters = parameters or []
        self.trailing_mods = trailing_mods or []

    def _apply_rules_to_children(self, rules):
        if self.return_type:
            self.return_type = self.return_type.apply_rules(rules)
        self.parameters = [p2 for p in self.parameters if (p2 := p.apply_rules(rules)) is not None]

    def __str__(self, indent=0):
        lines = []
        lines.append(' ' * indent + 'function pointer:')
        if self.return_type:
            lines.append(' ' * (indent + 4) + f'return type: {self.return_type.typename}')
        if self.calling_convention:
            lines.append(' ' * (indent + 4) + f'calling convention: {self.calling_convention}')
        if self.parameters:
            lines.append(' ' * (indent + 4) + 'tuple arguments:')
            for p in self.parameters:
                lines.append(p.__str__(indent + 8))
        if self.trailing_mods:
            lines.append(' ' * (indent + 4) + 'trailing_mods: ' + ', '.join(self.trailing_mods))
        return '\n'.join(lines)

class ValueNode(BaseNode):
    def __init__(self, value):
        super().__init__()
        self.value = value

    def __str__(self, indent=0):
        return ' ' * indent + f'value: {self.value}'

class EllipsisNode(BaseNode):
    def __init__(self):
        super().__init__()

    def __str__(self, indent=0):
        return ' ' * indent + '...'

class ParameterNode(BaseNode):
    def __init__(self, type_node=None, param_name=None, value_node=None):
        super().__init__()
        self.type_node = type_node
        self.param_name = param_name
        self.value_node = value_node

    def _apply_rules_to_children(self, rules):
        if self.type_node:
            self.type_node = self.type_node.apply_rules(rules)
        if self.value_node:
            self.value_node = self.value_node.apply_rules(rules)

    def __str__(self, indent=0):
        lines = []
        if self.type_node:
            lines.append(self.type_node.__str__(indent))
        if self.param_name:
            lines.append(' ' * (indent + 4) + f'name: {self.param_name}')
        if self.value_node:
            lines.append(self.value_node.__str__(indent))
        if not lines:
            lines.append(' ' * indent + '<ParameterNode>')
        return '\n'.join(lines)

class VariableNode(BaseNode):
    def __init__(self, type_node=None, var_name=None):
        super().__init__()
        self.type_node = type_node
        self.var_name = var_name

    def _apply_rules_to_children(self, rules):
        if self.type_node:
            self.type_node = self.type_node.apply_rules(rules)

    def __str__(self, indent=0):
        lines = []
        if self.type_node:
            lines.append(self.type_node.__str__(indent))
        if self.var_name:
            lines.append(' ' * indent + f'    name: {self.var_name}')
        return '\n'.join(lines)

class FunctionNode(BaseNode):
    def __init__(self, return_type=None, func_name=None, func_template_args=None, parameters=None):
        super().__init__()
        self.return_type = return_type
        self.func_name = func_name
        self.func_template_args = func_template_args or []
        self.parameters = parameters or []

    def _apply_rules_to_children(self, rules):
        if self.return_type:
            self.return_type = self.return_type.apply_rules(rules)
        self.func_template_args = [t2 for t in self.func_template_args if (t2 := t.apply_rules(rules)) is not None]
        self.parameters       = [p2 for p in self.parameters       if (p2 := p.apply_rules(rules)) is not None]

    def __str__(self, indent=0):
        lines = []
        if self.return_type:
            lines.append(' ' * indent + f'return type: {self.return_type.typename}')
        if self.func_name:
            lines.append(' ' * (indent + 4) + f'name: {self.func_name}')

        if self.func_template_args:
            lines.append(' ' * (indent + 8) + 'template arguments:')
            for t in self.func_template_args:
                lines.append(t.__str__(indent + 12))

        if self.parameters:
            lines.append(' ' * (indent + 8) + 'tuple arguments:')
            for p in self.parameters:
                lines.append(p.__str__(indent + 12))

        return '\n'.join(lines)

################################################################################
# to_code()
################################################################################

def to_code(node, top_level=False):
    if node is None:
        return ''

    if isinstance(node, FunctionPointerNode):
        parts = []
        if node.return_type:
            parts.append(to_code(node.return_type, top_level=False))
        if node.calling_convention:
            parts.append(node.calling_convention)
        if node.calling_convention:
            fp_str = f'{parts[0]}({parts[1]}*)'
        else:
            fp_str = f'{parts[0]}(*)'
        params = ', '.join(to_code(p, top_level=False) for p in node.parameters)
        fp_str += f'({params})'
        if node.trailing_mods:
            fp_str += ''.join(node.trailing_mods)
        return fp_str

    if isinstance(node, ValueNode):
        return str(node.value)

    if isinstance(node, EllipsisNode):
        return '...'

    if isinstance(node, ParameterNode):
        if node.value_node:
            return to_code(node.value_node, top_level=False)
        param_type = to_code(node.type_node, top_level=False)
        return f'{param_type} {node.param_name}' if node.param_name else param_type

    if isinstance(node, TypeNode):
        parts = []

        leading_parts = []
        ptr_ref_tokens = {'*', '&', '&&'}
        for m in node.leading_mods:
            if m in ptr_ref_tokens:
                if leading_parts:
                    leading_parts[-1] += m
                else:
                    leading_parts.append(m)
            else:
                if leading_parts:
                    leading_parts[-1] += ' ' + m
                else:
                    leading_parts.append(m)

        leading_part = ' '.join(leading_parts)

        if node.has_typename_prefix:
            if leading_part:
                parts.append(f'typename {leading_part}')
            else:
                parts.append('typename')
        else:
            if leading_part:
                parts.append(leading_part)

        ns_part = '::'.join(node.namespaces)
        if ns_part:
            if parts:
                if parts[-1]:
                    parts[-1] += ' ' + ns_part + '::'
                else:
                    parts.append(ns_part + '::')
            else:
                parts.append(ns_part + '::')

        base_name = node.typename or ''
        if node.has_template_keyword and base_name:
            base_name = 'template ' + base_name

        if base_name:
            if parts:
                if parts[-1].endswith('::'):
                    parts[-1] += base_name
                else:
                    parts[-1] += ' ' + base_name
            else:
                parts.append(base_name)

        if node.template_args:
            inside_args = [to_code(a, top_level=False) for a in node.template_args]
            parts[-1] += '<' + ', '.join(inside_args) + '>'

        if node.tuple_args:
            inside_pars = ', '.join(to_code(p, top_level=False) for p in node.tuple_args)
            parts[-1] += '(' + inside_pars + ')'

        for m in node.trailing_mods:
            if m in ptr_ref_tokens:
                if parts:
                    parts[-1] += m
                else:
                    parts.append(m)
            else:
                if parts:
                    parts[-1] += ' ' + m
                else:
                    parts.append(m)

        if node.special_suffix:
            if parts:
                parts[-1] += '::' + node.special_suffix
            else:
                parts.append('::' + node.special_suffix)

        base_str = ''.join(parts).strip()

        for nt in node.nested_types:
            nt_str = to_code(nt, top_level=False)
            base_str += f'::{nt_str}'

        if top_level:
            base_str += ';'
        return base_str

    if isinstance(node, VariableNode):
        t = to_code(node.type_node, top_level=False)
        v = node.var_name or ''
        out = f'{t} {v}'.strip()
        if top_level:
            out += ';'
        return out

    if isinstance(node, FunctionNode):
        rt = to_code(node.return_type, top_level=False)
        fn = node.func_name or ''
        tmpl = ''
        if node.func_template_args:
            inside = ', '.join(to_code(a, top_level=False) for a in node.func_template_args)
            tmpl = f'<{inside}>'
        param_part = f'({", ".join(to_code(p, top_level=False) for p in node.parameters)})' if node.parameters else '()'
        out = f'{rt} {fn}{tmpl}{param_part}'
        if top_level:
            out += ';'
        return out

    return '<UnknownNode>'

################################################################################
# Tokenization
################################################################################

TOKEN_PATTERN = re.compile(
    r'''
    (?P<word>[A-Za-z_]\w*)
    |(?P<number>\d+)
    |(?P<dbl_and>\&\&)
    |(?P<ellipsis>\.\.\.)
    |(?P<symbols>::|[<>,:\(\){}&\*\[\]=;\.\+\-])
    ''',
    re.VERBOSE
)

def tokenize(text):
    tokens = []
    for m in TOKEN_PATTERN.finditer(text):
        if m.group('word'):
            tokens.append(('WORD', m.group('word')))
        elif m.group('number'):
            tokens.append(('NUMBER', m.group('number')))
        elif m.group('dbl_and'):
            tokens.append(('SYMBOL', '&&'))
        elif m.group('ellipsis'):
            tokens.append(('ELLIPSIS', '...'))
        else:
            tokens.append(('SYMBOL', m.group('symbols')))
    return tokens

class TokenStream:
    def __init__(self, tokens):
        self.tokens = tokens
        self.pos = 0

    def peek(self, offset=0):
        if self.pos + offset < len(self.tokens):
            return self.tokens[self.pos + offset]
        return None

    def next(self):
        if self.pos < len(self.tokens):
            t = self.tokens[self.pos]
            self.pos += 1
            return t
        return None

    def consume_if(self, ttype=None, tval=None):
        nxt = self.peek()
        if nxt and (ttype is None or nxt[0] == ttype):
            if tval is None or nxt[1] == tval:
                return self.next()
        return None

    def expect(self, ttype=None, tval=None):
        nxt = self.peek()
        if not nxt:
            raise ParserError('Unexpected end of tokens.')
        if ttype and nxt[0] != ttype:
            raise ParserError(f'Expected {ttype}, got {nxt}')
        if tval and nxt[1] != tval:
            raise ParserError(f'Expected {tval}, got {nxt}')
        return self.next()

    def eof(self):
        return self.pos >= len(self.tokens)

################################################################################
# Parsing
################################################################################

_BUILTIN_COMBOS = [
    ('unsigned', 'long', 'long', 'int'),
    ('signed',   'long', 'long', 'int'),
    ('unsigned', 'short', 'int'),
    ('signed',   'short', 'int'),
    ('unsigned', 'long',  'int'),
    ('signed',   'long',  'int'),
    ('long',     'long',  'int'),
    ('long',     'double'),
    ('unsigned', 'long',  'long'),
    ('signed',   'long',  'long'),
    ('unsigned', 'short'),
    ('signed',   'short'),
    ('unsigned', 'int'),
    ('signed',   'int'),
    ('long',     'long'),
    ('short',    'int'),
    ('long',     'int'),
    ('signed',),
    ('unsigned',),
    ('short',),
    ('long',),
    ('void',),
    ('bool',),
    ('char',),
    ('signed',   'char'),
    ('unsigned', 'char'),
    ('wchar_t',),
    ('char8_t',),
    ('char16_t',),
    ('char32_t',),
    ('int',),
    ('float',),
    ('double',),
]

def _try_match_builtin(ts):
    max_len = 4
    words = []
    for i in range(max_len):
        tok = ts.peek(i)
        if tok and tok[0] == 'WORD':
            words.append(tok[1])
        else:
            break
    for L in range(min(len(words), max_len), 0, -1):
        key = tuple(w.lower() for w in words[:L])
        if key in _BUILTIN_COMBOS:
            out_tokens = [ts.next()[1] for _ in range(L)]
            return ' '.join(out_tokens)
    return None

def _tokens_to_spelling(tokens):
    parts = []
    prev_kind = None
    prev_val = None
    for kind, val in tokens:
        need_space = False
        if parts:
            if (prev_kind in ('WORD', 'NUMBER') and kind in ('WORD', 'NUMBER')):
                need_space = True
            if kind == 'SYMBOL' and val in ('*', '&', '&&') and (prev_val not in ('::',)):
                need_space = True
            if prev_val == '>' and kind in ('WORD', 'NUMBER'):
                need_space = True
            if val in ('::', '>', '<'):
                need_space = False
            if prev_val in ('::', '<', '>'):
                need_space = False
        if need_space:
            parts.append(' ')
        parts.append(val)
        prev_kind, prev_val = kind, val
    return ''.join(parts)

def parse_operator_function(ts):
    save = ts.pos

    while True:
        t1 = ts.peek()
        t2 = ts.peek(1)
        if t1 and t2 and t1[0] == 'WORD' and t2 == ('SYMBOL', '::'):
            ts.next(); ts.next()
        else:
            break

    if not (ts.peek() and ts.peek()[0] == 'WORD' and ts.peek()[1] == 'operator'):
        ts.pos = save
        return None
    ts.next()

    name_tokens = []
    templ_depth = 0
    while True:
        tok = ts.peek()
        if not tok:
            ts.pos = save
            return None
        if tok == ('SYMBOL', '(') and templ_depth == 0:
            break
        if tok == ('SYMBOL', '<'):
            templ_depth += 1
        elif tok == ('SYMBOL', '>') and templ_depth > 0:
            templ_depth -= 1
        name_tokens.append(ts.next())

    ts.expect('SYMBOL', '(')
    params = parse_tuple_args(ts)
    ts.expect('SYMBOL', ')')

    func_name = 'operator ' + _tokens_to_spelling(name_tokens).strip()
    return FunctionNode(return_type=None, func_name=func_name, func_template_args=[], parameters=params)

def parse_declaration(ts):
    opfn = parse_operator_function(ts)
    if opfn:
        ts.consume_if('SYMBOL', ';')
        return opfn

    rtype = parse_type_with_nesting(ts)
    if not rtype:
        return None

    nxt = ts.peek()
    if not nxt or nxt == ('SYMBOL', ';'):
        ts.consume_if('SYMBOL', ';')
        return rtype

    if nxt[0] == 'WORD':
        name_ = nxt[1]
        ts.next()

        func_tmpl = []
        if ts.consume_if('SYMBOL', '<'):
            func_tmpl = parse_template_args(ts)

        if ts.consume_if('SYMBOL', '('):
            params = parse_tuple_args(ts)
            ts.expect('SYMBOL', ')')
            ts.consume_if('SYMBOL', ';')
            return FunctionNode(rtype, name_, func_tmpl, params)
        else:
            ts.consume_if('SYMBOL', ';')
            return VariableNode(rtype, name_)

    if ts.consume_if('SYMBOL', '('):
        params = parse_tuple_args(ts)
        ts.expect('SYMBOL', ')')
        ts.consume_if('SYMBOL', ';')
        rtype.tuple_args = params
        return rtype

    ts.consume_if('SYMBOL', ';')
    return rtype

def parse_type_with_nesting(ts):
    base = parse_one_type(ts)
    if not base:
        return None
    parse_nested_chain(base, ts)
    return base

def parse_one_type(ts):
    start = ts.pos
    leading_mods = parse_modifiers(ts)

    special_typename_node = parse_typename_dependent_expr(ts, leading_mods)
    if special_typename_node:
        trailing_mods = parse_modifiers(ts)
        special_typename_node.trailing_mods.extend(trailing_mods)
        return special_typename_node

    builtin = _try_match_builtin(ts)
    if builtin is not None:
        trailing_mods = parse_modifiers(ts)
        node = TypeNode(
            namespaces=[],
            typename=builtin,
            template_args=[],
            leading_mods=leading_mods,
            trailing_mods=trailing_mods,
        )
        return node

    namespaces = []
    typename = None
    while True:
        nxt = ts.peek()
        if not nxt or nxt[0] != 'WORD':
            break
        word_ = nxt[1]
        ts.next()
        if ts.consume_if('SYMBOL', '::'):
            namespaces.append(word_)
        else:
            typename = word_
            break

    if not typename and not namespaces and not leading_mods:
        ts.pos = start
        return None

    targs = []
    if typename and ts.consume_if('SYMBOL', '<'):
        targs = parse_template_args(ts)

    funcptr_node = parse_function_pointer(ts, namespaces, typename, targs, leading_mods)
    if funcptr_node:
        trailing_mods = parse_modifiers(ts)
        funcptr_node.trailing_mods.extend(trailing_mods)
        return funcptr_node

    trailing_mods = parse_modifiers(ts)
    node = TypeNode(
        namespaces=namespaces,
        typename=typename,
        template_args=targs,
        leading_mods=leading_mods,
        trailing_mods=trailing_mods,
    )
    return node

def parse_typename_dependent_expr(ts, already_collected_mods):
    '''
    Parses 'typename A::template B<...>::type' or '...::size'.
    '''
    start_pos = ts.pos
    has_typename = False

    if 'typename' in already_collected_mods:
        new_mods = [m for m in already_collected_mods if m != 'typename']
        already_collected_mods[:] = new_mods
        has_typename = True
    else:
        nxt = ts.peek()
        if nxt and nxt[0] == 'WORD' and nxt[1] == 'typename':
            ts.next()
            has_typename = True

    if not has_typename:
        return None

    namespaces = []
    while True:
        w = ts.peek()
        if not w or w[0] != 'WORD':
            ts.pos = start_pos
            return None
        nsname = w[1]
        ts.next()
        if not ts.consume_if('SYMBOL', '::'):
            ts.pos = start_pos
            return None
        look = ts.peek()
        if look and look[0] == 'WORD' and look[1] == 'template':
            ts.next()
            namespaces.append(nsname)
            break
        else:
            namespaces.append(nsname)

    w2 = ts.peek()
    if not w2 or w2[0] != 'WORD':
        ts.pos = start_pos
        return None
    tmpl_name = w2[1]
    ts.next()

    if not ts.consume_if('SYMBOL', '<'):
        ts.pos = start_pos
        return None
    targs = parse_template_args(ts)

    if not ts.consume_if('SYMBOL', '::'):
        ts.pos = start_pos
        return None
    w3 = ts.peek()
    if not w3 or w3[0] != 'WORD':
        ts.pos = start_pos
        return None
    suffix = w3[1]
    ts.next()

    return TypeNode(
        namespaces=namespaces,
        typename=tmpl_name,
        template_args=targs,
        leading_mods=already_collected_mods,
        special_suffix=suffix,
        has_typename_prefix=True,
        has_template_keyword=True
    )

def parse_nested_chain(parent, ts):
    while True:
        if not ts.consume_if('SYMBOL', '::'):
            break
        nxt = ts.peek()
        if not nxt or nxt[0] != 'WORD':
            break

        if nxt[1] in {'class', 'struct', 'enum'}:
            mod = ts.next()[1]
            type_nxt = ts.peek()
            if not type_nxt or type_nxt[0] != 'WORD':
                raise ParserError(f'Expected type name after modifier \'{mod}\'')
            typename = ts.next()[1]

            if ts.consume_if('SYMBOL', '<'):
                targs = parse_template_args(ts)
            else:
                targs = []

            if ts.consume_if('SYMBOL', '('):
                tuple_pars = parse_tuple_args(ts)
                ts.expect('SYMBOL', ')')
            else:
                tuple_pars = []

            mods = parse_modifiers(ts)

            child = TypeNode(
                leading_mods=[mod],
                typename=typename,
                template_args=targs,
                tuple_args=tuple_pars,
                trailing_mods=mods
            )
            parent.nested_types.append(child)
            parse_nested_chain(child, ts)
        else:
            sub_name = ts.next()[1]

            if ts.consume_if('SYMBOL', '<'):
                targs = parse_template_args(ts)
                tuple_pars = []
                if ts.consume_if('SYMBOL', '('):
                    tuple_pars = parse_tuple_args(ts)
                    ts.expect('SYMBOL', ')')
                mods = parse_modifiers(ts)
                child = TypeNode(typename=sub_name, template_args=targs,
                                 tuple_args=tuple_pars, trailing_mods=mods)
                parent.nested_types.append(child)
                parse_nested_chain(child, ts)
            elif ts.consume_if('SYMBOL', '('):
                tuple_pars = parse_tuple_args(ts)
                ts.expect('SYMBOL', ')')
                mods = parse_modifiers(ts)
                child = TypeNode(typename=sub_name, tuple_args=tuple_pars, trailing_mods=mods)
                parent.nested_types.append(child)
                parse_nested_chain(child, ts)
            else:
                mods = parse_modifiers(ts)
                child = TypeNode(typename=sub_name, trailing_mods=mods)
                parent.nested_types.append(child)
                parse_nested_chain(child, ts)

def is_function_pointer(ts):
    pos = ts.pos
    if pos < len(ts.tokens) and ts.tokens[pos] == ('SYMBOL', '('):
        temp_pos = pos + 1
        if temp_pos < len(ts.tokens) and ts.tokens[temp_pos][0] == 'WORD' and ts.tokens[temp_pos][1] in {'__cdecl', '__stdcall', '__fastcall', '__vectorcall', '__thiscall'}:
            temp_pos += 1
        if temp_pos < len(ts.tokens) and ts.tokens[temp_pos] == ('SYMBOL', '*'):
            return True
    return False

def parse_function_pointer(ts, namespaces, base_typename, targs, leading_mods):
    if not is_function_pointer(ts):
        return None

    ts.next()  # '('
    calling_convention = None
    if ts.peek() and ts.peek()[0] == 'WORD' and ts.peek()[1] in {'__cdecl', '__stdcall', '__fastcall', '__vectorcall', '__thiscall'}:
        calling_convention = ts.next()[1]
    if not ts.consume_if('SYMBOL', '*'):
        return None
    if not ts.consume_if('SYMBOL', ')'):
        raise ParserError('Expected \')\' after function pointer \'*\'.')
    if not ts.consume_if('SYMBOL', '('):
        raise ParserError('Expected \'(\' to start function pointer parameter list.')
    parameters = parse_tuple_args(ts)
    ts.expect('SYMBOL', ')')

    return FunctionPointerNode(
        return_type=TypeNode(
            namespaces=namespaces,
            typename=base_typename,
            template_args=targs,
            leading_mods=leading_mods
        ),
        calling_convention=calling_convention,
        parameters=parameters
    )

def parse_template_args(ts):
    args = []
    while True:
        nxt = ts.peek()
        if not nxt:
            raise ParserError('Unclosed <... in template args')
        if nxt == ('SYMBOL', '>'):
            ts.next()
            break

        arg = parse_one_template_argument(ts)
        if not arg:
            raise ParserError('Failed to parse template argument')
        args.append(arg)

        ts.consume_if('SYMBOL', ',')
    return args

def parse_one_template_argument(ts):
    nxt = ts.peek()
    if not nxt:
        return None

    if nxt[0] == 'ELLIPSIS':
        ts.next()
        return EllipsisNode()

    if nxt[0] == 'NUMBER':
        val = int(nxt[1])
        ts.next()
        return ValueNode(val)

    type_node = parse_type_with_nesting(ts)
    if type_node:
        return type_node

    return None

def parse_tuple_args(ts):
    params = []
    first = True
    while True:
        nxt = ts.peek()
        if not nxt or nxt == ('SYMBOL', ')'):
            break
        if not first:
            if not ts.consume_if('SYMBOL', ','):
                break
        first = False

        save_pos = ts.pos
        ptype = parse_type_with_nesting(ts)
        if ptype:
            nxt2 = ts.peek()
            if nxt2 and nxt2[0] == 'WORD':
                pname = nxt2[1]
                ts.next()
                params.append(ParameterNode(type_node=ptype, param_name=pname))
            else:
                params.append(ParameterNode(type_node=ptype))
        else:
            ts.pos = save_pos
            val = parse_maybe_literal(ts)
            if val is None:
                raise ParserError('Failed to parse argument in tuple_args.')
            params.append(ParameterNode(value_node=val))

    return params

def parse_maybe_literal(ts):
    nxt = ts.peek()
    if nxt and nxt[0] == 'NUMBER':
        ts.next()
        return ValueNode(int(nxt[1]))
    return None

def parse_modifiers(ts):
    mods = []
    while True:
        nxt = ts.peek()
        if not nxt:
            break
        if nxt[0] == 'WORD':
            w_ = nxt[1]
            if w_ in (
                'const', 'volatile', 'constexpr', 'static', 'inline', 'extern',
                'register', 'mutable', 'thread_local', 'typename',
                '__cdecl', '__stdcall', '__fastcall', '__vectorcall', '__thiscall',
                'class', 'struct', 'enum'
            ):
                mods.append(w_)
                ts.next()
            else:
                break
        elif nxt[0] == 'SYMBOL':
            sym = nxt[1]
            if sym in ('&', '&&', '*'):
                mods.append(sym)
                ts.next()
            else:
                break
        else:
            break
    return mods

################################################################################
# ASTParser
################################################################################

class ASTParser:
    def __init__(self):
        self.rules = []

    def add_rule(self, rule_func):
        self.rules.append(rule_func)

    def parse(self, code):
        tokens = tokenize(code)
        ts = TokenStream(tokens)
        ast_nodes = []
        while not ts.eof():
            node = parse_declaration(ts)
            if node:
                node = node.apply_rules(self.rules)
                if node:
                    ast_nodes.append(node)
            else:
                break
        return ast_nodes

################################################################################
# vdump - fast AST utilities with caching
################################################################################

def function_pointer_to_void_pointer_rule(node):
    if isinstance(node, FunctionPointerNode):
        return TypeNode(
            typename='void',
            trailing_mods=['*']
        )
    return node

@lru_cache(maxsize=16384)
def extract_function_info(decl_str):
    if not decl_str:
        return None
    if not decl_str.endswith(';'):
        decl_str += ';'
    parser = ASTParser()
    parser.add_rule(function_pointer_to_void_pointer_rule)
    try:
        ast_nodes = parser.parse(decl_str)
    except Exception:
        return None

    for node in ast_nodes:
        if isinstance(node, FunctionNode):
            params = []
            for p in node.parameters:
                s = to_code(p, top_level=False)
                if s == 'void' and len(node.parameters) == 1:
                    break
                elif s == 'void' and len(node.parameters) > 1:
                    s = 'void*'
                params.append(s)
            func_name = node.func_name or (node.return_type.typename if node.return_type else '')
            return (func_name, tuple(params))

        if isinstance(node, TypeNode):
            params = []
            for p in node.tuple_args:
                s = to_code(p, top_level=False)
                if s == 'void' and len(node.tuple_args) == 1:
                    break
                elif s == 'void' and len(node.tuple_args) > 1:
                    s = 'void*'
                params.append(s)
            return (node.typename, tuple(params))
    return None

@lru_cache(maxsize=8192)
def extract_object_name(decl_str):
    if not decl_str:
        return None
    if not decl_str.endswith(';'):
        decl_str += ';'
    parser = ASTParser()
    parser.add_rule(function_pointer_to_void_pointer_rule)
    try:
        ast_nodes = parser.parse(decl_str)
    except Exception:
        return 'void*'

    for node in ast_nodes:
        if isinstance(node, TypeNode):
            targs = node.template_args
            if targs:
                thash = hashlib.sha256(b''.join([to_code(targ, top_level=False).encode() for targ in targs])).hexdigest().upper()
                return '_'.join(node.namespaces) + ('_' if node.namespaces else '') + node.typename + f'_{thash[:8]}'
            else:
                return '_'.join(node.namespaces) + ('_' if node.namespaces else '') + node.typename
        if isinstance(node, VariableNode):
            return '_'.join(node.type_node.namespaces) + ('_' if node.type_node.namespaces else '') + node.type_node.typename + ' ' + node.var_name
        if isinstance(node, FunctionPointerNode):
            return 'void*'
    return None

################################################################################
# Signature cache (decompile/parse once per EA)
################################################################################

class SignatureCache:
    def __init__(self, converter_ref=None):
        self.sig = {}  # ea -> dict(ret_str, args, base, special)
        self.conv = converter_ref  # filled later

    def attach(self, conv):
        self.conv = conv

    @lru_cache(maxsize=16384)
    def _canon_from_demangled(self, arg: str) -> str:
        tif = _parse_type_cached(arg)
        if tif:
            try:
                if tif.is_func() or tif.is_funcptr():
                    return 'void*'
                if tif.is_ptr():
                    pt = ida_typeinf.remove_pointer(tif)
                    if pt:
                        pt.clr_decl_const_volatile()
                        if is_builtin_type(pt):
                            out = re.sub(r'\s+', ' ', arg)
                            return out.replace(' *', '*').replace(' &', '&')
                    return 'void*'
                if is_builtin_type(tif):
                    return re.sub(r'\s+', ' ', arg)
            except Exception:
                pass
        return 'void*'

    def get(self, ea: int, demangled: str):
        if ea in self.sig:
            return self.sig[ea]

        d = _sanitize_demangled(demangled)
        base_name = d.split('(')[0].split('::')[-1]

        # Try to get type info (prefer decompile)
        ret_str = 'void'
        decomp_t = None
        try:
            decomp = ida_hexrays.decompile(ea)
        except Exception:
            decomp = None
        if decomp:
            decomp_t = decomp.type
            rt = decomp_t.get_rettype()
            rt.clr_decl_const_volatile()
            ret_str = self.conv.simplify_type(rt)
        else:
            f = ida_funcs.get_func(ea)
            if f and f.prototype:
                decomp_t = f.prototype
                rt = decomp_t.get_rettype()
                rt.clr_decl_const_volatile()
                ret_str = self.conv.simplify_type(rt)

        # Build args (fallback to decompiled prototype first)
        args = []
        if decomp_t and decomp_t.is_func():
            try:
                for i in range(1, decomp_t.get_nargs()):
                    a = decomp_t.get_nth_arg(i)
                    a.clr_decl_const_volatile()
                    astr = self.conv.simplify_type(a)
                    if astr == 'void' and i <= 2:
                        astr = 'void*'
                    args.append(astr)
            except Exception:
                args = []

        # If demangled signature is parseable, prefer it (canonicalized & cached)
        fi = extract_function_info(d)
        if fi:
            _, dargs = fi
            args = [ self._canon_from_demangled(a) for a in dargs ]
            # Ret stays from decompiler/prototype (more reliable)

        # classify special
        special = None
        if d.startswith('~') or '::~' in d or 'destructor' in d:
            special = 'destructor'
        elif d.startswith('___cxa_pure_virtual') or d.startswith('__purecall'):
            special = 'pure'

        self.sig[ea] = dict(ret=ret_str, args=tuple(args), base=base_name, special=special)
        return self.sig[ea]

SIGCACHE = SignatureCache()

################################################################################
# DeclarationConverter
################################################################################

class DeclarationConverter:
    def __init__(self):
        self.reset_state()
        SIGCACHE.attach(self)

    def reset_state(self):
        self.class_map = {}
        self.reverse_graph = {}
        self.in_degree = {}
        self.declare = set()
        self.forward_decls = set()
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
            node[1] = node[1].replace('`anonymous namespace\'::', '')
            class_name = extract_object_name(node[1])

            if class_name in self.class_map:
                continue

            base_names = []
            for base_node in node[2]:
                if base_node is None:
                    continue
                base_node[1] = base_node[1].replace('`anonymous namespace\'::', '')
                base_name = extract_object_name(base_node[1])
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

    def _canon_arg(self, arg_str):
        tif = self.parse_type(arg_str)
        if tif and is_builtin_type(tif):
            return arg_str
        return 'void*'

    def _key_for_compare(self, idx, func, demangled, cls, offset):
        d = _sanitize_demangled(demangled)

        if d.startswith('~') or '::~' in d or 'destructor' in d:
            return None
        if d[:19] == '___cxa_pure_virtual' or d[:10] == '__purecall':
            return None
        if '?' in d or '@' in d or '$' in d:
            return None
        if d.startswith('nullsub_'):
            return None

        fi = extract_function_info(d)
        if fi:
            base_name, dargs = fi
            base_name = base_name.strip()
            norm_args = tuple(self._canon_arg(a) for a in dargs)
            return (base_name, norm_args)

        base_name = d.split('(')[0].split('::')[-1].strip()
        return (base_name, ())

    def _collect_key_counts_from_nonzero_offsets(self, cls):
        if _FILETYPE != ida_ida.f_MACHO:
            return collections.Counter()

        cnt = collections.Counter()
        offmap = self.class_vfuncs.get(cls, {})
        for off, lst in offmap.items():
            if off == 0:
                continue
            for i, (ea, dem) in enumerate(lst):
                if not dem:
                    continue
                dem2 = _sanitize_demangled(dem)
                key = self._key_for_compare(i, ea, dem2, cls, off)
                if key:
                    cnt[key] += 1
        return cnt

    def _enumerate_vfuncs_filtered(self, cls, offset, vfuncs, other_counts):
        if _FILETYPE != ida_ida.f_MACHO or offset != 0:
            return [(i, i, ea, dem) for i, (ea, dem) in enumerate(vfuncs)]

        out = []
        logical = 0
        for phys_i, (ea, dem) in enumerate(vfuncs):
            if not dem:
                continue
            dem2 = _sanitize_demangled(dem)
            key = self._key_for_compare(phys_i, ea, dem2, cls, offset)
            if key and other_counts.get(key, 0) > 0:
                other_counts[key] -= 1
                continue
            out.append((logical, phys_i, ea, dem))
            logical += 1
        return out

    # ---------- shared low-level utilities ----------

    def _normalize_operator_name(self, base_name, idx):
        name = (base_name or '').strip()
        if name.startswith('operator'):
            return f'operator_{idx:010}'
        return name

    def parse_type(self, s):
        return _parse_type_cached(s)

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

    # ---------- Full class need check ----------

    def _need_full_class(self, filtered, full_list) -> bool:
        f1 = [ _sanitize_demangled(d) for _, _, _, d in filtered if d ]
        f2 = [ _sanitize_demangled(d) for _, _, ea, d in full_list if d ]
        return f1 != f2

    # ---------- codegen helpers ----------

    def _next_unique_name(self, cls, offset, func_name):
        self.used_func_names.setdefault((cls, offset), {}).setdefault(func_name, 0)
        self.used_func_names[(cls, offset)][func_name] += 1
        count = self.used_func_names[(cls, offset)][func_name]
        return f'{func_name}_{count}' if count > 1 else func_name

    def _emit_virtual_decl(self, idx, ea, demangled, cls, offset, dtor_class_name):
        d = _sanitize_demangled(demangled)

        if d[:19] == '___cxa_pure_virtual' or d[:10] == '__purecall':
            return f'virtual void PureStub_{idx:010}() = 0;'

        if d.startswith('~') or 'destructor' in d or '~' in d:
            return f'virtual ~{dtor_class_name}() = 0;'

        if '?' in d or '@' in d or '$' in d:
            return f'virtual void InvalidStub_{idx:010}() = 0;'

        sig = SIGCACHE.get(ea, d)
        ret_str = sig['ret']
        base = sig['base']
        args = list(sig['args'])

        if ida_bytes.has_dummy_name(ida_bytes.get_flags(ea)):
            return f'virtual void Stub_{idx:010}({", ".join(args)}) = 0;'

        if d[:8] == 'nullsub_':
            return f'virtual void NullStub_{idx:010}({", ".join(args)}) = 0;'

        func_name = self._normalize_operator_name(base, idx)
        func_name = self._next_unique_name(cls, offset, func_name)
        return f'virtual {ret_str} {func_name}({", ".join(args)}) = 0;'

    def _emit_static_invoke(self, idx_logical, ret_str, args):
        if args:
            nargs = [f'{arg} a{i}' for i, arg in enumerate(args, start=1)]
            naargs = [f'a{i}' for i in range(1, len(args) + 1)]
            return (
                f'static {ret_str} INVOKE(void* pThis, int nFixOffset, {", ".join(nargs)}) {{ '
                f'void** pVTable = *reinterpret_cast<void***>(pThis); '
                f'return reinterpret_cast<{ret_str}(__thiscall*)(void*, {", ".join(args)})>'
                f'(pVTable[{idx_logical} + nFixOffset])(pThis, {", ".join(naargs)}); }};'
            )
        else:
            return (
                f'static {ret_str} INVOKE(void* pThis, int nFixOffset) {{ '
                f'void** pVTable = *reinterpret_cast<void***>(pThis); '
                f'return reinterpret_cast<{ret_str}(__thiscall*)(void*)>'
                f'(pVTable[{idx_logical} + nFixOffset])(pThis); }};'
            )

    def _emit_static_decl(self, idx_logical, ea, demangled, cls, offset, name_prefix, dtor_class_name):
        d = _sanitize_demangled(demangled)

        if d[:19] == '___cxa_pure_virtual' or d[:10] == '__purecall':
            return (
                f'static void static_PureStub_{idx_logical:010}(void* pThis, int nFixOffset) {{ '
                f'void** pVTable = *reinterpret_cast<void***>(pThis); '
                f'reinterpret_cast<void(__thiscall*)(void*)>(pVTable[{idx_logical} + nFixOffset])(pThis); }};'
            )

        if d.startswith('~') or 'destructor' in d or '~' in d:
            return (
                f'static void static_destructor_{dtor_class_name}(void* pThis, int nFixOffset) {{ '
                f'void** pVTable = *reinterpret_cast<void***>(pThis); '
                f'reinterpret_cast<void(__thiscall*)(void*)>(pVTable[{idx_logical} + nFixOffset])(pThis); }};'
            )

        if '?' in d or '@' in d or '$' in d:
            return (
                f'static void static_InvalidStub_{idx_logical:010}(void* pThis, int nFixOffset) {{ '
                f'void** pVTable = *reinterpret_cast<void***>(pThis); '
                f'reinterpret_cast<void(__thiscall*)(void*)>(pVTable[{idx_logical} + nFixOffset])(pThis); }};'
            )

        sig = SIGCACHE.get(ea, d)
        ret_str = sig['ret']
        base = sig['base']
        args = list(sig['args'])

        if ida_bytes.has_dummy_name(ida_bytes.get_flags(ea)):
            if args:
                nargs = [f'{arg} a{i}' for i, arg in enumerate(args, start=1)]
                naargs = [f'a{i}' for i in range(1, len(args) + 1)]
                return (
                    f'static void static_Stub_{idx_logical:010}(void* pThis, int nFixOffset, {", ".join(nargs)}) {{ '
                    f'void** pVTable = *reinterpret_cast<void***>(pThis); '
                    f'reinterpret_cast<void(__thiscall*)(void*, {", ".join(args)})>(pVTable[{idx_logical} + nFixOffset])'
                    f'(pThis, {", ".join(naargs)}); }};'
                )
            else:
                return (
                    f'static void static_Stub_{idx_logical:010}(void* pThis, int nFixOffset) {{ '
                    f'void** pVTable = *reinterpret_cast<void***>(pThis); '
                    f'reinterpret_cast<void(__thiscall*)(void*)>(pVTable[{idx_logical} + nFixOffset])(pThis); }};'
                )

        if d[:8] == 'nullsub_':
            if args:
                nargs = [f'{arg} a{i}' for i, arg in enumerate(args, start=1)]
                naargs = [f'a{i}' for i in range(1, len(args) + 1)]
                return (
                    f'static void static_NullStub_{idx_logical:010}(void* pThis, int nFixOffset, {", ".join(nargs)}) {{ '
                    f'void** pVTable = *reinterpret_cast<void***>(pThis); '
                    f'reinterpret_cast<void(__thiscall*)(void*, {", ".join(args)})>(pVTable[{idx_logical} + nFixOffset])'
                    f'(pThis, {", ".join(naargs)}); }};'
                )
            else:
                return (
                    f'static void static_NullStub_{idx_logical:010}(void* pThis, int nFixOffset) {{ '
                    f'void** pVTable = *reinterpret_cast<void***>(pThis); '
                    f'reinterpret_cast<void(__thiscall*)(void*)>(pVTable[{idx_logical} + nFixOffset])(pThis); }};'
                )

        func_name = self._normalize_operator_name(base, idx_logical)
        func_name = f'{name_prefix}{func_name}'
        func_name = self._next_unique_name(cls, offset, func_name)

        invoke = self._emit_static_invoke(idx_logical, ret_str, args).replace('INVOKE', func_name)
        return invoke

    def _emit_get_decl(self, idx_logical, ea, demangled, cls, offset, name_prefix, dtor_class_name):
        d = _sanitize_demangled(demangled)

        if d[:19] == '___cxa_pure_virtual' or d[:10] == '__purecall':
            return (
                f'static void* get_PureStub_{idx_logical:010}(void* pThis, int nFixOffset) {{ '
                f'void** pVTable = *reinterpret_cast<void***>(pThis); '
                f'return pVTable[{idx_logical} + nFixOffset]; }};'
            )

        if d.startswith('~') or 'destructor' in d or '~' in d:
            return (
                f'static void* get_destructor_{dtor_class_name}(void* pThis, int nFixOffset) {{ '
                f'void** pVTable = *reinterpret_cast<void***>(pThis); '
                f'return pVTable[{idx_logical} + nFixOffset]; }};'
            )

        if '?' in d or '@' in d or '$' in d:
            return (
                f'static void* get_InvalidStub_{idx_logical:010}(void* pThis, int nFixOffset) {{ '
                f'void** pVTable = *reinterpret_cast<void***>(pThis); '
                f'return pVTable[{idx_logical} + nFixOffset]; }};'
            )

        base = SIGCACHE.get(ea, d)['base']

        if ida_bytes.has_dummy_name(ida_bytes.get_flags(ea)):
            return (
                f'static void* get_Stub_{idx_logical:010}(void* pThis, int nFixOffset) {{ '
                f'void** pVTable = *reinterpret_cast<void***>(pThis); '
                f'return pVTable[{idx_logical} + nFixOffset]; }};'
            )

        if d[:8] == 'nullsub_':
            return (
                f'static void* get_NullStub_{idx_logical:010}(void* pThis, int nFixOffset) {{ '
                f'void** pVTable = *reinterpret_cast<void***>(pThis); '
                f'return pVTable[{idx_logical} + nFixOffset]; }};'
            )

        func_name = self._normalize_operator_name(base, idx_logical)
        func_name = f'{name_prefix}{func_name}'
        func_name = self._next_unique_name(cls, offset, func_name)

        return (
            f'static void* {func_name}(void* pThis, int nFixOffset) {{ '
            f'void** pVTable = *reinterpret_cast<void***>(pThis); '
            f'return pVTable[{idx_logical} + nFixOffset]; }};'
        )

    # ---------- public generation ----------

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

        class_declarations = []
        class_name_map = {}

        for cls in sorted_classes:
            if cls not in self.class_vfuncs:
                continue

            other_counts = self._collect_key_counts_from_nonzero_offsets(cls)

            std_decls_for_cls = []
            full_decls_for_cls = []

            for offset in self.class_vfuncs[cls]:
                offset_name       = f'{cls}_{offset:08X}'
                offset_name_full  = f'{cls}_Full_{offset:08X}'
                class_name_map[(cls, offset)] = offset_name

                self.forward_decls.add(f'class {offset_name}; // OFFSET: {offset:08X}')

                vfuncs = self.class_vfuncs[cls][offset]

                filtered = self._enumerate_vfuncs_filtered(cls, offset, vfuncs, other_counts)

                decl_lines = [
                    f'class {offset_name} {{ // OFFSET: {offset:08X}',
                    'public:'
                ]

                for log_i, phys_i, func, demangled in filtered:
                    if not demangled:
                        continue
                    d2 = _sanitize_demangled(demangled)
                    decl = self._emit_virtual_decl(log_i, func, d2, cls, offset, offset_name)
                    decl_lines.append(f'    // {log_i:>10} - {d2}')
                    decl_lines.append(f'    {decl}\n')

                for log_i, phys_i, func, demangled in filtered:
                    if not demangled:
                        continue
                    d2 = _sanitize_demangled(demangled)
                    decl = self._emit_static_decl(log_i, func, d2, cls, offset, 'static_', offset_name)
                    decl_lines.append(f'    {decl}')

                decl_lines.append('')

                for log_i, phys_i, func, demangled in filtered:
                    if not demangled:
                        continue
                    d2 = _sanitize_demangled(demangled)
                    decl = self._emit_get_decl(log_i, func, d2, cls, offset, 'get_', offset_name)
                    decl_lines.append(f'    {decl}')

                decl_lines.append('};')

                std_decls_for_cls.append('\n'.join(decl_lines))

                self.used_func_names[(cls, offset)] = {}

                full_list = [(i, i, ea, dem) for i, (ea, dem) in enumerate(vfuncs)]
                need_full = self._need_full_class(filtered, full_list)

                if need_full:
                    self.forward_decls.add(f'class {offset_name_full}; // OFFSET: {offset:08X}')

                    decl_lines_full = [
                        f'class {offset_name_full} {{ // OFFSET: {offset:08X}',
                        'public:'
                    ]

                    for log_i, phys_i, func, demangled in full_list:
                        if not demangled:
                            continue
                        d2 = _sanitize_demangled(demangled)
                        decl = self._emit_virtual_decl(log_i, func, d2, cls, offset, offset_name_full)
                        decl_lines_full.append(f'    // {log_i:>10} - {d2}')
                        decl_lines_full.append(f'    {decl}\n')

                    for log_i, phys_i, func, demangled in full_list:
                        if not demangled:
                            continue
                        d2 = _sanitize_demangled(demangled)
                        decl = self._emit_static_decl(log_i, func, d2, cls, offset, 'static_', offset_name_full)
                        decl_lines_full.append(f'    {decl}')

                    decl_lines_full.append('')

                    for log_i, phys_i, func, demangled in full_list:
                        if not demangled:
                            continue
                        d2 = _sanitize_demangled(demangled)
                        decl = self._emit_get_decl(log_i, func, d2, cls, offset, 'get_', offset_name_full)
                        decl_lines_full.append(f'    {decl}')

                    decl_lines_full.append('};')

                    full_decls_for_cls.append('\n'.join(decl_lines_full))

            class_declarations.extend(std_decls_for_cls)
            class_declarations.extend(full_decls_for_cls)

        for cls in self.declare:
            if cls not in sorted_classes:
                self.forward_decls.add(f'class {cls} {{}};')

        return '\n' + \
               '\n'.join(sorted(self.forward_decls)) + \
               '\n\n' + \
               '\n\n'.join(class_declarations)

################################################################################
# vtable scanning
################################################################################

def get_vtable_functions(vtable):
    funcs = []
    i = 0
    destructor_count = 0

    if _FILETYPE in (ida_ida.f_ELF, ida_ida.f_MACHO):
        ___cxa_pure_virtual = ida_name.get_name_ea(0, '___cxa_pure_virtual')

    while True:
        if _IS64:
            if not ida_bytes.is_off(ida_bytes.get_flags(vtable + 8 * i), 0):
                break
            func = ida_bytes.get_qword(vtable + 8 * i)
        else:
            if not ida_bytes.is_off(ida_bytes.get_flags(vtable + 4 * i), 0):
                break
            func = ida_bytes.get_dword(vtable + 4 * i)

        if not ida_funcs.get_func(func):
            if _FILETYPE in (ida_ida.f_ELF, ida_ida.f_MACHO):
                if func != ___cxa_pure_virtual:
                    break
            elif _FILETYPE == ida_ida.f_PE:
                flags = ida_bytes.get_flags(func)
                if not ida_bytes.is_code(flags):
                    break

        demangled = ida_name.get_demangled_name(func, 0, 0)
        if not demangled:
            i += 1
            continue

        if '::~' in demangled:
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

    if _FILETYPE in (ida_ida.f_ELF, ida_ida.f_MACHO):
        type_addresses = (
            ida_name.get_name_ea(ida_idaapi.BADADDR, '__ZTVN10__cxxabiv117__class_type_infoE'),    # Single
            ida_name.get_name_ea(ida_idaapi.BADADDR, '__ZTVN10__cxxabiv120__si_class_type_infoE'), # One parent
            ida_name.get_name_ea(ida_idaapi.BADADDR, '__ZTVN10__cxxabiv121__vmi_class_type_infoE') # Multiple parents
        )

        for type_address in type_addresses:
            if not is_valid_address(type_address):
                continue

            type_reference = ida_xref.get_first_dref_to(type_address)
            while is_valid_address(type_reference):

                if _IS64:
                    name_address = ida_bytes.get_qword(type_reference + 8)
                else:
                    name_address = ida_bytes.get_dword(type_reference + 4)

                if not is_valid_address(name_address):
                    type_reference = ida_xref.get_next_dref_to(type_address, type_reference)
                    continue

                name = ida_bytes.get_strlit_contents(name_address, -1, 0)
                if not name:
                    type_reference = ida_xref.get_next_dref_to(type_address, type_reference)
                    continue

                name = name.decode(errors='ignore')
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
        base_address = ida_bytes.get_qword(typeinfo_address + 16) if _IS64 else ida_bytes.get_dword(typeinfo_address + 8)
        base_node = get_typeinfo_bases(base_address, type_infos, visited)
        if base_node:
            bases.append(base_node)
    elif type_base == TYPE_INFO_ADDRESSES[2]:
        if _IS64:
            base_count = ida_bytes.get_dword(typeinfo_address + 20)
            base_offset = 24
            entry_size  = 16
        else:
            base_count = ida_bytes.get_dword(typeinfo_address + 12)
            base_offset = 16
            entry_size  = 8
        
        for i in range(base_count):
            base_address = ida_bytes.get_qword(typeinfo_address + base_offset + i * entry_size) if _IS64 \
                           else ida_bytes.get_dword(typeinfo_address + base_offset + i * entry_size)

            if base_address == typeinfo_address:
                continue

            base_node = get_typeinfo_bases(base_address, type_infos, visited)
            if base_node:
                bases.append(base_node)
    
    visited.remove(typeinfo_address)
    return [typeinfo_address, name, bases]

def find_vtables_typeinfo(typeinfo):
    vtables = []

    if _FILETYPE in (ida_ida.f_ELF, ida_ida.f_MACHO):
        vtable_reference = ida_xref.get_first_dref_to(typeinfo)
        while is_valid_address(vtable_reference):
            offset = ida_bytes.get_qword(vtable_reference - 8) if _IS64 else ida_bytes.get_dword(vtable_reference - 4)

            if offset != 0 and offset <= 0x7FFFFFFF:
                if _IS64:
                    if not ida_bytes.is_off(ida_bytes.get_flags(vtable_reference - 8), 0):
                        vtable_reference = ida_xref.get_next_dref_to(typeinfo, vtable_reference); continue
                else:
                    if not ida_bytes.is_off(ida_bytes.get_flags(vtable_reference - 4), 0):
                        vtable_reference = ida_xref.get_next_dref_to(typeinfo, vtable_reference); continue

            offset = int(-1 * int.from_bytes((offset if _IS64 else offset).to_bytes(8 if _IS64 else 4, 'little', signed=False),
                                             byteorder='little', signed=True))
            if offset < 0:
                vtable_reference = ida_xref.get_next_dref_to(typeinfo, vtable_reference)
                continue

            if _IS64:
                if not ida_bytes.is_off(ida_bytes.get_flags(vtable_reference + 8), 0):
                    vtable_reference = ida_xref.get_next_dref_to(typeinfo, vtable_reference); continue
                if not ida_funcs.get_func(ida_bytes.get_qword(vtable_reference + 8)):
                    vtable_reference = ida_xref.get_next_dref_to(typeinfo, vtable_reference); continue
            else:
                if not ida_bytes.is_off(ida_bytes.get_flags(vtable_reference + 4), 0):
                    vtable_reference = ida_xref.get_next_dref_to(typeinfo, vtable_reference); continue
                if not ida_funcs.get_func(ida_bytes.get_dword(vtable_reference + 4)):
                    vtable_reference = ida_xref.get_next_dref_to(typeinfo, vtable_reference); continue

            vtables.append([offset, vtable_reference + (8 if _IS64 else 4)])
            vtable_reference = ida_xref.get_next_dref_to(typeinfo, vtable_reference)

    return vtables

# --------------------
# PE
# --------------------

def find_typeinfo_vtable():
    if _FILETYPE == ida_ida.f_PE:
        min_address = ida_ida.inf_get_min_ea()
        while True:
            address = find_pattern('2E 3F 41 56 74 79 70 65 5F 69 6E 66 6F 40 40 00', min_address=min_address) # .?AVtype_info@@
            if not is_valid_address(address):
                break

            min_address = address + 16

            if _IS64:
                if not ida_bytes.is_off(ida_bytes.get_flags(address - 16), 0):
                    continue
                typeinfo_vtable_address = ida_bytes.get_qword(address - 16)
                if not ida_bytes.is_qword(ida_bytes.get_flags(address - 8)):
                    continue
                spare = ida_bytes.get_qword(address - 8)
            else:
                if not ida_bytes.is_off(ida_bytes.get_flags(address - 8), 0):
                    continue
                typeinfo_vtable_address = ida_bytes.get_dword(address - 8)
                if not ida_bytes.is_dword(ida_bytes.get_flags(address - 4)):
                    continue
                spare = ida_bytes.get_dword(address - 4)

            if not is_valid_address(typeinfo_vtable_address) or spare != 0:
                continue

            return typeinfo_vtable_address

def find_type_descriptions(typeinfo_vtable):
    type_descriptors = []

    if _FILETYPE == ida_ida.f_PE:
        vtable_reference = ida_xref.get_first_dref_to(typeinfo_vtable)
        while is_valid_address(vtable_reference):
            if not ida_bytes.has_xref(ida_bytes.get_flags(vtable_reference)):
                vtable_reference = ida_xref.get_next_dref_to(typeinfo_vtable, vtable_reference)
                continue

            if _IS64:
                if not ida_bytes.is_qword(ida_bytes.get_flags(vtable_reference + 8)):
                    vtable_reference = ida_xref.get_next_dref_to(typeinfo_vtable, vtable_reference); continue
                spare = ida_bytes.get_qword(vtable_reference + 8)
            else:
                if not ida_bytes.is_dword(ida_bytes.get_flags(vtable_reference + 4)):
                    vtable_reference = ida_xref.get_next_dref_to(typeinfo_vtable, vtable_reference); continue
                spare = ida_bytes.get_dword(vtable_reference + 4)

            if spare != 0:
                vtable_reference = ida_xref.get_next_dref_to(typeinfo_vtable, vtable_reference)
                continue

            name = ida_bytes.get_strlit_contents(vtable_reference + (16 if _IS64 else 8), -1, 0)
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
    if _FILETYPE == ida_ida.f_PE:
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

    if _FILETYPE == ida_ida.f_PE:
        type_descriptor_reference = ida_xref.get_first_dref_to(type_descriptor)
        while is_valid_address(type_descriptor_reference):
            if not ida_bytes.has_xref(ida_bytes.get_flags(type_descriptor_reference)):
                type_descriptor_reference = ida_xref.get_next_dref_to(type_descriptor, type_descriptor_reference)
                continue

            if _IS64:
                if not ida_bytes.is_dword(ida_bytes.get_flags(type_descriptor_reference - 0xC)):
                    type_descriptor_reference = ida_xref.get_next_dref_to(type_descriptor, type_descriptor_reference)
                    continue
                signature = ida_bytes.get_dword(type_descriptor_reference - 0xC)
            else:
                if not ida_bytes.is_dword(ida_bytes.get_flags(type_descriptor_reference - 0xC)):
                    type_descriptor_reference = ida_xref.get_next_dref_to(type_descriptor, type_descriptor_reference)
                    continue
                signature = ida_bytes.get_dword(type_descriptor_reference - 0xC)

            if signature != 0 and signature != 1:
                type_descriptor_reference = ida_xref.get_next_dref_to(type_descriptor, type_descriptor_reference)
                continue

            offset = ida_bytes.get_dword(type_descriptor_reference - 0x8)

            if not ida_bytes.is_off(ida_bytes.get_flags(type_descriptor_reference + 0x4), 0):
                type_descriptor_reference = ida_xref.get_next_dref_to(type_descriptor, type_descriptor_reference)
                continue

            if _IS64:
                if _IMGBASE + ida_bytes.get_dword(type_descriptor_reference + 0x8) != type_descriptor_reference - 0xC:
                    type_descriptor_reference = ida_xref.get_next_dref_to(type_descriptor, type_descriptor_reference)
                    continue

            complete_objects.append([offset, type_descriptor_reference - 0xC])

            type_descriptor_reference = ida_xref.get_next_dref_to(type_descriptor, type_descriptor_reference)

    return complete_objects

def get_bases_from_base_class_descriptor(base_class_descriptor, type_descriptions):
    bases = []

    if _FILETYPE == ida_ida.f_PE:
        class_hierarchy_descriptor = (_IMGBASE + ida_bytes.get_dword(base_class_descriptor + 24)) if _IS64 \
                                     else ida_bytes.get_dword(base_class_descriptor + 24)

        signature = ida_bytes.get_dword(class_hierarchy_descriptor)
        if signature != 0 and signature != 1:
            return bases

        number_of_bases = ida_bytes.get_dword(class_hierarchy_descriptor + 8)
        array_of_bases  = (_IMGBASE + ida_bytes.get_dword(class_hierarchy_descriptor + 12)) if _IS64 \
                          else ida_bytes.get_dword(class_hierarchy_descriptor + 12)

        for i in range(number_of_bases):
            based_class_descriptor = (_IMGBASE + ida_bytes.get_dword(array_of_bases + 4 * i)) if _IS64 \
                                     else ida_bytes.get_dword(array_of_bases + 4 * i)
            based_class_descriptor_type_descriptor = (_IMGBASE + ida_bytes.get_dword(based_class_descriptor)) if _IS64 \
                                                     else ida_bytes.get_dword(based_class_descriptor)

            if based_class_descriptor == base_class_descriptor:
                continue

            for address, name in type_descriptions:
                if address == based_class_descriptor_type_descriptor:
                    bases.append((based_class_descriptor, name))

    return bases

def get_bases_from_complete_object(complete_object, type_descriptions):
    bases = []

    if _FILETYPE == ida_ida.f_PE:
        complete_object_type_descriptor = (_IMGBASE + ida_bytes.get_dword(complete_object + 12)) if _IS64 \
                                          else ida_bytes.get_dword(complete_object + 12)
        class_hierarchy_descriptor      = (_IMGBASE + ida_bytes.get_dword(complete_object + 16)) if _IS64 \
                                          else ida_bytes.get_dword(complete_object + 16)

        signature = ida_bytes.get_dword(class_hierarchy_descriptor)
        if signature != 0 and signature != 1:
            return bases

        number_of_bases = ida_bytes.get_dword(class_hierarchy_descriptor + 8)
        array_of_bases  = (_IMGBASE + ida_bytes.get_dword(class_hierarchy_descriptor + 12)) if _IS64 \
                          else ida_bytes.get_dword(class_hierarchy_descriptor + 12)

        for i in range(number_of_bases):
            based_class_descriptor = (_IMGBASE + ida_bytes.get_dword(array_of_bases + 4 * i)) if _IS64 \
                                     else ida_bytes.get_dword(array_of_bases + 4 * i)
            based_class_descriptor_type_descriptor = (_IMGBASE + ida_bytes.get_dword(based_class_descriptor)) if _IS64 \
                                                     else ida_bytes.get_dword(based_class_descriptor)

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
            base_type_descriptor = (_IMGBASE + ida_bytes.get_dword(base_class_descriptor)) if _IS64 \
                                   else ida_bytes.get_dword(base_class_descriptor)

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
    if _FILETYPE == ida_ida.f_PE:
        vtable_reference = ida_xref.get_first_dref_to(complete_object)
        while is_valid_address(vtable_reference):
            if _IS64:
                if not ida_bytes.is_off(ida_bytes.get_flags(vtable_reference + 8), 0):
                    vtable_reference = ida_xref.get_next_dref_to(complete_object, vtable_reference); continue
            else:
                if not ida_bytes.is_off(ida_bytes.get_flags(vtable_reference + 4), 0):
                    vtable_reference = ida_xref.get_next_dref_to(complete_object, vtable_reference); continue

            return vtable_reference + (8 if _IS64 else 4)

################################################################################
# Plugin
################################################################################

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
        global _FILETYPE, _IS64, _IMGBASE
        _FILETYPE = ida_ida.inf_get_filetype()
        _IS64     = ida_ida.inf_is_64bit()
        _IMGBASE  = ida_nalt.get_imagebase()

        if not ida_auto.auto_is_ok():
            print_message('INFO: The analysis is not finished!')
            return
        
        if not ida_hexrays.init_hexrays_plugin():
            print_message('ERROR: Failed to initialize hexrays plugin!\n')
            return

        if _FILETYPE not in (ida_ida.f_PE, ida_ida.f_ELF, ida_ida.f_MACHO):
            print_message('ERROR: This file type is not supported!\n')
            return

        trees = []
        class_vfuncs = {}

        if _FILETYPE in (ida_ida.f_ELF, ida_ida.f_MACHO):
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

        elif _FILETYPE == ida_ida.f_PE:
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

        idb_path = Path(ida_loader.get_path(ida_loader.PATH_TYPE_IDB))

        q = idb_path
        while q.suffix:
            q = q.with_suffix('')

        idb_path = q
       
        created_ts = datetime.now().astimezone().strftime('%Y-%m-%d %H:%M:%S')

        converter = DeclarationConverter()
        output_h = converter.convert(trees, class_vfuncs)
        output_h_path = idb_path.with_suffix('.h')
        header_h = '/*\n'
        header_h += f' * Generated by vdump [Version {VDUMP_VERSION}] ({created_ts})\n'
        header_h +=  ' */\n\n'
        with open(output_h_path, 'w', encoding='utf-8') as f:
            f.write(header_h + output_h)
        print_message(f'NOTE: C++ VTable declarations written to {output_h_path}')

        if DUMP_FOR_SOURCE_PYTHON:
            class PythonEmitter:
                def __init__(self, conv):
                    self.conv = conv
                    self.used_func_names = {}

                def _normalize_name(self, cls, offset, base, idx):
                    bn = (base or '').strip()
                    if bn.startswith('~') or '::~' in bn:
                        name = 'destructor'
                        key = (cls, offset, name)
                        self.used_func_names.setdefault(key, 0)
                        self.used_func_names[key] += 1
                        return name

                    name = (bn or '').strip()
                    if name.startswith('operator'):
                        name = f'operator_{idx:010}'
                    name = re.sub(r'[^0-9A-Za-z_]', '_', name)
                    name = re.sub(r'__+', '_', name).strip('_')
                    if not name:
                        name = f'Method_{idx:010}'

                    key = (cls, offset, name)
                    self.used_func_names.setdefault(key, 0)
                    self.used_func_names[key] += 1
                    if self.used_func_names[key] > 1:
                        name = f'{name}_{self.used_func_names[key]}'
                    return name

                def _is_pure_or_destructor(self, demangled):
                    d = _sanitize_demangled(demangled)
                    if d.startswith('~') or '::~' in d or 'destructor' in d:
                        return 'destructor'
                    if d.startswith('___cxa_pure_virtual') or d.startswith('__purecall'):
                        return 'pure'
                    return None

                def generate(self, class_vfuncs):
                    lines = []
                    lines.append('from memory import DataType, Convention')
                    lines.append('from memory.manager import manager, CustomType')
                    lines.append('')
                    lines.append('')

                    indegree = dict(self.conv.in_degree)
                    queue = collections.deque([cls for cls, deg in indegree.items() if deg == 0])
                    sorted_classes = []
                    while queue:
                        cls = queue.popleft()
                        sorted_classes.append(cls)
                        for derived in self.conv.reverse_graph.get(cls, []):
                            indegree[derived] -= 1
                            if indegree[derived] == 0:
                                queue.append(derived)

                    for cls in sorted_classes:
                        if cls not in class_vfuncs:
                            continue

                        other_counts = self.conv._collect_key_counts_from_nonzero_offsets(cls)

                        offsets_sorted = sorted(class_vfuncs[cls].items(), key=lambda kv: kv[0])

                        for offset, vfuncs in offsets_sorted:
                            py_cls_name = f'{cls}_{offset:08X}'
                            lines.append(f'class {py_cls_name}(CustomType, metaclass=manager):')

                            filtered = self.conv._enumerate_vfuncs_filtered(cls, offset, vfuncs, other_counts.copy())
                            if not filtered:
                                lines.append('    pass')
                                lines.append('')
                                continue

                            for logical_idx, phys_idx, func_ea, demangled in filtered:
                                if not demangled:
                                    continue

                                special = self._is_pure_or_destructor(demangled)
                                if special == 'destructor':
                                    lines.append(
                                        f'    destructor = manager.virtual_function({logical_idx}, [], DataType.VOID, Convention.THISCALL)'
                                    )
                                    continue
                                if special == 'pure':
                                    lines.append(
                                        f'    PureStub_{logical_idx:010} = manager.virtual_function({logical_idx}, [], DataType.VOID, Convention.THISCALL)'
                                    )
                                    continue

                                sig = SIGCACHE.get(func_ea, demangled)
                                base = sig["base"]
                                method_name = self._normalize_name(cls, offset, base, logical_idx)

                                ret_dt = 'DataType.VOID'
                                tinfo = None
                                try:
                                    decomp = ida_hexrays.decompile(func_ea)
                                except Exception:
                                    decomp = None
                                if decomp:
                                    tinfo = decomp.type
                                else:
                                    f = ida_funcs.get_func(func_ea)
                                    if f and f.prototype:
                                        tinfo = f.prototype

                                def _dt_from_tinfo_arg(a):
                                    try:
                                        if a.is_ref():
                                            b = ida_typeinf.tinfo_t(a); b.remove_ref(); a = b
                                        if a.is_array() or a.is_ptr():
                                            try:
                                                if a.is_ptr():
                                                    pt = a.get_pointed_object()
                                                    if pt and (pt.is_char() or pt.is_decl_char() or pt.is_uchar() or pt.is_decl_uchar()):
                                                        return 'DataType.STRING'
                                            except Exception:
                                                pass
                                            return 'DataType.POINTER'
                                        if a.is_void() or a.is_decl_void(): return 'DataType.VOID'
                                        if a.is_bool() or a.is_decl_bool(): return 'DataType.BOOL'
                                        if a.is_float() or a.is_decl_float(): return 'DataType.FLOAT'
                                        if a.is_double() or a.is_decl_double(): return 'DataType.DOUBLE'
                                        if a.is_integral() or a.is_arithmetic():
                                            sz = a.get_size()
                                            sign = a.is_signed() or (not a.is_unsigned() and not a.is_decl_uint())
                                            if sz == 1: return 'DataType.CHAR' if sign else 'DataType.UCHAR'
                                            if sz == 2: return 'DataType.SHORT' if sign else 'DataType.USHORT'
                                            if sz == 4: return 'DataType.INT' if sign else 'DataType.UINT'
                                            if sz == 8: return 'DataType.LONG_LONG' if sign else 'DataType.ULONG_LONG'
                                            return 'DataType.POINTER'
                                    except Exception:
                                        return 'DataType.POINTER'
                                    return 'DataType.POINTER'

                                arg_dts = []
                                if tinfo and tinfo.is_func():
                                    try:
                                        r = tinfo.get_rettype()
                                        if r: ret_dt = _dt_from_tinfo_arg(r)
                                    except Exception:
                                        ret_dt = 'DataType.VOID'
                                    try:
                                        for i in range(1, tinfo.get_nargs()):
                                            arg_dts.append(_dt_from_tinfo_arg(tinfo.get_nth_arg(i)))
                                    except Exception:
                                        arg_dts = []
                                else:
                                    arg_dts = ['DataType.POINTER' for _ in sig['args']]

                                args_repr = ', '.join(arg_dts)
                                lines.append(
                                    f'    {method_name} = manager.virtual_function({logical_idx}, [{args_repr}], {ret_dt}, Convention.THISCALL)'
                                )

                            lines.append('')

                        self.used_func_names = {}

                        for offset, vfuncs in offsets_sorted:
                            filtered = self.conv._enumerate_vfuncs_filtered(cls, offset, vfuncs, other_counts.copy())
                            full_list = [(i, i, ea, dem) for i, (ea, dem) in enumerate(vfuncs)]
                            need_full = self.conv._need_full_class(filtered, full_list)
                            if not need_full:
                                continue

                            py_cls_name_full = f'{cls}_Full_{offset:08X}'
                            lines.append(f'class {py_cls_name_full}(CustomType, metaclass=manager):')

                            if not full_list:
                                lines.append('    pass')
                                lines.append('')
                                continue

                            for logical_idx, phys_idx, func_ea, demangled in full_list:
                                if not demangled:
                                    continue

                                special = self._is_pure_or_destructor(demangled)
                                if special == 'destructor':
                                    lines.append(
                                        f'    destructor = manager.virtual_function({logical_idx}, [], DataType.VOID, Convention.THISCALL)'
                                    )
                                    continue
                                if special == 'pure':
                                    lines.append(
                                        f'    PureStub_{logical_idx:010} = manager.virtual_function({logical_idx}, [], DataType.VOID, Convention.THISCALL)'
                                    )
                                    continue

                                sig = SIGCACHE.get(func_ea, demangled)
                                base = sig['base']
                                method_name = self._normalize_name(cls, offset, base, logical_idx)

                                ret_dt = 'DataType.VOID'
                                tinfo = None
                                try:
                                    decomp = ida_hexrays.decompile(func_ea)
                                except Exception:
                                    decomp = None
                                if decomp:
                                    tinfo = decomp.type
                                else:
                                    f = ida_funcs.get_func(func_ea)
                                    if f and f.prototype:
                                        tinfo = f.prototype

                                def _dt_from_tinfo_arg(a):
                                    try:
                                        if a.is_ref():
                                            b = ida_typeinf.tinfo_t(a); b.remove_ref(); a = b
                                        if a.is_array() or a.is_ptr():
                                            try:
                                                if a.is_ptr():
                                                    pt = a.get_pointed_object()
                                                    if pt and (pt.is_char() or pt.is_decl_char() or pt.is_uchar() or pt.is_decl_uchar()):
                                                        return 'DataType.STRING'
                                            except Exception:
                                                pass
                                            return 'DataType.POINTER'
                                        if a.is_void() or a.is_decl_void(): return 'DataType.VOID'
                                        if a.is_bool() or a.is_decl_bool(): return 'DataType.BOOL'
                                        if a.is_float() or a.is_decl_float(): return 'DataType.FLOAT'
                                        if a.is_double() or a.is_decl_double(): return 'DataType.DOUBLE'
                                        if a.is_integral() or a.is_arithmetic():
                                            sz = a.get_size()
                                            sign = a.is_signed() or (not a.is_unsigned() and not a.is_decl_uint())
                                            if sz == 1: return 'DataType.CHAR' if sign else 'DataType.UCHAR'
                                            if sz == 2: return 'DataType.SHORT' if sign else 'DataType.USHORT'
                                            if sz == 4: return 'DataType.INT' if sign else 'DataType.UINT'
                                            if sz == 8: return 'DataType.LONG_LONG' if sign else 'DataType.ULONG_LONG'
                                            return 'DataType.POINTER'
                                    except Exception:
                                        return 'DataType.POINTER'
                                    return 'DataType.POINTER'

                                arg_dts = []
                                if tinfo and tinfo.is_func():
                                    try:
                                        r = tinfo.get_rettype()
                                        if r: ret_dt = _dt_from_tinfo_arg(r)
                                    except Exception:
                                        ret_dt = 'DataType.VOID'
                                    try:
                                        for i in range(1, tinfo.get_nargs()):
                                            arg_dts.append(_dt_from_tinfo_arg(tinfo.get_nth_arg(i)))
                                    except Exception:
                                        arg_dts = []
                                else:
                                    arg_dts = ['DataType.POINTER' for _ in sig['args']]

                                args_repr = ', '.join(arg_dts)
                                lines.append(
                                    f'    {method_name} = manager.virtual_function({logical_idx}, [{args_repr}], {ret_dt}, Convention.THISCALL)'
                                )

                            lines.append('')

                        self.used_func_names = {}

                    return '\n'.join(lines)

            py_emitter = PythonEmitter(converter)
            output_py = py_emitter.generate(class_vfuncs)
            output_py_path = idb_path.with_suffix('.py')
            header_py = '#\n'
            header_py += f'# Generated by vdump [Version {VDUMP_VERSION}] ({created_ts})\n'
            header_py += '#\n\n'
            with open(output_py_path, 'w', encoding='utf-8') as f:
                f.write(header_py + output_py)
            print_message(f'NOTE: Python DSL dumped to {output_py_path}')

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
