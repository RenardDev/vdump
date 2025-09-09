
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
    '''
    Represents a (possibly) qualified type with optional template args,
    modifiers, nested ::, etc.
    '''
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
        new_ta = []
        for a in self.template_args:
            a2 = a.apply_rules(rules)
            if a2 is not None:
                new_ta.append(a2)
        self.template_args = new_ta

        new_tuple = []
        for p in self.tuple_args:
            p2 = p.apply_rules(rules)
            if p2 is not None:
                new_tuple.append(p2)
        self.tuple_args = new_tuple

        new_nested = []
        for nt in self.nested_types:
            nt2 = nt.apply_rules(rules)
            if nt2 is not None:
                new_nested.append(nt2)
        self.nested_types = new_nested

    def __str__(self, indent=0):
        lines = []
        curr = indent

        # Show namespaces
        for ns in self.namespaces:
            lines.append(' ' * curr + f'namespace: {ns}')
            curr += 4

        # Show main typename with modifiers
        if self.leading_mods or self.typename:
            if any(mod in {'class', 'struct', 'enum'} for mod in self.leading_mods):
                # Extract the modifier
                mods = ' '.join(self.leading_mods) if self.leading_mods else ''
                if self.typename:
                    lines.append(' ' * curr + f'{mods}: {self.typename}')
            else:
                if self.leading_mods:
                    lines.append(' ' * curr + f'leading_mods: {', '.join(self.leading_mods)}')
                    curr += 4
                if self.typename:
                    lines.append(' ' * curr + f'type: {self.typename}')

        # Template args
        if self.template_args:
            lines.append(' ' * (curr + 4) + 'template arguments:')
            for arg in self.template_args:
                lines.append(arg.__str__(curr + 8))

        # Trailing mods
        if self.trailing_mods:
            lines.append(' ' * (curr + 4) + f'trailing_mods: {', '.join(self.trailing_mods)}')

        # Tuple args (like function param style)
        if self.tuple_args:
            lines.append(' ' * (curr + 4) + 'tuple arguments:')
            for p in self.tuple_args:
                lines.append(p.__str__(curr + 8))

        # Special suffix
        if self.special_suffix:
            lines.append(' ' * (curr + 4) + f'suffix: {self.special_suffix}')

        if self.has_typename_prefix:
            lines.append(' ' * (curr + 4) + 'has_typename_prefix: True')
        if self.has_template_keyword:
            lines.append(' ' * (curr + 4) + 'has_template_keyword: True')

        # Nested types
        for nt in self.nested_types:
            lines.append(nt.__str__(curr + 4))

        return '\n'.join(lines)

class FunctionPointerNode(BaseNode):
    '''
    Represents a function pointer type with return type, calling convention,
    trailing modifiers, and parameters.
    '''
    def __init__(self, return_type=None, calling_convention=None, parameters=None, trailing_mods=None):
        super().__init__()
        self.return_type = return_type
        self.calling_convention = calling_convention
        self.parameters = parameters or []
        self.trailing_mods = trailing_mods or []

    def _apply_rules_to_children(self, rules):
        if self.return_type:
            self.return_type = self.return_type.apply_rules(rules)
        new_params = []
        for p in self.parameters:
            p2 = p.apply_rules(rules)
            if p2 is not None:
                new_params.append(p2)
        self.parameters = new_params

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
            lines.append(' ' * (indent + 4) + f'trailing_mods: {', '.join(self.trailing_mods)}')
        return '\n'.join(lines)

class ValueNode(BaseNode):
    '''Represents a numeric literal (e.g. 42).'''
    def __init__(self, value):
        super().__init__()
        self.value = value

    def __str__(self, indent=0):
        return f'{' ' * indent}value: {self.value}'

class EllipsisNode(BaseNode):
    '''Represents the ellipsis '...' used as a placeholder in template args.'''
    def __init__(self):
        super().__init__()

    def __str__(self, indent=0):
        return ' ' * indent + '...'

class ParameterNode(BaseNode):
    '''
    A function or constructor parameter, like (int x) or (0).
    '''
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

        new_ft = []
        for t in self.func_template_args:
            t2 = t.apply_rules(rules)
            if t2 is not None:
                new_ft.append(t2)
        self.func_template_args = new_ft

        new_params = []
        for p in self.parameters:
            p2 = p.apply_rules(rules)
            if p2 is not None:
                new_params.append(p2)
        self.parameters = new_params

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
    '''
    Convert an AST node back to a synthetic code-like string, with semicolon if top_level.
    '''

    if node is None:
        return ''

    # 1. FunctionPointerNode
    if isinstance(node, FunctionPointerNode):
        parts = []
        if node.return_type:
            parts.append(to_code(node.return_type, top_level=False))
        if node.calling_convention:
            parts.append(node.calling_convention)
        # Enclose calling convention and '*' in parentheses
        if node.calling_convention:
            fp_str = f'{parts[0]}({parts[1]}*)'
        else:
            fp_str = f'{parts[0]}(*)'
        params = ', '.join(to_code(p, top_level=False) for p in node.parameters)
        fp_str += f'({params})'
        # Append trailing mods if any
        if node.trailing_mods:
            fp_str += ''.join(node.trailing_mods)
        return fp_str

    # 2. Numeric literal
    if isinstance(node, ValueNode):
        return str(node.value)

    # 3. Ellipsis
    if isinstance(node, EllipsisNode):
        return '...'

    # 4. Parameter
    if isinstance(node, ParameterNode):
        if node.value_node:
            return to_code(node.value_node, top_level=False)
        param_type = to_code(node.type_node, top_level=False)
        return f'{param_type} {node.param_name}' if node.param_name else param_type

    # 5. TypeNode
    if isinstance(node, TypeNode):
        parts = []

        # Leading mods (merge pointers/references)
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

        # 'typename' prefix
        if node.has_typename_prefix:
            if leading_part:
                parts.append(f'typename {leading_part}')
            else:
                parts.append('typename')
        else:
            if leading_part:
                parts.append(leading_part)

        # namespaces
        ns_part = '::'.join(node.namespaces)
        if ns_part:
            if parts:
                if parts[-1]:
                    parts[-1] += ' ' + ns_part + '::'
                else:
                    parts.append(ns_part + '::')
            else:
                parts.append(ns_part + '::')

        # base typename
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

        # <template args>
        if node.template_args:
            inside_args = [to_code(a, top_level=False) for a in node.template_args]
            # join with commas
            parts[-1] += '<' + ', '.join(inside_args) + '>'

        # (tuple args)
        if node.tuple_args:
            inside_pars = ', '.join(to_code(p, top_level=False) for p in node.tuple_args)
            parts[-1] += '(' + inside_pars + ')'

        # trailing mods
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

        # special suffix
        if node.special_suffix:
            if parts:
                parts[-1] += '::' + node.special_suffix
            else:
                parts.append('::' + node.special_suffix)

        base_str = ''.join(parts).strip()

        # Nested types
        for nt in node.nested_types:
            nt_str = to_code(nt, top_level=False)
            base_str += f'::{nt_str}'

        if top_level:
            base_str += ';'
        return base_str

    # 6. VariableNode
    if isinstance(node, VariableNode):
        t = to_code(node.type_node, top_level=False)
        v = node.var_name or ''
        out = f'{t} {v}'.strip()
        if top_level:
            out += ';'
        return out

    # 7. FunctionNode
    if isinstance(node, FunctionNode):
        rt = to_code(node.return_type, top_level=False)
        fn = node.func_name or ''
        tmpl = ''
        if node.func_template_args:
            inside = ', '.join(to_code(a, top_level=False) for a in node.func_template_args)
            tmpl = f'<{inside}>'
        if node.parameters:
            inside_params = ', '.join(to_code(p, top_level=False) for p in node.parameters)
            param_part = f'({inside_params})'
        else:
            param_part = '()'
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
    # Match words, numbers, &&, ellipsis, etc.
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

def _tokens_to_spelling(tokens):
    parts = []
    prev_kind = None
    prev_val = None
    for kind, val in tokens:
        need_space = False
        if parts:
            # space between two WORDs / NUMBERs
            if (prev_kind in ('WORD', 'NUMBER') and kind in ('WORD', 'NUMBER')):
                need_space = True
            # space before * & && if previous wasn't a symbol starting a scope
            if kind == 'SYMBOL' and val in ('*', '&', '&&') and (prev_val not in ('::',)):
                need_space = True
            # space after > when next is WORD (templates)
            if prev_val == '>' and kind in ('WORD', 'NUMBER'):
                need_space = True
            # collapse spaces around ::, <, >
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
    """
    Parse [scope::]* operator <operator-id or conversion-type-id> ( param-list )
    Returns FunctionNode or None.
    """
    save = ts.pos

    # swallow optional scope qualifiers: A::B:: ...
    while True:
        t1 = ts.peek()
        t2 = ts.peek(1)
        if t1 and t2 and t1[0] == 'WORD' and t2 == ('SYMBOL', '::'):
            ts.next(); ts.next()
        else:
            break

    # operator keyword
    if not (ts.peek() and ts.peek()[0] == 'WORD' and ts.peek()[1] == 'operator'):
        ts.pos = save
        return None
    ts.next()  # consume 'operator'

    # Collect operator-id / conversion-type-id tokens up to the parameter '('
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

    # Now parameter list
    ts.expect('SYMBOL', '(')
    params = parse_tuple_args(ts)
    ts.expect('SYMBOL', ')')

    func_name = 'operator ' + _tokens_to_spelling(name_tokens).strip()
    return FunctionNode(return_type=None, func_name=func_name, func_template_args=[], parameters=params)

def parse_declaration(ts):
    '''
    Parses a top-level declaration. If we only get a TypeNode, we return it
    (bare type). If we see a name, we parse as a variable, function, or function call.
    This revised version does not try to “optimize away” a parenthesized argument list,
    so that the reconstructed code exactly matches the input.
    '''
    opfn = parse_operator_function(ts)
    if opfn:
        ts.consume_if('SYMBOL', ';')
        return opfn

    # First, parse a type with possible nesting.
    rtype = parse_type_with_nesting(ts)
    if not rtype:
        return None

    nxt = ts.peek()
    if not nxt or nxt == ('SYMBOL', ';'):
        ts.consume_if('SYMBOL', ';')
        return rtype

    # If the next token is a word, then treat it as an explicit variable or function name.
    if nxt[0] == 'WORD':
        name_ = nxt[1]
        ts.next()  # consume the variable/function name

        # Check for any function template arguments
        func_tmpl = []
        if ts.consume_if('SYMBOL', '<'):
            func_tmpl = parse_template_args(ts)

        # If a '(' follows, this is a function declaration.
        if ts.consume_if('SYMBOL', '('):
            params = parse_tuple_args(ts)
            ts.expect('SYMBOL', ')')
            ts.consume_if('SYMBOL', ';')
            return FunctionNode(rtype, name_, func_tmpl, params)
        else:
            ts.consume_if('SYMBOL', ';')
            return VariableNode(rtype, name_)

    # Otherwise, if a '(' follows the type, treat it as part of the type (a tuple of arguments)
    # and preserve them exactly.
    if ts.consume_if('SYMBOL', '('):
        params = parse_tuple_args(ts)
        ts.expect('SYMBOL', ')')
        ts.consume_if('SYMBOL', ';')
        rtype.tuple_args = params  # ALWAYS preserve the parsed tuple arguments
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

    # Maybe 'typename X::template Y<...>::type'
    special_typename_node = parse_typename_dependent_expr(ts, leading_mods)
    if special_typename_node:
        trailing_mods = parse_modifiers(ts)
        special_typename_node.trailing_mods.extend(trailing_mods)
        return special_typename_node

    # Gather possible namespaces + final word
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
        # fallback
        ts.pos = start
        return None

    # check if template <...>
    targs = []
    if typename and ts.consume_if('SYMBOL', '<'):
        targs = parse_template_args(ts)

    # function pointer attempt?
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
    Parses expressions like 'typename A::template B<...>::type' or 'typename A::template B<...>::size'.
    Returns a TypeNode if matched, else None.
    '''
    start_pos = ts.pos
    has_typename = False

    # Check if 'typename' is already in modifiers.
    if 'typename' in already_collected_mods:
        new_mods = [m for m in already_collected_mods if m != 'typename']
        already_collected_mods[:] = new_mods
        has_typename = True
    else:
        # Or check next token.
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
            ts.next()  # consume 'template'
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
    ts.next()  # consume the suffix token

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

        # Check if 'nxt' is a modifier
        if nxt[1] in {'class', 'struct', 'enum'}:
            # Consume the modifier
            mod = ts.next()[1]
            # Now expect the type name
            type_nxt = ts.peek()
            if not type_nxt or type_nxt[0] != 'WORD':
                raise ParserError(f'Expected type name after modifier \'{mod}\'')
            typename = ts.next()[1]

            # Check for template args
            if ts.consume_if('SYMBOL', '<'):
                targs = parse_template_args(ts)
            else:
                targs = []

            # Check for tuple args
            if ts.consume_if('SYMBOL', '('):
                tuple_pars = parse_tuple_args(ts)
                ts.expect('SYMBOL', ')')
            else:
                tuple_pars = []

            # Parse trailing modifiers
            mods = parse_modifiers(ts)

            # Create TypeNode with leading_mods
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
            # It's a regular type name
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

# Add a helper that checks (without consuming tokens) if the tokens ahead match a function pointer.
def is_function_pointer(ts):
    pos = ts.pos
    if pos < len(ts.tokens) and ts.tokens[pos] == ('SYMBOL', '('):
        temp_pos = pos + 1
        # Optionally skip a calling convention token if present.
        if temp_pos < len(ts.tokens) and ts.tokens[temp_pos][0] == 'WORD' and ts.tokens[temp_pos][1] in {'__cdecl', '__stdcall', '__fastcall', '__vectorcall'}:
            temp_pos += 1
        # Next token must be '*' for a function pointer.
        if temp_pos < len(ts.tokens) and ts.tokens[temp_pos] == ('SYMBOL', '*'):
            return True
    return False

def parse_function_pointer(ts, namespaces, base_typename, targs, leading_mods):
    if not is_function_pointer(ts):
        return None

    ts.next()  # '('
    calling_convention = None
    if ts.peek() and ts.peek()[0] == 'WORD' and ts.peek()[1] in {'__cdecl', '__stdcall', '__fastcall', '__vectorcall'}:
        calling_convention = ts.next()[1]
    if not ts.consume_if('SYMBOL', '*'):
        return None
    if not ts.consume_if('SYMBOL', ')'):
        raise ParserError("Expected ')' after function pointer '*'.")
    if not ts.consume_if('SYMBOL', '('):
        raise ParserError("Expected '(' to start function pointer parameter list.")
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
    '''
    Reads template args between < and >, treating 'class', 'struct', 'enum' as modifiers.
    Commas are required to separate arguments.
    '''
    args = []
    while True:
        # stop if we see '>'
        nxt = ts.peek()
        if not nxt:
            raise ParserError('Unclosed <... in template args')
        if nxt == ('SYMBOL', '>'):
            ts.next()  # consume '>'
            break

        # parse a single argument
        arg = parse_one_template_argument(ts)
        if not arg:
            raise ParserError('Failed to parse template argument')
        args.append(arg)

        # If the next token is a comma, consume it and parse next arg
        ts.consume_if('SYMBOL', ',')

    return args

def parse_one_template_argument(ts):
    '''
    Parse exactly one template argument, which can be:
    - A type with possible leading modifiers
    - A function pointer
    - An ellipsis '...'
    - A numeric literal
    '''
    nxt = ts.peek()
    if not nxt:
        return None

    # 1) Ellipsis
    if nxt[0] == 'ELLIPSIS':
        ts.next()
        return EllipsisNode()

    # 2) Number
    if nxt[0] == 'NUMBER':
        val = int(nxt[1])
        ts.next()
        return ValueNode(val)

    # 3) Type with possible leading modifiers
    type_node = parse_type_with_nesting(ts)
    if type_node:
        return type_node

    return None

def parse_tuple_args(ts):
    '''
    Parses a list of arguments separated by commas within parentheses.
    '''
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
            # Possibly a param name
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
    '''
    Grabs recognized type modifiers or calling conventions:
      const, volatile, static, inline, __cdecl, __stdcall, &/&&/*, class, struct, enum
    '''
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
                '__cdecl', '__stdcall', '__fastcall', '__vectorcall',
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
# vdump
################################################################################

def function_pointer_to_void_pointer_rule(node):
    if isinstance(node, FunctionPointerNode):
        return TypeNode(
            typename='void',
            trailing_mods=['*']
        )
    return node

def extract_function_info(decl_str):
    if not decl_str.endswith(';'):
        decl_str += ';'

    parser = ASTParser()
    parser.add_rule(function_pointer_to_void_pointer_rule)
    try:
        ast_nodes = parser.parse(decl_str)
    except:
        return None

    for node in ast_nodes:
        # Function type (e.g., "Ret NS::Cls::f(T1, T2)")
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
            return (func_name, params)

        # Type with tuple args (e.g., "void(int, float)")
        if isinstance(node, TypeNode):
            params = []
            for p in node.tuple_args:
                s = to_code(p, top_level=False)
                if s == 'void' and len(node.tuple_args) == 1:
                    break
                elif s == 'void' and len(node.tuple_args) > 1:
                    s = 'void*'
                params.append(s)
            return (node.typename, params)

    return None

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
            if t.is_int16() or t.is_decl_int16(): return 'short'
            if t.is_int32() or t.is_decl_int32(): return 'int'
            if t.is_int64() or t.is_decl_int64(): return 'long long'
            if t.is_int128() or t.is_decl_int128(): return 'void*'
            if t.is_int() or t.is_decl_int():
                return 'int' if size != 1 else 'char'
            
            return {
                1: 'char',
                2: 'short',
                4: 'int',
                8: 'long long',
                16: 'void*'
            }.get(size, 'int')
        else:
            if t.is_uint16() or t.is_decl_uint16(): return 'unsigned short'
            if t.is_uint32() or t.is_decl_uint32(): return 'unsigned int'
            if t.is_uint64() or t.is_decl_uint64(): return 'unsigned long long'
            if t.is_uint128() or t.is_decl_uint128(): return 'void*'
            if t.is_uint() or t.is_decl_uint():
                return 'unsigned int' if size != 1 else 'unsigned char'
            
            return {
                1: 'unsigned char',
                2: 'unsigned short',
                4: 'unsigned int',
                8: 'unsigned long long',
                16: 'void*'
            }.get(size, 'unsigned int')
    
    if t.is_floating() or t.is_decl_floating():
        return {
            4: 'float',
            8: 'double',
            10: 'long double',
            16: 'long double'
        }.get(size, 'double')

    return 'void*'

def is_builtin_type(t):
    if t.is_ptr():
        t = ida_typeinf.remove_pointer(t)
        t.clr_decl_const_volatile()

    if not t.is_correct() or not t.is_well_defined():
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

    if t.is_void() or t.is_decl_void():
        return True
    if t.is_bool() or t.is_decl_bool():
        return True
    if t.is_char() or t.is_decl_char():
        return True
    if t.is_uchar() or t.is_decl_uchar():
        return True
    if t.is_float() or t.is_decl_float():
        return True
    if t.is_double() or t.is_decl_double():
        return True
    if t.is_ldouble():
        return True

    if t.is_integral() or t.is_arithmetic() or t.is_decl_arithmetic():
        if t.is_signed() or (not t.is_unsigned() and not t.is_decl_uint()):
            if t.is_int16() or t.is_decl_int16(): return True
            if t.is_int32() or t.is_decl_int32(): return True
            if t.is_int64() or t.is_decl_int64(): return True
            if t.is_int128() or t.is_decl_int128(): return True
            if t.is_int() or t.is_decl_int():
                return True
            
            return False
        else:
            if t.is_uint16() or t.is_decl_uint16(): return True
            if t.is_uint32() or t.is_decl_uint32(): return True
            if t.is_uint64() or t.is_decl_uint64(): return True
            if t.is_uint128() or t.is_decl_uint128(): return True
            if t.is_uint() or t.is_decl_uint():
                return True
            
            return False

    if t.is_floating() or t.is_decl_floating():
        return True

    return False

def extract_object_name(decl_str):
    if not decl_str.endswith(';'):
        decl_str += ';'

    parser = ASTParser()
    parser.add_rule(function_pointer_to_void_pointer_rule)
    try:
        ast_nodes = parser.parse(decl_str)
    except:
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

class DeclarationConverter:
    def __init__(self):
        self.reset_state()

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
            if cls in self.class_vfuncs:
                for offset in self.class_vfuncs[cls]:
                    offset_name = f'{cls}_{offset:08X}'
                    class_name_map[(cls, offset)] = offset_name

                    self.forward_decls.add(f'class {offset_name}; // OFFSET: {offset:08X}')
                    
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
                    
                    for idx, (func, demangled) in enumerate(self.class_vfuncs[cls][offset]):
                        if not demangled:
                            continue
    
                        demangled = demangled.replace('`non-virtual thunk to\'', '')

                        decl = self.process_static_function(idx, func, demangled, cls, offset)
                        #decl_lines.append(f'    // {idx:>10} - {demangled}')
                        decl_lines.append(f'    {decl}\n')

                    for idx, (func, demangled) in enumerate(self.class_vfuncs[cls][offset]):
                        if not demangled:
                            continue
    
                        demangled = demangled.replace('`non-virtual thunk to\'', '')

                        decl = self.process_get_function(idx, func, demangled, cls, offset)
                        #decl_lines.append(f'    // {idx:>10} - {demangled}')
                        decl_lines.append(f'    {decl}\n')
                    
                    decl_lines.extend([
                        '};'
                    ])
                    
                    class_declarations.append('\n'.join(decl_lines))
        
        for cls in self.declare:
            if cls not in sorted_classes:
                self.forward_decls.add(f'class {cls} {{}};')
        
        return '\n' + \
               '\n'.join(sorted(self.forward_decls)) + \
               '\n\n' + \
               '\n\n'.join(class_declarations)

    def _normalize_operator_name(self, base_name: str, idx: int) -> str:
        name = base_name.strip()
        if name.startswith('operator'):
            return f'operator_{idx:010}'
        return name

    def process_function(self, idx, func, demangled, cls, offset):

        if demangled[:19] == '___cxa_pure_virtual' or demangled[:10] == '__purecall':
            return f'virtual void PureStub_{idx:010}() = 0;'

        if demangled.startswith('~') or 'destructor' in demangled or '~' in demangled:
            return f'virtual ~{cls}_{offset:08X}() = 0;'

        if '?' in demangled or '@' in demangled or '$' in demangled:
            return f'virtual void InvalidStub_{idx:010}() = 0;'

        type = None

        try:
            decompiled = ida_hexrays.decompile(func)
        except Exception:
            decompiled = None
        if decompiled:
            type = decompiled.type
            ret_type = type.get_rettype()
            ret_type.clr_decl_const_volatile()
            ret_str = self.simplify_type(ret_type)
        else:
            if f := ida_funcs.get_func(func):
                type = f.prototype
            ret_str = 'void'

        if not type:
            return f'virtual void InvalidStub_{idx:010}() = 0;'

        decompiled_args = []
        for i in range(1, type.get_nargs()):
            arg = type.get_nth_arg(i)
            arg.clr_decl_const_volatile()
            arg_str = self.simplify_type(arg)
            if arg_str == 'void' and i <= 2:
                arg_str = 'void*'
            decompiled_args.append(arg_str)

        args = decompiled_args

        func_info = extract_function_info(demangled)
        if func_info:
            demangled_args = []
            func_name, dargs = func_info
            func_name = self._normalize_operator_name(func_name, idx)
            for i, arg in enumerate(dargs):
                arg = self.parse_type(arg)
                arg_str = 'void*'
                if arg and is_builtin_type(arg):
                    arg_str = dargs[i]
                demangled_args.append(arg_str)
            args = demangled_args
        else:
            func_name = demangled.split('(')[0].split('::')[-1]
            func_name = self._normalize_operator_name(func_name, idx)

        if ida_bytes.has_dummy_name(ida_bytes.get_flags(func)):
            return f'virtual void Stub_{idx:010}({', '.join(args)}) = 0;'

        if demangled[:8] == 'nullsub_':
            return f'virtual void NullStub_{idx:010}({', '.join(args)}) = 0;'

        self.used_func_names.setdefault((cls, offset), {}).setdefault(func_name, 0)
        self.used_func_names[(cls, offset)][func_name] += 1
        count = self.used_func_names[(cls, offset)][func_name]
        final_name = f'{func_name}_{count}' if count > 1 else func_name

        return f'virtual {ret_str} {final_name}({', '.join(args)}) = 0;'

    def process_static_function(self, idx, func, demangled, cls, offset):

        if demangled[:19] == '___cxa_pure_virtual' or demangled[:10] == '__purecall':
            return f'static void static_PureStub_{idx:010}(void* pThis) {{ void** pVTable = *reinterpret_cast<void***>(reinterpret_cast<char*>(pThis) + {offset:#x}); reinterpret_cast<void(__thiscall*)(void*)>(pVTable[{idx}])(pThis); }};'

        if demangled.startswith('~') or 'destructor' in demangled or '~' in demangled:
            return f'static void static_destructor_{cls}_{offset:08X}(void* pThis) {{ void** pVTable = *reinterpret_cast<void***>(reinterpret_cast<char*>(pThis) + {offset:#x}); reinterpret_cast<void(__thiscall*)(void*)>(pVTable[{idx}])(pThis); }};'

        if '?' in demangled or '@' in demangled or '$' in demangled:
            return f'static void static_InvalidStub_{idx:010}(void* pThis) {{ void** pVTable = *reinterpret_cast<void***>(reinterpret_cast<char*>(pThis) + {offset:#x}); reinterpret_cast<void(__thiscall*)(void*)>(pVTable[{idx}])(pThis); }};'

        type = None

        try:
            decompiled = ida_hexrays.decompile(func)
        except Exception:
            decompiled = None
        if decompiled:
            type = decompiled.type
            ret_type = type.get_rettype()
            ret_type.clr_decl_const_volatile()
            ret_str = self.simplify_type(ret_type)
        else:
            if f := ida_funcs.get_func(func):
                type = f.prototype
            ret_str = 'void'

        if not type:
            return f'static void static_InvalidStub_{idx:010}(void* pThis) {{ void** pVTable = *reinterpret_cast<void***>(reinterpret_cast<char*>(pThis) + {offset:#x}); reinterpret_cast<void(__thiscall*)(void*)>(pVTable[{idx}])(pThis); }};'

        decompiled_args = []
        for i in range(1, type.get_nargs()):
            arg = type.get_nth_arg(i)
            arg.clr_decl_const_volatile()
            arg_str = self.simplify_type(arg)
            if arg_str == 'void' and i <= 2:
                arg_str = 'void*'
            decompiled_args.append(arg_str)

        args = decompiled_args

        func_info = extract_function_info(demangled)
        if func_info:
            demangled_args = []
            func_name, dargs = func_info
            func_name = self._normalize_operator_name(func_name, idx)
            func_name = 'static_' + func_name
            for i, arg in enumerate(dargs):
                arg = self.parse_type(arg)
                arg_str = 'void*'
                if arg and is_builtin_type(arg):
                    arg_str = dargs[i]
                demangled_args.append(arg_str)
            args = demangled_args
        else:
            func_name = demangled.split('(')[0].split('::')[-1]
            func_name = self._normalize_operator_name(func_name, idx)
            func_name = 'static_' + func_name

        if ida_bytes.has_dummy_name(ida_bytes.get_flags(func)):
            if args:
                nargs = []
                naargs = []
                for i, arg in enumerate(args, start=1):
                    nargs.append(arg + f' a{i}')
                for i, arg in enumerate(args, start=1):
                    naargs.append(f'a{i}')
                return f'static void static_Stub_{idx:010}(void* pThis, {', '.join(nargs)}) {{ void** pVTable = *reinterpret_cast<void***>(reinterpret_cast<char*>(pThis) + {offset:#x}); reinterpret_cast<void(__thiscall*)(void*, {', '.join(args)})>(pVTable[{idx}])(pThis, {', '.join(naargs)}); }};'
            else:
                return f'static void static_Stub_{idx:010}(void* pThis) {{ void** pVTable = *reinterpret_cast<void***>(reinterpret_cast<char*>(pThis) + {offset:#x}); reinterpret_cast<void(__thiscall*)(void*)>(pVTable[{idx}])(pThis); }};'

        if demangled[:8] == 'nullsub_':
            if args:
                nargs = []
                naargs = []
                for i, arg in enumerate(args, start=1):
                    nargs.append(arg + f' a{i}')
                for i, arg in enumerate(args, start=1):
                    naargs.append(f'a{i}')
                return f'static void static_NullStub_{idx:010}(void* pThis, {', '.join(nargs)}) {{ void** pVTable = *reinterpret_cast<void***>(reinterpret_cast<char*>(pThis) + {offset:#x}); reinterpret_cast<void(__thiscall*)(void*, {', '.join(args)})>(pVTable[{idx}])(pThis, {', '.join(naargs)}); }};'
            else:
                return f'static void static_NullStub_{idx:010}(void* pThis) {{ void** pVTable = *reinterpret_cast<void***>(reinterpret_cast<char*>(pThis) + {offset:#x}); reinterpret_cast<void(__thiscall*)(void*)>(pVTable[{idx}])(pThis); }};'

        self.used_func_names.setdefault((cls, offset), {}).setdefault(func_name, 0)
        self.used_func_names[(cls, offset)][func_name] += 1
        count = self.used_func_names[(cls, offset)][func_name]
        final_name = f'{func_name}_{count}' if count > 1 else func_name

        if args:
            nargs = []
            naargs = []
            for i, arg in enumerate(args, start=1):
                nargs.append(arg + f' a{i}')
            for i, arg in enumerate(args, start=1):
                naargs.append(f'a{i}')
            return f'static {ret_str} {final_name}(void* pThis, {', '.join(nargs)}) {{ void** pVTable = *reinterpret_cast<void***>(reinterpret_cast<char*>(pThis) + {offset:#x}); return reinterpret_cast<{ret_str}(__thiscall*)(void*, {', '.join(args)})>(pVTable[{idx}])(pThis, {', '.join(naargs)}); }};'
        else:
            return f'static {ret_str} {final_name}(void* pThis) {{ void** pVTable = *reinterpret_cast<void***>(reinterpret_cast<char*>(pThis) + {offset:#x}); return reinterpret_cast<{ret_str}(__thiscall*)(void*)>(pVTable[{idx}])(pThis); }};'

    def process_get_function(self, idx, func, demangled, cls, offset):

        if demangled[:19] == '___cxa_pure_virtual' or demangled[:10] == '__purecall':
            return f'static void* get_PureStub_{idx:010}(void* pThis) {{ void** pVTable = *reinterpret_cast<void***>(reinterpret_cast<char*>(pThis) + {offset:#x}); return pVTable[{idx}]; }};'

        if demangled.startswith('~') or 'destructor' in demangled or '~' in demangled:
            return f'static void* get_destructor_{cls}_{offset:08X}(void* pThis) {{ void** pVTable = *reinterpret_cast<void***>(reinterpret_cast<char*>(pThis) + {offset:#x}); return pVTable[{idx}]; }};'

        if '?' in demangled or '@' in demangled or '$' in demangled:
            return f'static void* get_InvalidStub_{idx:010}(void* pThis) {{ void** pVTable = *reinterpret_cast<void***>(reinterpret_cast<char*>(pThis) + {offset:#x}); return pVTable[{idx}]; }};'

        type = None

        try:
            decompiled = ida_hexrays.decompile(func)
        except Exception:
            decompiled = None
        if decompiled:
            type = decompiled.type
            ret_type = type.get_rettype()
            ret_type.clr_decl_const_volatile()
        else:
            if f := ida_funcs.get_func(func):
                type = f.prototype

        if not type:
            return f'static void* get_InvalidStub_{idx:010}(void* pThis) {{ void** pVTable = *reinterpret_cast<void***>(reinterpret_cast<char*>(pThis) + {offset:#x}); return pVTable[{idx}]; }};'

        func_info = extract_function_info(demangled)
        if func_info:
            func_name, _ = func_info
            func_name = self._normalize_operator_name(func_name, idx)
            func_name = 'get_' + func_name
        else:
            func_name = demangled.split('(')[0].split('::')[-1]
            func_name = self._normalize_operator_name(func_name, idx)
            func_name = 'get_' + func_name

        if ida_bytes.has_dummy_name(ida_bytes.get_flags(func)):
            return f'static void* get_Stub_{idx:010}(void* pThis) {{ void** pVTable = *reinterpret_cast<void***>(reinterpret_cast<char*>(pThis) + {offset:#x}); return pVTable[{idx}];}};'

        if demangled[:8] == 'nullsub_':
            return f'static void* get_NullStub_{idx:010}(void* pThis) {{ void** pVTable = *reinterpret_cast<void***>(reinterpret_cast<char*>(pThis) + {offset:#x}); return pVTable[{idx}]; }};'

        self.used_func_names.setdefault((cls, offset), {}).setdefault(func_name, 0)
        self.used_func_names[(cls, offset)][func_name] += 1
        count = self.used_func_names[(cls, offset)][func_name]
        final_name = f'{func_name}_{count}' if count > 1 else func_name

        return f'static void* {final_name}(void* pThis) {{ void** pVTable = *reinterpret_cast<void***>(reinterpret_cast<char*>(pThis) + {offset:#x}); return pVTable[{idx}]; }};'

    def parse_type(self, str):
        tif = ida_typeinf.tinfo_t()
        if ida_typeinf.parse_decl(tif, None, str, ida_typeinf.PT_SIL | ida_typeinf.PT_TYP | ida_typeinf.PT_SEMICOLON) is None:
            return None
        if tif.is_ptr():
            t = tif
            lt = tif
            while t and t.is_ptr():
                lt = t
                t = t.get_pointed_object()
            tif = lt
        return tif

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
        idb_path = Path(ida_loader.get_path(ida_loader.PATH_TYPE_IDB))
        output_path = idb_path.with_suffix('.h')
        with open(output_path, 'w', encoding='utf-8') as f:
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
