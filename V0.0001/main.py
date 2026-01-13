from sly import Lexer
from sly import Parser
import struct
from Helper import Assembler
from Helper import Builtins
class BasicLexer(Lexer):
    tokens = { PRINTF, PRINT,COMMAND,REG,NAME, NUMBER, STRING, IF, THEN, ELSE, FOR, FUN, TO, ARROW, EQEQ }
    ignore = '\t '

    literals = { '=', '+', '-', '/', '*', '(', ')', ',', ';' , "{","}"}

    # Define tokens
    # Regex to find instructions and registers based on your symbols
    COMMAND = r"@(\w+)"  # Matches @mov, @push, etc.
    PRINTF = r"printf"
    PRINT = r"print"

    REG= r"\$([a-zA-Z0-9]+)"  # Matches $rax, $eax, $r15
    IF = r'if'
    THEN = r'then'
    ELSE = r'else'
    FOR = r'for'
    FUN = r'fun'
    TO = r'to'
    ARROW = r'->'
    NAME = r'[a-zA-Z_][a-zA-Z0-9_]*'
    STRING = r'\".*?\"'

    EQEQ = r'=='

    @_(r'\d+')
    def NUMBER(self, t):
        t.value = int(t.value)
        return t

    @_(r'#.*')
    def COMMENT(self, t):
        pass

    @_(r'\n+')
    def newline(self,t ):
        self.lineno = t.value.count('\n')

class BasicParser(Parser):
    tokens = BasicLexer.tokens

    precedence = (
        ('left', '+', '-'),
        ('left', '*', '/'),
        ('right', 'UMINUS'),
        )

    def __init__(self):
        self.env = { }

    @_("'{' procs '}'")
    def statement(self,p):
        return p.procs

    @_("procs ';' proc")
    def procs(self, p):
        return p.procs + [p.proc]

    @_("proc")
    def procs(self,p):
        return [p.proc]

    @_("statement")
    def proc(self,p):
        return p.statement
    @_('')
    def statement(self, p):
        pass


    @_("COMMAND REG ',' expr")
    def statement(self, p):
        if p[0][1:].lower() == "mov":
            return ("mov_imm", p.REG[1:], p.expr)


        return



    @_('FOR var_assign TO expr THEN statement')
    def statement(self, p):
        return ('for_loop', ('for_loop_setup', p.var_assign, p.expr), p.statement)

    @_('IF condition THEN statement ELSE statement')
    def statement(self, p):
        return ('if_stmt', p.condition, ('branch', p.statement0, p.statement1))

    @_('FUN NAME "(" ")" ARROW statement')
    def statement(self, p):
        return ('fun_def', p.NAME, p.statement)

    @_('NAME "(" ")"')
    def statement(self, p):
        return ('fun_call', p.NAME)

    @_('expr EQEQ expr')
    def condition(self, p):
        return ('condition_eqeq', p.expr0, p.expr1)

    @_('var_assign')
    def statement(self, p):
        return p.var_assign

    @_('NAME "=" expr')
    def var_assign(self, p):
        return ('var_assign', p.NAME, p.expr)

    @_('NAME "=" STRING')
    def var_assign(self, p):
        return ('var_assign', p.NAME, p.STRING)

    @_('expr')
    def statement(self, p):
        return (p.expr)

    @_('expr "+" expr')
    def expr(self, p):
        return ('add', p.expr0, p.expr1)

    @_('expr "-" expr')
    def expr(self, p):
        return ('sub', p.expr0, p.expr1)

    @_('expr "*" expr')
    def expr(self, p):
        return ('mul', p.expr0, p.expr1)

    @_('expr "/" expr')
    def expr(self, p):
        return ('div', p.expr0, p.expr1)

    @_('"-" expr %prec UMINUS')
    def expr(self, p):
        return p.expr

    @_('NAME')
    def expr(self, p):
        return ('var', p.NAME)

    @_('PRINT NAME')
    def statement(self, p):
        return ('print', p.NAME)

    @_('PRINT STRING')
    def statement(self, p):
        return ('print', p.STRING)

    @_('PRINTF STRING')
    def statement(self, p):
        return ('print', "f" ,p.STRING)

    @_('NUMBER')
    def expr(self, p):
        return ('num', p.NUMBER)



class BasicExecute:

    def __init__(self, tree, env,Asm):
        self.env = env
        self.Asm = Asm
        self.any_args ={}
        result = self.walkTree(tree)

        if result is not None and isinstance(result, int):
            print(result)
        if isinstance(result, str) and result[0] == '"':
            print(result)

    def walkTree(self, node):

        if isinstance(node, int):
            return node
        if isinstance(node, str):
            return node

        if node is None:
            return None

        if node[0] == 'program':
            if node[1] == None:
                self.walkTree(node[2])
            else:
                self.walkTree(node[1])
                self.walkTree(node[2])


        if node[0]=="print":
            node1 = node[1]

            if node[1] == "f":
                brak = 0
                txt =""
                lst=[]
                for i in node[2]:
                    if brak==1:
                        txt+=i
                    if i=="{":
                        brak =1
                        txt+=i
                        continue
                    if i=="}":
                        brak = 0
                        lst.append(txt)
                        txt=""
                        continue
                new_str = node[2]
                for i in lst:
                    new_str = new_str.replace(i,str(self.env[i[1:-1]]))

                node1 = new_str
                pass

            if node1 in self.env:

                if isinstance(self.env[node1], str):

                    before = len(self.Asm.data_buffer)

                    self.Asm.db(self.env[node1][1:-1])

                    self.Asm.write(1,before,len(self.env[node1][1:-1]))
                    return
            else:
                if isinstance(node1, str):
                    string = node1[1:-1]
                    before = len(self.Asm.data_buffer)
                    if "loop" in self.any_args:
                        string = string*(self.any_args["loop"]//400)
                    self.Asm.db(string)

                    self.Asm.write(1, before, len(string))
                    return



            return

        if node[0]=="mov_imm":


            reg = node[1]
            val = self.walkTree(node[2])

            target_bytes = self.Asm.size[reg] // 8

            try:
                # This will naturally throw an OverflowError if the value
                # doesn't fit in the specified number of bytes
                if val>=0:
                    bytes_val = val.to_bytes(target_bytes, byteorder='little')#negatives ,signed=True)
                else:
                    bytes_val = val.to_bytes(target_bytes, byteorder='little' ,signed=True)
            except OverflowError:
                raise Exception(f"Value {val} is too big for a {self.Asm.size[reg]}-bit register (${reg})")


            self.Asm.mov_imm(reg, val, self.Asm.size[reg])
            return
        if node[0] == 'num':
            return node[1]

        if node[0] == 'str':
            return node[1]

        if node[0] == 'if_stmt':
            result = self.walkTree(node[1])
            if result:
                return self.walkTree(node[2][1])
            return self.walkTree(node[2][2])

        if node[0] == 'condition_eqeq':
            return self.walkTree(node[1]) == self.walkTree(node[2])

        if node[0] == 'fun_def':
            self.env[node[1]] = node[2]

        if node[0] == 'fun_call':
            try:
                return self.walkTree(self.env[node[1]])
            except LookupError:
                print("Undefined function '%s'" % node[1])
                return 0

        if node[0] == 'add':
            return self.walkTree(node[1]) + self.walkTree(node[2])
        elif node[0] == 'sub':
            return self.walkTree(node[1]) - self.walkTree(node[2])
        elif node[0] == 'mul':
            return self.walkTree(node[1]) * self.walkTree(node[2])
        elif node[0] == 'div':
            return self.walkTree(node[1]) / self.walkTree(node[2])


        if node[0] == 'var_assign':
            reg = None
            if node[2][0]=="var":
                reg = node[2][1]
            #if both are registers we do something else
            if node[1] in self.Asm.size and reg in self.Asm.size:
                if node[1] == reg:
                    return
                if self.env[node[1]]==self.env[reg]:
                    return
                self.Asm.mov_reg(node[1], reg)

            else:
                val = self.walkTree(node[2])
                if node[1] in self.Asm.size:
                    if isinstance(val, int):
                        if node[1] in self.env:
                            if self.env[node[1]] == val:
                                return
                        #imm value move to reg from value ie rax,100
                        Builtins.Check_reg_size(node[1], val, self)


            self.env[node[1]] = self.walkTree(node[2])
            return node[1]

        if node[0] == 'var':
            try:


                return self.env[node[1]]
            except LookupError:
                print("Undefined variable '"+node[1]+"' found!")
                return 0

        if node[0] == 'for_loop':
            #run through all the stmtns
            #assumes we have a print or input

            is_pure_print_block = all(cmd[0] == 'print' and len(cmd)==2 for cmd in node[2])

            is_pure_printf_block = all(cmd[0] == 'print' and cmd[1]=="f" for cmd in node[2])

            if is_pure_print_block:
                strings = "".join(cmd[1][1:-1] for cmd in node[2])
                new_str = strings*(4096//len(strings))
                req_len = len(new_str)//len(strings)


            if node[1][0]== "for_loop_setup":
                #quick cheat

                loop_setup = self.walkTree(node[1])
                loop_count = self.env[loop_setup[0]]
                loop_limit = loop_setup[1]
                #self.any_args = {"loop":loop_limit}


                self.Asm.mov_imm("rbp",loop_count)
                #self.Asm.mov_imm("rbx",loop_limit)


                before = len(self.Asm.buffer)

                stmts = node[2] #temporary
                if is_pure_print_block:
                    self.Asm.mov_imm("rbx", loop_limit//(req_len))
                    self.walkTree(("print",new_str))
                else:
                    self.Asm.mov_imm("rbx", loop_limit)
                    for i in stmts:

                        self.walkTree(i)



                self.Asm.inc_reg("rbp")
                self.Asm.cmp_reg("rbp","rbx")
                # 1. Mark the spot
                after = len(self.Asm.buffer)

                # 2. Add the jump instruction (2 bytes: Opcode + Offset)
                #self.Asm.buffer.append(0xEB)  # Short Jump

                #self.Asm.buffer.append(0x00)  # Placeholder at index (after + 1)

                # 3. Calculate from the END of the instruction
                # RIP is now at (after + 2)
                #offset = before - (after + 2)

                # 4. Patch the placeholder (which is at after + 1)
                # Use 'b' for signed char (-128 to 127)
                #elf.Asm.buffer[after + 1] = struct.pack("b", offset)[0]
                self.Asm.jump_cond("jl",before)
                return
            if node[1][0] == 'for_loop_setup':
                loop_setup = self.walkTree(node[1])

                loop_count = self.env[loop_setup[0]]
                loop_limit = loop_setup[1]

                for i in range(loop_count+1, loop_limit+1):
                    res = self.walkTree(node[2])
                    if res is not None:
                        print(res)
                    self.env[loop_setup[0]] = i
                del self.env[loop_setup[0]]

        if node[0] == 'for_loop_setup':
            return (self.walkTree(node[1]), self.walkTree(node[2]))


if __name__ == '__main__':

    lexer = BasicLexer()
    parser = BasicParser()
    Asm = Assembler()
    env = {}
    try:

        with open("code.txt") as f:
            text = f.readlines()

            multi_line_buffer = ""
            in_bracket = 0

            for i in text:
                stripped = i.strip()
                if not stripped: continue

                # Count brackets to handle nesting
                in_bracket += stripped.count('{')
                in_bracket -= stripped.count('}')

                multi_line_buffer += " " + stripped

                if in_bracket == 0:
                    # We have a complete statement (either single line or closed block)
                    tree = parser.parse(lexer.tokenize(multi_line_buffer))
                    BasicExecute(tree, env, Asm)
                    multi_line_buffer = ""
        # ret Asm.buffer.extend([0xC3])
        Asm.buffer.extend(bytearray([
    0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, # mov rax, 60 (sys_exit)
    0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, # mov rdi, 0  (error code 0)
    0x0F, 0x05                                # syscall
]))
        #message_pos = Asm.current_pos
        #Asm.db("Hello OS!")

        # Now use that position in a register
        #Asm.mov_imm("rsi", message_pos)
        Asm.save()

    except EOFError:
        exit()

import ctypes


def run_machine_code_windows(code_bytes):
    blob = bytes(code_bytes)
    size = len(blob)

    # 1. Allocate memory in the Windows Kernel
    # 0x1000 = MEM_COMMIT | MEM_RESERVE
    # 0x40 = PAGE_EXECUTE_READWRITE (The "Cheat" mode)
    ptr = ctypes.windll.kernel32.VirtualAlloc(0, size, 0x3000, 0x40)

    if not ptr:
        print("Failed to allocate memory.")
        return

    # 2. Copy your hex bytes into that memory
    ctypes.windll.kernel32.RtlMoveMemory(ptr, blob, size)

    # 3. Cast the pointer to a function and call it
    func = ctypes.CFUNCTYPE(None)(ptr)

    print(f"--- Executing {size} bytes on Windows ---")
    try:
        func()
        print("--- Success ---")
    except Exception as e:
        print(f"--- Crash: {e} ---")
    # Note: In a real app, you'd call VirtualFree here

import os

# 1. YOUR 51 BYTES (Make sure the last 16 bytes are the EXIT syscall)
# If your code currently ends in 'ret' (C3), replace it with the exit hex
# Exit Hex: 48C7C03C000000 48C7C700000000 0F05
my_code = Asm.buffer+Asm.data_buffer

# 2. THE HARDCODED 120-BYTE HEADER
# This header is pre-configured to load your code at 0x400078
elf_header = (
    b'\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    b'\x02\x00\x3e\x00\x01\x00\x00\x00\x78\x00\x40\x00\x00\x00\x00\x00'
    b'\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    b'\x00\x00\x00\x00\x40\x00\x38\x00\x01\x00\x00\x00\x00\x00\x00\x00'
    b'\x01\x00\x00\x00\x07\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    b'\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00'
    b'\xaa\x00\x00\x00\x00\x00\x00\x00\xaa\x00\x00\x00\x00\x00\x00\x00'
    b'\x00\x10\x00\x00\x00\x00\x00\x00'
)

# 3. CONCATENATE AND SAVE
with open("my_app", "wb") as f:
    f.write(elf_header + my_code)

os.chmod("my_app", 0o755)
print("Created 'my_app'. Run it with ./my_app")
