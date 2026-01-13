class Builtins:
    # The "ID" is what actually goes into the binary opcode
    reg_ids = {
        'rax': 0, 'rcx': 1, 'rdx': 2, 'rbx': 3, 'rsp': 4, 'rbp': 5, 'rsi': 6, 'rdi': 7,
        'eax': 0, 'ecx': 1, 'edx': 2, 'ebx': 3, 'esp': 4, 'ebp': 5, 'esi': 6, 'edi': 7,
        # Add r8-r15 (IDs 8-15)
    }
    @staticmethod
    def to_little_endian_64(value):
        # Returns the 8-byte hex representation of a number
        return value.to_bytes(8, byteorder='little')

    # Example for mov rax, 1
    prefix = 0x48
    opcode = 0xB8 + 0  # 0 for RAX
    imm = to_little_endian_64(1)

    binary_instruction = bytes([prefix, opcode]) + imm
    #Output: b'\x48\xb8\x01\x00\x00\x00\x00\x00\x00\x00'
    @staticmethod
    def Check_reg_size(reg,val,self):


        target_bytes = self.Asm.size[reg] // 8

        try:
            # This will naturally throw an OverflowError if the value
            # doesn't fit in the specified number of bytes
            if val >= 0:
                bytes_val = val.to_bytes(target_bytes, byteorder='little')  # negatives ,signed=True)
            else:
                bytes_val = val.to_bytes(target_bytes, byteorder='little', signed=True)
        except OverflowError:
            raise Exception(f"Value {val} is too big for a {self.Asm.size[reg]}-bit register (${reg})")

        self.Asm.mov_imm(reg, val, self.Asm.size[reg])

import struct

import struct


class Assembler:

    @property
    def current_pos(self):
        return len(self.buffer)
    def __init__(self):
        self.pos = []
        self.size = {
            # 64-bit Registers
            "rax": 64, "rcx": 64, "rdx": 64, "rbx": 64, "rsp": 64, "rbp": 64, "rsi": 64, "rdi": 64,
            "r8": 64, "r9": 64, "r10": 64, "r11": 64, "r12": 64, "r13": 64, "r14": 64, "r15": 64,

            # 32-bit Registers
            "eax": 32, "ecx": 32, "edx": 32, "ebx": 32, "esp": 32, "ebp": 32, "esi": 32, "edi": 32,
            "r8d": 32, "r9d": 32, "r10d": 32, "r11d": 32, "r12d": 32, "r13d": 32, "r14d": 32, "r15d": 32,

            # 16-bit Registers
            "ax": 16, "cx": 16, "dx": 16, "bx": 16, "sp": 16, "bp": 16, "si": 16, "di": 16,
            "r8w": 16, "r9w": 16, "r10w": 16, "r11w": 16, "r12w": 16, "r13w": 16, "r14w": 16, "r15w": 16,

            # 8-bit Registers (Low bytes)
            "al": 8, "cl": 8, "dl": 8, "bl": 8, "spl": 8, "bpl": 8, "sil": 8, "dil": 8,
            "r8b": 8, "r9b": 8, "r10b": 8, "r11b": 8, "r12b": 8, "r13b": 8, "r14b": 8, "r15b": 8,

            # 8-bit Registers (High bytes - Only for rax, rcx, rdx, rbx)
            "ah": 8, "ch": 8, "dh": 8, "bh": 8
        }
        self.buffer = bytearray()
        self.data_buffer = bytearray()
        # Base IDs (0-7)
        self.regs = {
            "rax": 0, "rcx": 1, "rdx": 2, "rbx": 3, "rsp": 4, "rbp": 5, "rsi": 6, "rdi": 7,
            "eax": 0, "ecx": 1, "edx": 2, "ebx": 3, "esp": 4, "ebp": 5, "esi": 6, "edi": 7,
            "ax": 0, "cx": 1, "dx": 2, "bx": 3, "sp": 4, "bp": 5, "si": 6, "di": 7,
            "al": 0, "cl": 1, "dl": 2, "bl": 3, "spl": 4, "bpl": 5, "sil": 6, "dil": 7,
            # Extension registers r8-r15 omitted for brevity, but follow same ID logic
        }

    def _get_rex(self, size, reg_id, is_rm=False):
        """Generates the REX prefix based on operand size and register ID."""
        if size != 64 and reg_id < 8:
            return None

        rex = 0x40
        if size == 64: rex |= 0x08  # W bit (64-bit)
        if reg_id >= 8:
            if is_rm:
                rex |= 0x01  # B bit (extension in R/M field)
            else:
                rex |= 0x04  # R bit (extension in Reg field)
        return rex

    def mov_imm(self, reg_name, value, size=64):
        """@mov $reg, imm (Supports 8, 16, 32, 64 bit)"""
        reg_id = self.regs[reg_name.lower()]

        # 1. Size Prefix (16-bit needs 0x66)
        if size == 16:
            self.buffer.append(0x66)

        # 2. REX Prefix
        rex = self._get_rex(size, reg_id)
        if rex: self.buffer.append(rex)

        # 3. Opcode
        # 8-bit mov imm is 0xB0 + ID. 16/32/64-bit is 0xB8 + ID.
        if size == 8:
            self.buffer.append(0xB0 + (reg_id % 8))
            self.buffer.append(value & 0xFF)
        else:
            self.buffer.append(0xB8 + (reg_id % 8))
            # 4. Immediate Value
            if size == 16:
                format = "<H"
            elif size == 32:
                format = "<I"
            else:
                format = "<Q"
            self.buffer.extend(struct.pack(format, value))

    def mov_reg(self, dest_reg, src_reg, size=64):
        """@mov $dest, $src (Supports 8, 16, 32, 64 bit)"""
        d_id = self.regs[dest_reg.lower()]
        s_id = self.regs[src_reg.lower()]

        if size == 16: self.buffer.append(0x66)

        # REX: Needs to check both registers for extensions (r8-r15)
        rex = 0x40
        if size == 64: rex |= 0x08
        if s_id >= 8: rex |= 0x04  # R bit
        if d_id >= 8: rex |= 0x01  # B bit
        if rex > 0x40 or (size == 8 and d_id >= 4):  # Simplified REX trigger
            self.buffer.append(rex)

        # Opcode: 0x88 for 8-bit, 0x89 for others
        opcode = 0x88 if size == 8 else 0x89
        modrm = 0xC0 | ((s_id % 8) << 3) | (d_id % 8)

        self.buffer.append(opcode)

        self.buffer.append(modrm)
        return
    def save(self, filename="output.bin"):
        """Writes the current buffer to a raw binary file."""
        try:
            with open(filename, "wb") as f:
                #jump_distance = len(self.data_buffer)
                # 2. The Header: [0xEB, distance]
                #header = bytearray([0xEB, jump_distance])



                # 2. Calculate padding so code starts at a multiple of 8
                # (Account for the 2-byte jump at the start)
                #current_total_size = 2+ len(self.data_buffer)
                #padding_needed = (8 - (current_total_size % 8)) % 8

                #self.data_buffer.extend([0x90] * padding_needed)

                # 3. Update the Jump at the very beginning

                for i, data_start in self.pos:
                    rip_after_instruction = i + 4
                    # len(self.buffer) is the exact start of the data section
                    offset = len(self.buffer) + data_start - rip_after_instruction
                    self.buffer[i:i + 4] = struct.pack("<i", offset)
                final_bin =  self.buffer + self.data_buffer

                f.write(final_bin)

            print(f"Successfully saved {len(final_bin)} bytes to {filename}")
            return
        except Exception as e:
            print(f"Failed to save binary: {e}")

    def write(self, file_descriptor, string_address, length):


        self.buffer.extend([0x48, 0x8D, 0x35])

        # 2. The offset is calculated from the END of the 7-byte instruction
        instruction_end = len(self.buffer)+7
        offset = string_address - instruction_end
        offset=string_address-len(self.buffer)


        import  struct
        #SAVES rel addr before doing rel...
        self.pos.append((len(self.buffer), string_address))

        # 3. Pack it as a 4-byte signed integer
        self.buffer.extend(struct.pack("<i", offset))

        #self.mov_imm("rsi", string_address)
        self.mov_imm("rdx", length)
        self.mov_imm("rax", 1)  # syscall: write
        self.mov_imm("rdi", file_descriptor)

        self.buffer.extend([0x0F, 0x05])  # syscall opcode
        return
    def db(self, data):
        if isinstance(data, str):
            self.data_buffer.extend(data.encode('ascii'))

        elif isinstance(data, int):
            self.data_buffer.append(data & 0xFF)

    def inc_reg(self, reg_name, size=64):
        """@inc $reg (Supports 8, 16, 32, 64 bit)"""
        r_id = self.regs[reg_name.lower()]

        # 1. Size Prefix for 16-bit
        if size == 16:
            self.buffer.append(0x66)

        # 2. REX Prefix (Required for 64-bit or R8-R15)
        rex = 0x40
        if size == 64: rex |= 0x08
        if r_id >= 8:  rex |= 0x01  # B bit for extension registers

        if rex > 0x40 or (size == 8 and r_id >= 4):
            self.buffer.append(rex)

        # 3. Opcode
        # 0xFE for 8-bit, 0xFF for others
        opcode = 0xFE if size == 8 else 0xFF
        self.buffer.append(opcode)

        # 4. ModR/M
        # The /0 extension means the middle bits (5,4,3) are 000
        # Mode 3 (0xC0) + Extension 0 + Register ID
        modrm = 0xC0 | (0 << 3) | (r_id % 8)
        self.buffer.append(modrm)

    def cmp_reg(self, dest_reg, src_reg, size=64):
        """@cmp $dest, $src (Supports 8, 16, 32, 64 bit)"""
        d_id = self.regs[dest_reg.lower()]
        s_id = self.regs[src_reg.lower()]

        if size == 16: self.buffer.append(0x66)

        # REX prefix logic (Identical to your mov_reg)
        rex = 0x40
        if size == 64: rex |= 0x08
        if s_id >= 8: rex |= 0x04  # R bit (source)
        if d_id >= 8: rex |= 0x01  # B bit (destination)
        if rex > 0x40 or (size == 8 and d_id >= 4):
            self.buffer.append(rex)

        # Opcode: 0x38 for 8-bit, 0x39 for others
        opcode = 0x38 if size == 8 else 0x39

        # ModR/M: Mode 3 (11) | Source | Destination
        modrm = 0xC0 | ((s_id % 8) << 3) | (d_id % 8)

        self.buffer.append(opcode)
        self.buffer.append(modrm)

    def jump_cond(self, condition, target_label_pos=None):
        """
        @jcc target_label_pos
        Supports: je, jne, jb, ja, jl, jg, jle, jge
        """
        # Short Jump Condition Opcodes (Relative 8-bit)
        opcodes = {
            "jo": 0x70, "jno": 0x71,  # Overflow
            "jb": 0x72, "jae": 0x73,  # Below / Above or Equal (Unsigned)
            "je": 0x74, "jz": 0x74,  # Equal / Zero
            "jne": 0x75, "jnz": 0x75,  # Not Equal / Not Zero
            "jbe": 0x76, "ja": 0x77,  # Below or Equal / Above
            "js": 0x78, "jns": 0x79,  # Sign / No Sign
            "jl": 0x7C, "jge": 0x7D,  # Less / Greater or Equal (Signed)
            "jle": 0x7E, "jg": 0x7F  # Less or Equal / Greater (Signed)
        }

        if condition.lower() not in opcodes:
            raise ValueError(f"Unknown condition: {condition}")

        # 1. Mark current position
        after = len(self.buffer)

        # 2. Append the Opcode
        self.buffer.append(opcodes[condition.lower()])

        # 3. Append Placeholder for 1-byte offset
        self.buffer.append(0x00)

        # 4. Math: target - (start_of_instr + length_of_instr)
        # Jcc short is always 2 bytes
        offset = target_label_pos - (after + 2)

        # 5. Patch (Signed byte)
        try:
            self.buffer[after + 1] = struct.pack("b", offset)[0]
        except struct.error:
            raise OverflowError("Jump target too far for short jump (max 127 bytes)")



