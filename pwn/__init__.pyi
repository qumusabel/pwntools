"""
This is a .pyi stub file to let static type checkers
like pyright know what members are imported with

    >>> from pwn import *
"""

import pwnlib
from typing import Callable

import pwn.toplevel


import pwnlib


import pwnlib.adb


import pwnlib.args


import pwnlib.asm

def asm(shellcode, vma=0, extract=True, shared=False):
    r"""
    asm(code, vma = 0, extract = True, shared = False, ...) -> str

    Runs :func:`cpp` over a given shellcode and then assembles it into bytes.

    To see which architectures or operating systems are supported,
    look in :mod:`pwnlib.context`.

    Assembling shellcode requires that the GNU assembler is installed
    for the target architecture.
    See :doc:`Installing Binutils </install/binutils>` for more information.

    Arguments:
        shellcode(str): Assembler code to assemble.
        vma(int):       Virtual memory address of the beginning of assembly
        extract(bool):  Extract the raw assembly bytes from the assembled
                        file.  If :const:`False`, returns the path to an ELF file
                        with the assembly embedded.
        shared(bool):   Create a shared object.
        kwargs(dict):   Any attributes on :data:`.context` can be set, e.g.set
                        ``arch='arm'``.

    Examples:

        >>> asm("mov eax, SYS_select", arch = 'i386', os = 'freebsd')
        b'\xb8]\x00\x00\x00'
        >>> asm("mov eax, SYS_select", arch = 'amd64', os = 'linux')
        b'\xb8\x17\x00\x00\x00'
        >>> asm("mov rax, SYS_select", arch = 'amd64', os = 'linux')
        b'H\xc7\xc0\x17\x00\x00\x00'
        >>> asm("mov r0, #SYS_select", arch = 'arm', os = 'linux', bits=32)
        b'R\x00\xa0\xe3'
        >>> asm("mov #42, r0", arch = 'msp430')
        b'0@*\x00'
        >>> asm("la %r0, 42", arch = 's390', bits=64)
        b'A\x00\x00*'
    """
    ...

def cpp(shellcode):
    r"""
    cpp(shellcode, ...) -> str

    Runs CPP over the given shellcode.

    The output will always contain exactly one newline at the end.

    Arguments:
        shellcode(str): Shellcode to preprocess

    Kwargs:
        Any arguments/properties that can be set on ``context``

    Examples:

        >>> cpp("mov al, SYS_setresuid", arch = "i386", os = "linux")
        'mov al, 164\n'
        >>> cpp("weee SYS_setresuid", arch = "arm", os = "linux")
        'weee (0+164)\n'
        >>> cpp("SYS_setresuid", arch = "thumb", os = "linux")
        '(0+164)\n'
        >>> cpp("SYS_setresuid", os = "freebsd")
        '311\n'
    """
    ...

def disasm(data, vma=0, byte=True, offset=True, instructions=True):
    r"""
    disasm(data, ...) -> str

    Disassembles a bytestring into human readable assembler.

    To see which architectures are supported,
    look in :mod:`pwnlib.contex`.

    Arguments:
      data(str): Bytestring to disassemble.
      vma(int): Passed through to the --adjust-vma argument of objdump
      byte(bool): Include the hex-printed bytes in the disassembly
      offset(bool): Include the virtual memory address in the disassembly

    Kwargs:
      Any arguments/properties that can be set on ``context``

    Examples:

        >>> print(disasm(unhex('b85d000000'), arch = 'i386'))
           0:   b8 5d 00 00 00          mov    eax, 0x5d
        >>> print(disasm(unhex('b85d000000'), arch = 'i386', byte = 0))
           0:   mov    eax, 0x5d
        >>> print(disasm(unhex('b85d000000'), arch = 'i386', byte = 0, offset = 0))
        mov    eax, 0x5d
        >>> print(disasm(unhex('b817000000'), arch = 'amd64'))
           0:   b8 17 00 00 00          mov    eax, 0x17
        >>> print(disasm(unhex('48c7c017000000'), arch = 'amd64'))
           0:   48 c7 c0 17 00 00 00    mov    rax, 0x17
        >>> print(disasm(unhex('04001fe552009000'), arch = 'arm'))
           0:   e51f0004        ldr     r0, [pc, #-4]   ; 0x4
           4:   00900052        addseq  r0, r0, r2, asr r0
        >>> print(disasm(unhex('4ff00500'), arch = 'thumb', bits=32))
           0:   f04f 0005       mov.w   r0, #5
        >>> print(disasm(unhex('656664676665400F18A4000000000051'), byte=0, arch='amd64'))
           0:   gs data16 fs data16 rex nop/reserved BYTE PTR gs:[eax+eax*1+0x0]
           f:   push   rcx
        >>> print(disasm(unhex('01000000'), arch='sparc64'))
           0:   01 00 00 00     nop
        >>> print(disasm(unhex('60000000'), arch='powerpc64'))
           0:   60 00 00 00     nop
        >>> print(disasm(unhex('00000000'), arch='mips64'))
           0:   00000000        nop
    """
    ...

def make_elf(data, vma=None, strip=True, extract=True, shared=False):
    r"""
    make_elf(data, vma=None, strip=True, extract=True, shared=False, **kwargs) -> str

    Builds an ELF file with the specified binary data as its executable code.

    Arguments:
        data(str): Assembled code
        vma(int):  Load address for the ELF file
        strip(bool): Strip the resulting ELF file. Only matters if ``extract=False``.
            (Default: ``True``)
        extract(bool): Extract the assembly from the ELF file.
            If ``False``, the path of the ELF file is returned.
            (Default: ``True``)
        shared(bool): Create a Dynamic Shared Object (DSO, i.e. a ``.so``)
            which can be loaded via ``dlopen`` or ``LD_PRELOAD``.

    Examples:
        This example creates an i386 ELF that just does
        execve('/bin/sh',...).

        >>> context.clear(arch='i386')
        >>> bin_sh = unhex('6a68682f2f2f73682f62696e89e331c96a0b5899cd80')
        >>> filename = make_elf(bin_sh, extract=False)
        >>> p = process(filename)
        >>> p.sendline(b'echo Hello; exit')
        >>> p.recvline()
        b'Hello\n'
    """
    ...

def make_elf_from_assembly(assembly, vma=None, extract=False, shared=False, strip=False, **kwargs):
    r"""
    make_elf_from_assembly(assembly, vma=None, extract=None, shared=False, strip=False, **kwargs) -> str

    Builds an ELF file with the specified assembly as its executable code.

    This differs from :func:`.make_elf` in that all ELF symbols are preserved,
    such as labels and local variables.  Use :func:`.make_elf` if size matters.
    Additionally, the default value for ``extract`` in :func:`.make_elf` is
    different.

    Note:
        This is effectively a wrapper around :func:`.asm`. with setting
        ``extract=False``, ``vma=0x10000000``, and marking the resulting
        file as executable (``chmod +x``).

    Note:
        ELF files created with `arch=thumb` will prepend an ARM stub
        which switches to Thumb mode.

    Arguments:
        assembly(str): Assembly code to build into an ELF
        vma(int): Load address of the binary
            (Default: ``0x10000000``, or ``0`` if ``shared=True``)
        extract(bool): Extract the full ELF data from the file.
            (Default: ``False``)
        shared(bool): Create a shared library
            (Default: ``False``)
        kwargs(dict): Arguments to pass to :func:`.asm`.

    Returns:

        The path to the assembled ELF (extract=False), or the data
        of the assembled ELF.

    Example:

        This example shows how to create a shared library, and load it via
        ``LD_PRELOAD``.

        >>> context.clear()
        >>> context.arch = 'amd64'
        >>> sc = 'push rbp; mov rbp, rsp;'
        >>> sc += shellcraft.echo('Hello\n')
        >>> sc += 'mov rsp, rbp; pop rbp; ret'
        >>> solib = make_elf_from_assembly(sc, shared=1)
        >>> subprocess.check_output(['echo', 'World'], env={'LD_PRELOAD': solib}, universal_newlines = True)
        'Hello\nWorld\n'

        The same thing can be done with :func:`.make_elf`, though the sizes
        are different.  They both

        >>> file_a = make_elf(asm('nop'), extract=True)
        >>> file_b = make_elf_from_assembly('nop', extract=True)
        >>> file_a[:4] == file_b[:4]
        True
        >>> len(file_a) < len(file_b)
        True
    """
    ...


import pwnlib.atexception


import pwnlib.atexit


import pwnlib.commandline


import pwnlib.constants


import pwnlib.context

def LocalContext(function):
    r"""
    Wraps the specified function on a context.local() block, using kwargs.

    Example:

        >>> context.clear()
        >>> @LocalContext
        ... def printArch():
        ...     print(context.arch)
        >>> printArch()
        i386
        >>> printArch(arch='arm')
        arm
    """
    ...

def LocalNoarchContext(function):
    r"""
    Same as LocalContext, but resets arch to :const:`'none'` by default

    Example:

        >>> @LocalNoarchContext
        ... def printArch():
        ...     print(context.arch)
        >>> printArch()
        none
    """
    ...

class Thread (threading.Thread):
    r"""
    Instantiates a context-aware thread, which inherit its context when it is
    instantiated. The class can be accessed both on the context module as
    `pwnlib.context.Thread` and on the context singleton object inside the
    context module as `pwnlib.context.context.Thread`.

    Threads created by using the native :class`threading`.Thread` will have a
    clean (default) context.

    Regardless of the mechanism used to create any thread, the context
    is de-coupled from the parent thread, so changes do not cascade
    to child or parent.

    Saves a copy of the context when instantiated (at ``__init__``)
    and updates the new thread's context before passing control
    to the user code via ``run`` or ``target=``.

    Examples:

        >>> context.clear()
        >>> context.update(arch='arm')
        >>> def p():
        ...     print(context.arch)
        ...     context.arch = 'mips'
        ...     print(context.arch)
        >>> # Note that a normal Thread starts with a clean context
        >>> # (i386 is the default architecture)
        >>> t = threading.Thread(target=p)
        >>> _=(t.start(), t.join())
        i386
        mips
        >>> # Note that the main Thread's context is unchanged
        >>> print(context.arch)
        arm
        >>> # Note that a context-aware Thread receives a copy of the context
        >>> t = pwnlib.context.Thread(target=p)
        >>> _=(t.start(), t.join())
        arm
        mips
        >>> # Again, the main thread is unchanged
        >>> print(context.arch)
        arm

    Implementation Details:

        This class implemented by hooking the private function
        :func:`threading.Thread._Thread_bootstrap`, which is called before
        passing control to :func:`threading.Thread.run`.

        This could be done by overriding ``run`` itself, but we would have to
        ensure that all uses of the class would only ever use the keyword
        ``target=`` for ``__init__``, or that all subclasses invoke
        ``super(Subclass.self).set_up_context()`` or similar.
    """
    def _Thread__bootstrap(self):
        r"""
        Implementation Details:
            This only works because the class is named ``Thread``.
            If its name is changed, we have to implement this hook
            differently.
        """
        ...

    def __init__(self, *args, **kwargs):
        r"""
        This constructor should always be called with keyword arguments. Arguments are:

        *group* should be None; reserved for future extension when a ThreadGroup
        class is implemented.

        *target* is the callable object to be invoked by the run()
        method. Defaults to None, meaning nothing is called.

        *name* is the thread name. By default, a unique name is constructed of
        the form "Thread-N" where N is a small decimal number.

        *args* is the argument tuple for the target invocation. Defaults to ().

        *kwargs* is a dictionary of keyword arguments for the target
        invocation. Defaults to {}.

        If a subclass overrides the constructor, it must make sure to invoke
        the base class constructor (Thread.__init__()) before doing anything
        else to the thread.
        """
        ...

    def __repr__(self):
        r"""
        Return repr(self).
        """
        ...

    def _bootstrap(self):
        r"""
        Implementation Details:
            This only works because the class is named ``Thread``.
            If its name is changed, we have to implement this hook
            differently.
        """
        ...

    def _bootstrap_inner(self):

        ...

    def _delete(self):
        r"""
        Remove current thread from the dict of currently running threads.
        """
        ...

    def _reset_internal_locks(self, is_alive):

        ...

    def _set_ident(self):

        ...

    def _set_native_id(self):

        ...

    def _set_tstate_lock(self):
        r"""
        Set a lock object which will be released by the interpreter when
        the underlying thread state (see pystate.h) gets deleted.
        """
        ...

    def _stop(self):

        ...

    def _wait_for_tstate_lock(self, block=True, timeout=-1):

        ...

    def getName(self):

        ...

    def isDaemon(self):

        ...

    def is_alive(self):
        r"""
        Return whether the thread is alive.

        This method returns True just before the run() method starts until just
        after the run() method terminates. The module function enumerate()
        returns a list of all alive threads.
        """
        ...

    def join(self, timeout=None):
        r"""
        Wait until the thread terminates.

        This blocks the calling thread until the thread whose join() method is
        called terminates -- either normally or through an unhandled exception
        or until the optional timeout occurs.

        When the timeout argument is present and not None, it should be a
        floating point number specifying a timeout for the operation in seconds
        (or fractions thereof). As join() always returns None, you must call
        is_alive() after join() to decide whether a timeout happened -- if the
        thread is still alive, the join() call timed out.

        When the timeout argument is not present or None, the operation will
        block until the thread terminates.

        A thread can be join()ed many times.

        join() raises a RuntimeError if an attempt is made to join the current
        thread as that would cause a deadlock. It is also an error to join() a
        thread before it has been started and attempts to do so raises the same
        exception.
        """
        ...

    def run(self):
        r"""
        Method representing the thread's activity.

        You may override this method in a subclass. The standard run() method
        invokes the callable object passed to the object's constructor as the
        target argument, if any, with sequential and keyword arguments taken
        from the args and kwargs arguments, respectively.
        """
        ...

    def setDaemon(self, daemonic):

        ...

    def setName(self, name):

        ...

    def start(self):
        r"""
        Start the thread's activity.

        It must be called at most once per thread object. It arranges for the
        object's run() method to be invoked in a separate thread of control.

        This method will raise a RuntimeError if called more than once on the
        same thread object.
        """
        ...


import pwnlib.data


import pwnlib.dynelf

class DynELF:
    r"""
    DynELF knows how to resolve symbols in remote processes via an infoleak or
    memleak vulnerability encapsulated by :class:`pwnlib.memleak.MemLeak`.

    Implementation Details:

        Resolving Functions:

            In all ELFs which export symbols for importing by other libraries,
            (e.g. ``libc.so``) there are a series of tables which give exported
            symbol names, exported symbol addresses, and the ``hash`` of those
            exported symbols.  By applying a hash function to the name of the
            desired symbol (e.g., ``'printf'``), it can be located in the hash
            table.  Its location in the hash table provides an index into the
            string name table (strtab_), and the symbol address (symtab_).

            Assuming we have the base address of ``libc.so``, the way to resolve
            the address of ``printf`` is to locate the ``symtab``, ``strtab``,
            and hash table. The string ``"printf"`` is hashed according to the
            style of the hash table (SYSV_ or GNU_), and the hash table is
            walked until a matching entry is located. We can verify an exact
            match by checking the string table, and then get the offset into
            ``libc.so`` from the ``symtab``.

        Resolving Library Addresses:

            If we have a pointer into a dynamically-linked executable, we can
            leverage an internal linker structure called the `link map`_. This
            is a linked list structure which contains information about each
            loaded library, including its full path and base address.

            A pointer to the ``link map`` can be found in two ways.  Both are
            referenced from entries in the DYNAMIC_ array.

            - In non-RELRO binaries, a pointer is placed in the `.got.plt`_ area
              in the binary. This is marked by finding the DT_PLTGOT_ area in the
              binary.
            - In all binaries, a pointer can be found in the area described by
              the DT_DEBUG_ area.  This exists even in stripped binaries.

            For maximum flexibility, both mechanisms are used exhaustively.

    .. _symtab:    https://refspecs.linuxbase.org/elf/gabi4+/ch4.symtab.html
    .. _strtab:    https://refspecs.linuxbase.org/elf/gabi4+/ch4.strtab.html
    .. _.got.plt:  https://refspecs.linuxbase.org/LSB_3.1.1/LSB-Core-generic/LSB-Core-generic/specialsections.html
    .. _DYNAMIC:   http://www.sco.com/developers/gabi/latest/ch5.dynamic.html#dynamic_section
    .. _SYSV:      https://refspecs.linuxbase.org/elf/gabi4+/ch5.dynamic.html#hash
    .. _GNU:       https://blogs.oracle.com/ali/entry/gnu_hash_elf_sections
    .. _DT_DEBUG:  https://reverseengineering.stackexchange.com/questions/6525/elf-link-map-when-linked-as-relro
    .. _link map:  https://sourceware.org/git/?p=glibc.git;a=blob;f=elf/link.h;h=eaca8028e45a859ac280301a6e955a14eed1b887;hb=HEAD#l84
    .. _DT_PLTGOT: http://refspecs.linuxfoundation.org/ELF/zSeries/lzsabi0_zSeries/x2251.html
    """
    def __init__(self, leak, pointer=None, elf=None, libcdb=True):
        r"""
        Instantiates an object which can resolve symbols in a running binary
        given a :class:`pwnlib.memleak.MemLeak` leaker and a pointer inside
        the binary.

        Arguments:
            leak(MemLeak): Instance of pwnlib.memleak.MemLeak for leaking memory
            pointer(int):  A pointer into a loaded ELF file
            elf(str,ELF):  Path to the ELF file on disk, or a loaded :class:`pwnlib.elf.ELF`.
            libcdb(bool):  Attempt to use libcdb to speed up libc lookups
        """
        ...

    def _dynamic_load_dynelf(self, libname):
        r"""
        _dynamic_load_dynelf(libname) -> DynELF

        Looks up information about a loaded library via the link map.

        Arguments:
            libname(str):  Name of the library to resolve, or a substring (e.g. 'libc.so')

        Returns:
            A DynELF instance for the loaded library, or None.
        """
        ...

    def _find_base(self, ptr):

        ...

    def _find_base_optimized(self, ptr):

        ...

    def _find_dt(self, tag):
        r"""
        Find an entry in the DYNAMIC array.

        Arguments:
            tag(int): Single tag to find

        Returns:
            Pointer to the data described by the specified entry.
        """
        ...

    def _find_dynamic_phdr(self):
        r"""
        Returns the address of the first Program Header with the type
        PT_DYNAMIC.
        """
        ...

    def _find_linkmap(self, pltgot=None, debug=None):
        r"""
        The linkmap is a chained structure created by the loader at runtime
        which contains information on the names and load addresses of all
        libraries.

        For non-RELRO binaries, a pointer to this is stored in the .got.plt
        area.

        For RELRO binaries, a pointer is additionally stored in the DT_DEBUG
        area.
        """
        ...

    def _find_linkmap_assisted(self, path):
        r"""
        Uses an ELF file to assist in finding the link_map.
        
        """
        ...

    def _find_mapped_pages(self, readonly=False, page_size=4096):
        r"""
        A generator of all mapped pages, as found using the Program Headers.

        Yields tuples of the form: (virtual address, memory size)
        """
        ...

    def _lookup(self, symb):
        r"""
        Performs the actual symbol lookup within one ELF file.
        """
        ...

    def _lookup_build_id(self, lib=None):

        ...

    def _make_absolute_ptr(self, ptr_or_offset):
        r"""
        For shared libraries (or PIE executables), many ELF fields may
        contain offsets rather than actual pointers. If the ELF type is 'DYN',
        the argument may be an offset. It will not necessarily be an offset,
        because the run-time linker may have fixed it up to be a real pointer
        already. In this case an educated guess is made, and the ELF base
        address is added to the value if it is determined to be an offset.
        """
        ...

    def _resolve_symbol_gnu(self, libbase, symb, hshtab, strtab, symtab):
        r"""
        Internal Documentation:
            The GNU hash structure is a bit more complex than the normal hash
            structure.

            Again, Oracle has good documentation.
            https://blogs.oracle.com/ali/entry/gnu_hash_elf_sections

            You can force an ELF to use this type of symbol table by compiling
            with 'gcc -Wl,--hash-style=gnu'
        """
        ...

    def _resolve_symbol_sysv(self, libbase, symb, hshtab, strtab, symtab):
        r"""
        Internal Documentation:
            See the ELF manual for more information.  Search for the phrase
            "A hash table of Elf32_Word objects supports symbol table access", or see:
            https://docs.oracle.com/cd/E19504-01/802-6319/6ia12qkfo/index.html#chapter6-48031

            .. code-block:: c

                struct Elf_Hash {
                    uint32_t nbucket;
                    uint32_t nchain;
                    uint32_t bucket[nbucket];
                    uint32_t chain[nchain];
                }

            You can force an ELF to use this type of symbol table by compiling
            with 'gcc -Wl,--hash-style=sysv'
        """
        ...

    def bases(self):
        r"""
        Resolve base addresses of all loaded libraries.

        Return a dictionary mapping library path to its base address.
        """
        ...

    def dump(self, libs=False, readonly=False):
        r"""
        dump(libs = False, readonly = False)

        Dumps the ELF's memory pages to allow further analysis.

        Arguments:
            libs(bool, optional): True if should dump the libraries too (False by default)
            readonly(bool, optional): True if should dump read-only pages (False by default)

        Returns:
            a dictionary of the form: { address : bytes }
        """
        ...

    def failure(self, msg):

        ...

    def find_base(leak, ptr):
        r"""
        Given a :class:`pwnlib.memleak.MemLeak` object and a pointer into a
        library, find its base address.
        """
        ...

    def heap(self):
        r"""
        Finds the beginning of the heap via __curbrk, which is an exported
        symbol in the linker, which points to the current brk.
        """
        ...

    def lookup(self, symb=None, lib=None):
        r"""
        lookup(symb = None, lib = None) -> int

        Find the address of ``symbol``, which is found in ``lib``.

        Arguments:
            symb(str): Named routine to look up
              If omitted, the base address of the library will be returned.
            lib(str): Substring to match for the library name.
              If omitted, the current library is searched.
              If set to ``'libc'``, ``'libc.so'`` is assumed.

        Returns:
            Address of the named symbol, or :const:`None`.
        """
        ...

    def stack(self):
        r"""
        Finds a pointer to the stack via __environ, which is an exported
        symbol in libc, which points to the environment block.
        """
        ...

    def status(self, msg):

        ...

    def success(self, msg):

        ...

    def waitfor(self, msg):

        ...


import pwnlib.elf


import pwnlib.elf.corefile

class Core (pwnlib.elf.corefile.Corefile):
    r"""
    Alias for :class:`.Corefile`
    """
    def __getattr__(self, attribute):

        ...

    def __getitem__(self, name):
        r"""
        Implement dict-like access to header entries
        
        """
        ...

    def __init__(self, *a, **kw):
        r"""
        Initialize self.  See help(type(self)) for accurate signature.
        """
        ...

    def __repr__(self):
        r"""
        Return repr(self).
        """
        ...

    def _decompress_dwarf_section(section):
        r"""
        Returns the uncompressed contents of the provided DWARF section.
        
        """
        ...

    def _describe(self):

        ...

    def _describe_core(self):

        ...

    def _get_section_header(self, n):
        r"""
        Find the header of section #n, parse it and return the struct
        
        """
        ...

    def _get_section_header_stringtable(self):
        r"""
        Get the string table section corresponding to the section header
        table.
        """
        ...

    def _get_section_name(self, section_header):
        r"""
        Given a section header, find this section's name in the file's
        string table
        """
        ...

    def _get_segment_header(self, n):
        r"""
        Find the header of segment #n, parse it and return the struct
        
        """
        ...

    def _identify_file(self):
        r"""
        Verify the ELF file and identify its class and endianness.
        
        """
        ...

    def _load_mappings(self):

        ...

    def _make_elf_hash_section(self, section_header, name):

        ...

    def _make_gnu_hash_section(self, section_header, name):

        ...

    def _make_gnu_verdef_section(self, section_header, name):
        r"""
        Create a GNUVerDefSection
        
        """
        ...

    def _make_gnu_verneed_section(self, section_header, name):
        r"""
        Create a GNUVerNeedSection
        
        """
        ...

    def _make_gnu_versym_section(self, section_header, name):
        r"""
        Create a GNUVerSymSection
        
        """
        ...

    def _make_section(self, section_header):
        r"""
        Create a section object of the appropriate type
        
        """
        ...

    def _make_segment(self, segment_header):
        r"""
        Create a Segment object of the appropriate type
        
        """
        ...

    def _make_sunwsyminfo_table_section(self, section_header, name):
        r"""
        Create a SUNWSyminfoTableSection
        
        """
        ...

    def _make_symbol_table_index_section(self, section_header, name):
        r"""
        Create a SymbolTableIndexSection object
        
        """
        ...

    def _make_symbol_table_section(self, section_header, name):
        r"""
        Create a SymbolTableSection
        
        """
        ...

    def _parse_auxv(self, note):

        ...

    def _parse_elf_header(self):
        r"""
        Parses the ELF file header and assigns the result to attributes
        of this object.
        """
        ...

    def _parse_nt_file(self, note):

        ...

    def _parse_stack(self):

        ...

    def _patch_elf_and_read_maps(self):
        r"""
        patch_elf_and_read_maps(self) -> dict

        Read ``/proc/self/maps`` as if the ELF were executing.

        This is done by replacing the code at the entry point with shellcode which
        dumps ``/proc/self/maps`` and exits, and **actually executing the binary**.

        Returns:
            A ``dict`` mapping file paths to the lowest address they appear at.
            Does not do any translation for e.g. QEMU emulation, the raw results
            are returned.

            If there is not enough space to inject the shellcode in the segment
            which contains the entry point, returns ``{}``.

        Doctests:

            These tests are just to ensure that our shellcode is correct.

            >>> for arch in CAT_PROC_MAPS_EXIT:
            ...   context.clear()
            ...   with context.local(arch=arch):
            ...     sc = shellcraft.cat("/proc/self/maps")
            ...     sc += shellcraft.exit()
            ...     sc = asm(sc)
            ...     sc = enhex(sc)
            ...     assert sc == CAT_PROC_MAPS_EXIT[arch]
        """
        ...

    def _populate_functions(self):
        r"""
        Builds a dict of 'functions' (i.e. symbols of type 'STT_FUNC')
        by function name that map to a tuple consisting of the func address and size
        in bytes.
        """
        ...

    def _populate_got(*a):
        r"""
        Loads the symbols for all relocations
        """
        ...

    def _populate_kernel_version(self):

        ...

    def _populate_libraries(self):
        r"""
        >>> from os.path import exists
        >>> bash = ELF(which('bash'))
        >>> all(map(exists, bash.libs.keys()))
        True
        >>> any(map(lambda x: 'libc' in x, bash.libs.keys()))
        True
        """
        ...

    def _populate_memory(self):

        ...

    def _populate_mips_got(self):

        ...

    def _populate_plt(*a):
        r"""
        Loads the PLT symbols

        >>> path = pwnlib.data.elf.path
        >>> for test in glob(os.path.join(path, 'test-*')):
        ...     test = ELF(test)
        ...     assert '__stack_chk_fail' in test.got, test
        ...     if test.arch != 'ppc':
        ...         assert '__stack_chk_fail' in test.plt, test
        """
        ...

    def _populate_symbols(self):
        r"""
        >>> bash = ELF(which('bash'))
        >>> bash.symbols['_start'] == bash.entry
        True
        """
        ...

    def _populate_synthetic_symbols(self):
        r"""
        Adds symbols from the GOT and PLT to the symbols dictionary.

        Does not overwrite any existing symbols, and prefers PLT symbols.

        Synthetic plt.xxx and got.xxx symbols are added for each PLT and
        GOT entry, respectively.

        Example:bash.

            >>> bash = ELF(which('bash'))
            >>> bash.symbols.wcscmp == bash.plt.wcscmp
            True
            >>> bash.symbols.wcscmp == bash.symbols.plt.wcscmp
            True
            >>> bash.symbols.stdin  == bash.got.stdin
            True
            >>> bash.symbols.stdin  == bash.symbols.got.stdin
            True
        """
        ...

    def _read_dwarf_section(self, section, relocate_dwarf_sections):
        r"""
        Read the contents of a DWARF section from the stream and return a
        DebugSectionDescriptor. Apply relocations if asked to.
        """
        ...

    def _section_offset(self, n):
        r"""
        Compute the offset of section #n in the file
        
        """
        ...

    def _segment_offset(self, n):
        r"""
        Compute the offset of segment #n in the file
        
        """
        ...

    def _update_args(self, kw):

        ...

    def address_offsets(self, start, size=1):
        r"""
        Yield a file offset for each ELF segment containing a memory region.

        A memory region is defined by the range [start...start+size). The
        offset of the region is yielded.
        """
        ...

    def asm(self, address, assembly):
        r"""
        asm(address, assembly)

        Assembles the specified instructions and inserts them
        into the ELF at the specified address.

        This modifies the ELF in-place.
        The resulting binary can be saved with :meth:`.ELF.save`
        """
        ...

    def bss(self, offset=0):
        r"""
        bss(offset=0) -> int

        Returns:
            Address of the ``.bss`` section, plus the specified offset.
        """
        ...

    def checksec(self, banner=True, color=True):
        r"""
        checksec(banner=True, color=True)

        Prints out information in the binary, similar to ``checksec.sh``.

        Arguments:
            banner(bool): Whether to print the path to the ELF binary.
            color(bool): Whether to use colored output.
        """
        ...

    def debug(self):
        r"""
        Open the corefile under a debugger.
        """
        ...

    def disable_nx(self):
        r"""
        Disables NX for the ELF.

        Zeroes out the ``PT_GNU_STACK`` program header ``p_type`` field.
        """
        ...

    def disasm(self, address, n_bytes):
        r"""
        disasm(address, n_bytes) -> str

        Returns a string of disassembled instructions at
        the specified virtual memory address
        """
        ...

    def dynamic_by_tag(self, tag):
        r"""
        dynamic_by_tag(tag) -> tag

        Arguments:
            tag(str): Named ``DT_XXX`` tag (e.g. ``'DT_STRTAB'``).

        Returns:
            :class:`elftools.elf.dynamic.DynamicTag`
        """
        ...

    def dynamic_string(self, offset):
        r"""
        dynamic_string(offset) -> bytes

        Fetches an enumerated string from the ``DT_STRTAB`` table.

        Arguments:
            offset(int): String index

        Returns:
            :class:`str`: String from the table as raw bytes.
        """
        ...

    def dynamic_value_by_tag(self, tag):
        r"""
        dynamic_value_by_tag(tag) -> int

        Retrieve the value from a dynamic tag a la ``DT_XXX``.

        If the tag is missing, returns ``None``.
        """
        ...

    def fit(self, address, *a, **kw):
        r"""
        Writes fitted data into the specified address.

        See: :func:`.packing.fit`
        """
        ...

    def flat(self, address, *a, **kw):
        r"""
        Writes a full array of values to the specified address.

        See: :func:`.packing.flat`
        """
        ...

    def from_assembly(assembly, *a, **kw):
        r"""
        from_assembly(assembly) -> ELF

        Given an assembly listing, return a fully loaded ELF object
        which contains that assembly at its entry point.

        Arguments:

            assembly(str): Assembly language listing
            vma(int): Address of the entry point and the module's base address.

        Example:

            >>> e = ELF.from_assembly('nop; foo: int 0x80', vma = 0x400000)
            >>> e.symbols['foo'] = 0x400001
            >>> e.disasm(e.entry, 1)
            '  400000:       90                      nop'
            >>> e.disasm(e.symbols['foo'], 2)
            '  400001:       cd 80                   int    0x80'
        """
        ...

    def from_bytes(bytes, *a, **kw):
        r"""
        from_bytes(bytes) -> ELF

        Given a sequence of bytes, return a fully loaded ELF object
        which contains those bytes at its entry point.

        Arguments:

            bytes(str): Shellcode byte string
            vma(int): Desired base address for the ELF.

        Example:

            >>> e = ELF.from_bytes(b'\x90\xcd\x80', vma=0xc000)
            >>> print(e.disasm(e.entry, 3))
                c000:       90                      nop
                c001:       cd 80                   int    0x80
        """
        ...

    def get_data(self):
        r"""
        get_data() -> bytes

        Retrieve the raw data from the ELF file.

        >>> bash = ELF(which('bash'))
        >>> fd   = open(which('bash'), 'rb')
        >>> bash.get_data() == fd.read()
        True
        """
        ...

    def get_dwarf_info(self, relocate_dwarf_sections=True):
        r"""
        Return a DWARFInfo object representing the debugging information in
        this file.

        If relocate_dwarf_sections is True, relocations for DWARF sections
        are looked up and applied.
        """
        ...

    def get_ehabi_infos(self):
        r"""
        Generally, shared library and executable contain 1 .ARM.exidx section.
        Object file contains many .ARM.exidx sections.
        So we must traverse every section and filter sections whose type is SHT_ARM_EXIDX.
        """
        ...

    def get_machine_arch(self):
        r"""
        Return the machine architecture, as detected from the ELF header.
        
        """
        ...

    def get_section(self, n):
        r"""
        Get the section at index #n from the file (Section object or a
        subclass)
        """
        ...

    def get_section_by_name(self, name):
        r"""
        Get a section from the file, by name. Return None if no such
        section exists.
        """
        ...

    def get_segment(self, n):
        r"""
        Get the segment at index #n from the file (Segment object)
        
        """
        ...

    def get_segment_for_address(self, address, size=1):
        r"""
        get_segment_for_address(address, size=1) -> Segment

        Given a virtual address described by a ``PT_LOAD`` segment, return the
        first segment which describes the virtual address.  An optional ``size``
        may be provided to ensure the entire range falls into the same segment.

        Arguments:
            address(int): Virtual address to find
            size(int): Number of bytes which must be available after ``address``
                in **both** the file-backed data for the segment, and the memory
                region which is reserved for the data.

        Returns:
            Either returns a :class:`.segments.Segment` object, or ``None``.
        """
        ...

    def get_shstrndx(self):
        r"""
        Find the string table section index for the section header table
        
        """
        ...

    def getenv(self, name):
        r"""
        getenv(name) -> int

        Read an environment variable off the stack, and return its contents.

        Arguments:
            name(str): Name of the environment variable to read.

        Returns:
            :class:`str`: The contents of the environment variable.

        Example:

            >>> elf = ELF.from_assembly(shellcraft.trap())
            >>> io = elf.process(env={'GREETING': 'Hello!'})
            >>> io.wait(1)
            >>> io.corefile.getenv('GREETING')
            b'Hello!'
        """
        ...

    def has_dwarf_info(self):
        r"""
        Check whether this file appears to have debugging information.
        We assume that if it has the .debug_info or .zdebug_info section, it
        has all the other required sections as well.
        """
        ...

    def has_ehabi_info(self):
        r"""
        Check whether this file appears to have arm exception handler index table.
        
        """
        ...

    def iter_sections(self):
        r"""
        Yield all the sections in the file
        
        """
        ...

    def iter_segments(self):
        r"""
        Yield all the segments in the file
        
        """
        ...

    def iter_segments_by_type(self, t):
        r"""
        Yields:
            Segments matching the specified type.
        """
        ...

    def num_sections(self):
        r"""
        Number of sections in the file
        
        """
        ...

    def num_segments(self):
        r"""
        Number of segments in the file
        
        """
        ...

    def offset_to_vaddr(self, offset):
        r"""
        offset_to_vaddr(offset) -> int

        Translates the specified offset to a virtual address.

        Arguments:
            offset(int): Offset to translate

        Returns:
            `int`: Virtual address which corresponds to the file offset, or
            :const:`None`.

        Examples:

            This example shows that regardless of changes to the virtual
            address layout by modifying :attr:`.ELF.address`, the offset
            for any given address doesn't change.

            >>> bash = ELF('/bin/bash')
            >>> bash.address == bash.offset_to_vaddr(0)
            True
            >>> bash.address += 0x123456
            >>> bash.address == bash.offset_to_vaddr(0)
            True
        """
        ...

    def p16(self, address, data, *a, **kw):
        r"""
        Writes a 16-bit integer ``data`` to the specified ``address``
        """
        ...

    def p32(self, address, data, *a, **kw):
        r"""
        Writes a 32-bit integer ``data`` to the specified ``address``
        """
        ...

    def p64(self, address, data, *a, **kw):
        r"""
        Writes a 64-bit integer ``data`` to the specified ``address``
        """
        ...

    def p8(self, address, data, *a, **kw):
        r"""
        Writes a 8-bit integer ``data`` to the specified ``address``
        """
        ...

    def pack(self, address, data, *a, **kw):
        r"""
        Writes a packed integer ``data`` to the specified ``address``
        """
        ...

    def parse_kconfig(self, data):

        ...

    def process(self, argv=[], *a, **kw):
        r"""
        process(argv=[], *a, **kw) -> process

        Execute the binary with :class:`.process`.  Note that ``argv``
        is a list of arguments, and should not include ``argv[0]``.

        Arguments:
            argv(list): List of arguments to the binary
            *args: Extra arguments to :class:`.process`
            **kwargs: Extra arguments to :class:`.process`

        Returns:
            :class:`.process`
        """
        ...

    def read(self, address, count):
        r"""
        read(address, count) -> bytes

        Read data from the specified virtual address

        Arguments:
            address(int): Virtual address to read
            count(int): Number of bytes to read

        Returns:
            A :class:`str` object, or :const:`None`.

        Examples:
            The simplest example is just to read the ELF header.

            >>> bash = ELF(which('bash'))
            >>> bash.read(bash.address, 4)
            b'\x7fELF'

            ELF segments do not have to contain all of the data on-disk
            that gets loaded into memory.

            First, let's create an ELF file has some code in two sections.

            >>> assembly = '''
            ... .section .A,"awx"
            ... .global A
            ... A: nop
            ... .section .B,"awx"
            ... .global B
            ... B: int3
            ... '''
            >>> e = ELF.from_assembly(assembly, vma=False)

            By default, these come right after eachother in memory.

            >>> e.read(e.symbols.A, 2)
            b'\x90\xcc'
            >>> e.symbols.B - e.symbols.A
            1

            Let's move the sections so that B is a little bit further away.

            >>> objcopy = pwnlib.asm._objcopy()
            >>> objcopy += [
            ...     '--change-section-vma', '.B+5',
            ...     '--change-section-lma', '.B+5',
            ...     e.path
            ... ]
            >>> subprocess.check_call(objcopy)
            0

            Now let's re-load the ELF, and check again

            >>> e = ELF(e.path)
            >>> e.symbols.B - e.symbols.A
            6
            >>> e.read(e.symbols.A, 2)
            b'\x90\x00'
            >>> e.read(e.symbols.A, 7)
            b'\x90\x00\x00\x00\x00\x00\xcc'
            >>> e.read(e.symbols.A, 10)
            b'\x90\x00\x00\x00\x00\x00\xcc\x00\x00\x00'

            Everything is relative to the user-selected base address, so moving
            things around keeps everything working.

            >>> e.address += 0x1000
            >>> e.read(e.symbols.A, 10)
            b'\x90\x00\x00\x00\x00\x00\xcc\x00\x00\x00'
        """
        ...

    def save(self, path=None):
        r"""
        Save the ELF to a file

        >>> bash = ELF(which('bash'))
        >>> bash.save('/tmp/bash_copy')
        >>> copy = open('/tmp/bash_copy', 'rb')
        >>> bash = open(which('bash'), 'rb')
        >>> bash.read() == copy.read()
        True
        """
        ...

    def search(self, needle, writable=False, executable=False):
        r"""
        search(needle, writable = False, executable = False) -> generator

        Search the ELF's virtual address space for the specified string.

        Notes:
            Does not search empty space between segments, or uninitialized
            data.  This will only return data that actually exists in the
            ELF file.  Searching for a long string of NULL bytes probably
            won't work.

        Arguments:
            needle(str): String to search for.
            writable(bool): Search only writable sections.
            executable(bool): Search only executable sections.

        Yields:
            An iterator for each virtual address that matches.

        Examples:

            An ELF header starts with the bytes ``\x7fELF``, so we
            sould be able to find it easily.

            >>> bash = ELF('/bin/bash')
            >>> bash.address + 1 == next(bash.search(b'ELF'))
            True

            We can also search for string the binary.

            >>> len(list(bash.search(b'GNU bash'))) > 0
            True

            It is also possible to search for instructions in executable sections.

            >>> binary = ELF.from_assembly('nop; mov eax, 0; jmp esp; ret')
            >>> jmp_addr = next(binary.search(asm('jmp esp'), executable = True))
            >>> binary.read(jmp_addr, 2) == asm('jmp esp')
            True
        """
        ...

    def section(self, name):
        r"""
        section(name) -> bytes

        Gets data for the named section

        Arguments:
            name(str): Name of the section

        Returns:
            :class:`str`: String containing the bytes for that section
        """
        ...

    def string(self, address):
        r"""
        string(address) -> str

        Reads a null-terminated string from the specified ``address``

        Returns:
            A ``str`` with the string contents (NUL terminator is omitted),
            or an empty string if no NUL terminator could be found.
        """
        ...

    def u16(self, address, *a, **kw):
        r"""
        Unpacks an integer from the specified ``address``.
        """
        ...

    def u32(self, address, *a, **kw):
        r"""
        Unpacks an integer from the specified ``address``.
        """
        ...

    def u64(self, address, *a, **kw):
        r"""
        Unpacks an integer from the specified ``address``.
        """
        ...

    def u8(self, address, *a, **kw):
        r"""
        Unpacks an integer from the specified ``address``.
        """
        ...

    def unpack(self, address, *a, **kw):
        r"""
        Unpacks an integer from the specified ``address``.
        """
        ...

    def vaddr_to_offset(self, address):
        r"""
        vaddr_to_offset(address) -> int

        Translates the specified virtual address to a file offset

        Arguments:
            address(int): Virtual address to translate

        Returns:
            int: Offset within the ELF file which corresponds to the address,
            or :const:`None`.

        Examples:
            >>> bash = ELF(which('bash'))
            >>> bash.vaddr_to_offset(bash.address)
            0
            >>> bash.address += 0x123456
            >>> bash.vaddr_to_offset(bash.address)
            0
            >>> bash.vaddr_to_offset(0) is None
            True
        """
        ...

    def write(self, address, data):
        r"""
        Writes data to the specified virtual address

        Arguments:
            address(int): Virtual address to write
            data(str): Bytes to write

        Note:
            This routine does not check the bounds on the write to ensure
            that it stays in the same segment.

        Examples:
          >>> bash = ELF(which('bash'))
          >>> bash.read(bash.address+1, 3)
          b'ELF'
          >>> bash.write(bash.address, b"HELO")
          >>> bash.read(bash.address, 4)
          b'HELO'
        """
        ...

class Coredump (pwnlib.elf.corefile.Corefile):
    r"""
    Alias for :class:`.Corefile`
    """
    def __getattr__(self, attribute):

        ...

    def __getitem__(self, name):
        r"""
        Implement dict-like access to header entries
        
        """
        ...

    def __init__(self, *a, **kw):
        r"""
        Initialize self.  See help(type(self)) for accurate signature.
        """
        ...

    def __repr__(self):
        r"""
        Return repr(self).
        """
        ...

    def _decompress_dwarf_section(section):
        r"""
        Returns the uncompressed contents of the provided DWARF section.
        
        """
        ...

    def _describe(self):

        ...

    def _describe_core(self):

        ...

    def _get_section_header(self, n):
        r"""
        Find the header of section #n, parse it and return the struct
        
        """
        ...

    def _get_section_header_stringtable(self):
        r"""
        Get the string table section corresponding to the section header
        table.
        """
        ...

    def _get_section_name(self, section_header):
        r"""
        Given a section header, find this section's name in the file's
        string table
        """
        ...

    def _get_segment_header(self, n):
        r"""
        Find the header of segment #n, parse it and return the struct
        
        """
        ...

    def _identify_file(self):
        r"""
        Verify the ELF file and identify its class and endianness.
        
        """
        ...

    def _load_mappings(self):

        ...

    def _make_elf_hash_section(self, section_header, name):

        ...

    def _make_gnu_hash_section(self, section_header, name):

        ...

    def _make_gnu_verdef_section(self, section_header, name):
        r"""
        Create a GNUVerDefSection
        
        """
        ...

    def _make_gnu_verneed_section(self, section_header, name):
        r"""
        Create a GNUVerNeedSection
        
        """
        ...

    def _make_gnu_versym_section(self, section_header, name):
        r"""
        Create a GNUVerSymSection
        
        """
        ...

    def _make_section(self, section_header):
        r"""
        Create a section object of the appropriate type
        
        """
        ...

    def _make_segment(self, segment_header):
        r"""
        Create a Segment object of the appropriate type
        
        """
        ...

    def _make_sunwsyminfo_table_section(self, section_header, name):
        r"""
        Create a SUNWSyminfoTableSection
        
        """
        ...

    def _make_symbol_table_index_section(self, section_header, name):
        r"""
        Create a SymbolTableIndexSection object
        
        """
        ...

    def _make_symbol_table_section(self, section_header, name):
        r"""
        Create a SymbolTableSection
        
        """
        ...

    def _parse_auxv(self, note):

        ...

    def _parse_elf_header(self):
        r"""
        Parses the ELF file header and assigns the result to attributes
        of this object.
        """
        ...

    def _parse_nt_file(self, note):

        ...

    def _parse_stack(self):

        ...

    def _patch_elf_and_read_maps(self):
        r"""
        patch_elf_and_read_maps(self) -> dict

        Read ``/proc/self/maps`` as if the ELF were executing.

        This is done by replacing the code at the entry point with shellcode which
        dumps ``/proc/self/maps`` and exits, and **actually executing the binary**.

        Returns:
            A ``dict`` mapping file paths to the lowest address they appear at.
            Does not do any translation for e.g. QEMU emulation, the raw results
            are returned.

            If there is not enough space to inject the shellcode in the segment
            which contains the entry point, returns ``{}``.

        Doctests:

            These tests are just to ensure that our shellcode is correct.

            >>> for arch in CAT_PROC_MAPS_EXIT:
            ...   context.clear()
            ...   with context.local(arch=arch):
            ...     sc = shellcraft.cat("/proc/self/maps")
            ...     sc += shellcraft.exit()
            ...     sc = asm(sc)
            ...     sc = enhex(sc)
            ...     assert sc == CAT_PROC_MAPS_EXIT[arch]
        """
        ...

    def _populate_functions(self):
        r"""
        Builds a dict of 'functions' (i.e. symbols of type 'STT_FUNC')
        by function name that map to a tuple consisting of the func address and size
        in bytes.
        """
        ...

    def _populate_got(*a):
        r"""
        Loads the symbols for all relocations
        """
        ...

    def _populate_kernel_version(self):

        ...

    def _populate_libraries(self):
        r"""
        >>> from os.path import exists
        >>> bash = ELF(which('bash'))
        >>> all(map(exists, bash.libs.keys()))
        True
        >>> any(map(lambda x: 'libc' in x, bash.libs.keys()))
        True
        """
        ...

    def _populate_memory(self):

        ...

    def _populate_mips_got(self):

        ...

    def _populate_plt(*a):
        r"""
        Loads the PLT symbols

        >>> path = pwnlib.data.elf.path
        >>> for test in glob(os.path.join(path, 'test-*')):
        ...     test = ELF(test)
        ...     assert '__stack_chk_fail' in test.got, test
        ...     if test.arch != 'ppc':
        ...         assert '__stack_chk_fail' in test.plt, test
        """
        ...

    def _populate_symbols(self):
        r"""
        >>> bash = ELF(which('bash'))
        >>> bash.symbols['_start'] == bash.entry
        True
        """
        ...

    def _populate_synthetic_symbols(self):
        r"""
        Adds symbols from the GOT and PLT to the symbols dictionary.

        Does not overwrite any existing symbols, and prefers PLT symbols.

        Synthetic plt.xxx and got.xxx symbols are added for each PLT and
        GOT entry, respectively.

        Example:bash.

            >>> bash = ELF(which('bash'))
            >>> bash.symbols.wcscmp == bash.plt.wcscmp
            True
            >>> bash.symbols.wcscmp == bash.symbols.plt.wcscmp
            True
            >>> bash.symbols.stdin  == bash.got.stdin
            True
            >>> bash.symbols.stdin  == bash.symbols.got.stdin
            True
        """
        ...

    def _read_dwarf_section(self, section, relocate_dwarf_sections):
        r"""
        Read the contents of a DWARF section from the stream and return a
        DebugSectionDescriptor. Apply relocations if asked to.
        """
        ...

    def _section_offset(self, n):
        r"""
        Compute the offset of section #n in the file
        
        """
        ...

    def _segment_offset(self, n):
        r"""
        Compute the offset of segment #n in the file
        
        """
        ...

    def _update_args(self, kw):

        ...

    def address_offsets(self, start, size=1):
        r"""
        Yield a file offset for each ELF segment containing a memory region.

        A memory region is defined by the range [start...start+size). The
        offset of the region is yielded.
        """
        ...

    def asm(self, address, assembly):
        r"""
        asm(address, assembly)

        Assembles the specified instructions and inserts them
        into the ELF at the specified address.

        This modifies the ELF in-place.
        The resulting binary can be saved with :meth:`.ELF.save`
        """
        ...

    def bss(self, offset=0):
        r"""
        bss(offset=0) -> int

        Returns:
            Address of the ``.bss`` section, plus the specified offset.
        """
        ...

    def checksec(self, banner=True, color=True):
        r"""
        checksec(banner=True, color=True)

        Prints out information in the binary, similar to ``checksec.sh``.

        Arguments:
            banner(bool): Whether to print the path to the ELF binary.
            color(bool): Whether to use colored output.
        """
        ...

    def debug(self):
        r"""
        Open the corefile under a debugger.
        """
        ...

    def disable_nx(self):
        r"""
        Disables NX for the ELF.

        Zeroes out the ``PT_GNU_STACK`` program header ``p_type`` field.
        """
        ...

    def disasm(self, address, n_bytes):
        r"""
        disasm(address, n_bytes) -> str

        Returns a string of disassembled instructions at
        the specified virtual memory address
        """
        ...

    def dynamic_by_tag(self, tag):
        r"""
        dynamic_by_tag(tag) -> tag

        Arguments:
            tag(str): Named ``DT_XXX`` tag (e.g. ``'DT_STRTAB'``).

        Returns:
            :class:`elftools.elf.dynamic.DynamicTag`
        """
        ...

    def dynamic_string(self, offset):
        r"""
        dynamic_string(offset) -> bytes

        Fetches an enumerated string from the ``DT_STRTAB`` table.

        Arguments:
            offset(int): String index

        Returns:
            :class:`str`: String from the table as raw bytes.
        """
        ...

    def dynamic_value_by_tag(self, tag):
        r"""
        dynamic_value_by_tag(tag) -> int

        Retrieve the value from a dynamic tag a la ``DT_XXX``.

        If the tag is missing, returns ``None``.
        """
        ...

    def fit(self, address, *a, **kw):
        r"""
        Writes fitted data into the specified address.

        See: :func:`.packing.fit`
        """
        ...

    def flat(self, address, *a, **kw):
        r"""
        Writes a full array of values to the specified address.

        See: :func:`.packing.flat`
        """
        ...

    def from_assembly(assembly, *a, **kw):
        r"""
        from_assembly(assembly) -> ELF

        Given an assembly listing, return a fully loaded ELF object
        which contains that assembly at its entry point.

        Arguments:

            assembly(str): Assembly language listing
            vma(int): Address of the entry point and the module's base address.

        Example:

            >>> e = ELF.from_assembly('nop; foo: int 0x80', vma = 0x400000)
            >>> e.symbols['foo'] = 0x400001
            >>> e.disasm(e.entry, 1)
            '  400000:       90                      nop'
            >>> e.disasm(e.symbols['foo'], 2)
            '  400001:       cd 80                   int    0x80'
        """
        ...

    def from_bytes(bytes, *a, **kw):
        r"""
        from_bytes(bytes) -> ELF

        Given a sequence of bytes, return a fully loaded ELF object
        which contains those bytes at its entry point.

        Arguments:

            bytes(str): Shellcode byte string
            vma(int): Desired base address for the ELF.

        Example:

            >>> e = ELF.from_bytes(b'\x90\xcd\x80', vma=0xc000)
            >>> print(e.disasm(e.entry, 3))
                c000:       90                      nop
                c001:       cd 80                   int    0x80
        """
        ...

    def get_data(self):
        r"""
        get_data() -> bytes

        Retrieve the raw data from the ELF file.

        >>> bash = ELF(which('bash'))
        >>> fd   = open(which('bash'), 'rb')
        >>> bash.get_data() == fd.read()
        True
        """
        ...

    def get_dwarf_info(self, relocate_dwarf_sections=True):
        r"""
        Return a DWARFInfo object representing the debugging information in
        this file.

        If relocate_dwarf_sections is True, relocations for DWARF sections
        are looked up and applied.
        """
        ...

    def get_ehabi_infos(self):
        r"""
        Generally, shared library and executable contain 1 .ARM.exidx section.
        Object file contains many .ARM.exidx sections.
        So we must traverse every section and filter sections whose type is SHT_ARM_EXIDX.
        """
        ...

    def get_machine_arch(self):
        r"""
        Return the machine architecture, as detected from the ELF header.
        
        """
        ...

    def get_section(self, n):
        r"""
        Get the section at index #n from the file (Section object or a
        subclass)
        """
        ...

    def get_section_by_name(self, name):
        r"""
        Get a section from the file, by name. Return None if no such
        section exists.
        """
        ...

    def get_segment(self, n):
        r"""
        Get the segment at index #n from the file (Segment object)
        
        """
        ...

    def get_segment_for_address(self, address, size=1):
        r"""
        get_segment_for_address(address, size=1) -> Segment

        Given a virtual address described by a ``PT_LOAD`` segment, return the
        first segment which describes the virtual address.  An optional ``size``
        may be provided to ensure the entire range falls into the same segment.

        Arguments:
            address(int): Virtual address to find
            size(int): Number of bytes which must be available after ``address``
                in **both** the file-backed data for the segment, and the memory
                region which is reserved for the data.

        Returns:
            Either returns a :class:`.segments.Segment` object, or ``None``.
        """
        ...

    def get_shstrndx(self):
        r"""
        Find the string table section index for the section header table
        
        """
        ...

    def getenv(self, name):
        r"""
        getenv(name) -> int

        Read an environment variable off the stack, and return its contents.

        Arguments:
            name(str): Name of the environment variable to read.

        Returns:
            :class:`str`: The contents of the environment variable.

        Example:

            >>> elf = ELF.from_assembly(shellcraft.trap())
            >>> io = elf.process(env={'GREETING': 'Hello!'})
            >>> io.wait(1)
            >>> io.corefile.getenv('GREETING')
            b'Hello!'
        """
        ...

    def has_dwarf_info(self):
        r"""
        Check whether this file appears to have debugging information.
        We assume that if it has the .debug_info or .zdebug_info section, it
        has all the other required sections as well.
        """
        ...

    def has_ehabi_info(self):
        r"""
        Check whether this file appears to have arm exception handler index table.
        
        """
        ...

    def iter_sections(self):
        r"""
        Yield all the sections in the file
        
        """
        ...

    def iter_segments(self):
        r"""
        Yield all the segments in the file
        
        """
        ...

    def iter_segments_by_type(self, t):
        r"""
        Yields:
            Segments matching the specified type.
        """
        ...

    def num_sections(self):
        r"""
        Number of sections in the file
        
        """
        ...

    def num_segments(self):
        r"""
        Number of segments in the file
        
        """
        ...

    def offset_to_vaddr(self, offset):
        r"""
        offset_to_vaddr(offset) -> int

        Translates the specified offset to a virtual address.

        Arguments:
            offset(int): Offset to translate

        Returns:
            `int`: Virtual address which corresponds to the file offset, or
            :const:`None`.

        Examples:

            This example shows that regardless of changes to the virtual
            address layout by modifying :attr:`.ELF.address`, the offset
            for any given address doesn't change.

            >>> bash = ELF('/bin/bash')
            >>> bash.address == bash.offset_to_vaddr(0)
            True
            >>> bash.address += 0x123456
            >>> bash.address == bash.offset_to_vaddr(0)
            True
        """
        ...

    def p16(self, address, data, *a, **kw):
        r"""
        Writes a 16-bit integer ``data`` to the specified ``address``
        """
        ...

    def p32(self, address, data, *a, **kw):
        r"""
        Writes a 32-bit integer ``data`` to the specified ``address``
        """
        ...

    def p64(self, address, data, *a, **kw):
        r"""
        Writes a 64-bit integer ``data`` to the specified ``address``
        """
        ...

    def p8(self, address, data, *a, **kw):
        r"""
        Writes a 8-bit integer ``data`` to the specified ``address``
        """
        ...

    def pack(self, address, data, *a, **kw):
        r"""
        Writes a packed integer ``data`` to the specified ``address``
        """
        ...

    def parse_kconfig(self, data):

        ...

    def process(self, argv=[], *a, **kw):
        r"""
        process(argv=[], *a, **kw) -> process

        Execute the binary with :class:`.process`.  Note that ``argv``
        is a list of arguments, and should not include ``argv[0]``.

        Arguments:
            argv(list): List of arguments to the binary
            *args: Extra arguments to :class:`.process`
            **kwargs: Extra arguments to :class:`.process`

        Returns:
            :class:`.process`
        """
        ...

    def read(self, address, count):
        r"""
        read(address, count) -> bytes

        Read data from the specified virtual address

        Arguments:
            address(int): Virtual address to read
            count(int): Number of bytes to read

        Returns:
            A :class:`str` object, or :const:`None`.

        Examples:
            The simplest example is just to read the ELF header.

            >>> bash = ELF(which('bash'))
            >>> bash.read(bash.address, 4)
            b'\x7fELF'

            ELF segments do not have to contain all of the data on-disk
            that gets loaded into memory.

            First, let's create an ELF file has some code in two sections.

            >>> assembly = '''
            ... .section .A,"awx"
            ... .global A
            ... A: nop
            ... .section .B,"awx"
            ... .global B
            ... B: int3
            ... '''
            >>> e = ELF.from_assembly(assembly, vma=False)

            By default, these come right after eachother in memory.

            >>> e.read(e.symbols.A, 2)
            b'\x90\xcc'
            >>> e.symbols.B - e.symbols.A
            1

            Let's move the sections so that B is a little bit further away.

            >>> objcopy = pwnlib.asm._objcopy()
            >>> objcopy += [
            ...     '--change-section-vma', '.B+5',
            ...     '--change-section-lma', '.B+5',
            ...     e.path
            ... ]
            >>> subprocess.check_call(objcopy)
            0

            Now let's re-load the ELF, and check again

            >>> e = ELF(e.path)
            >>> e.symbols.B - e.symbols.A
            6
            >>> e.read(e.symbols.A, 2)
            b'\x90\x00'
            >>> e.read(e.symbols.A, 7)
            b'\x90\x00\x00\x00\x00\x00\xcc'
            >>> e.read(e.symbols.A, 10)
            b'\x90\x00\x00\x00\x00\x00\xcc\x00\x00\x00'

            Everything is relative to the user-selected base address, so moving
            things around keeps everything working.

            >>> e.address += 0x1000
            >>> e.read(e.symbols.A, 10)
            b'\x90\x00\x00\x00\x00\x00\xcc\x00\x00\x00'
        """
        ...

    def save(self, path=None):
        r"""
        Save the ELF to a file

        >>> bash = ELF(which('bash'))
        >>> bash.save('/tmp/bash_copy')
        >>> copy = open('/tmp/bash_copy', 'rb')
        >>> bash = open(which('bash'), 'rb')
        >>> bash.read() == copy.read()
        True
        """
        ...

    def search(self, needle, writable=False, executable=False):
        r"""
        search(needle, writable = False, executable = False) -> generator

        Search the ELF's virtual address space for the specified string.

        Notes:
            Does not search empty space between segments, or uninitialized
            data.  This will only return data that actually exists in the
            ELF file.  Searching for a long string of NULL bytes probably
            won't work.

        Arguments:
            needle(str): String to search for.
            writable(bool): Search only writable sections.
            executable(bool): Search only executable sections.

        Yields:
            An iterator for each virtual address that matches.

        Examples:

            An ELF header starts with the bytes ``\x7fELF``, so we
            sould be able to find it easily.

            >>> bash = ELF('/bin/bash')
            >>> bash.address + 1 == next(bash.search(b'ELF'))
            True

            We can also search for string the binary.

            >>> len(list(bash.search(b'GNU bash'))) > 0
            True

            It is also possible to search for instructions in executable sections.

            >>> binary = ELF.from_assembly('nop; mov eax, 0; jmp esp; ret')
            >>> jmp_addr = next(binary.search(asm('jmp esp'), executable = True))
            >>> binary.read(jmp_addr, 2) == asm('jmp esp')
            True
        """
        ...

    def section(self, name):
        r"""
        section(name) -> bytes

        Gets data for the named section

        Arguments:
            name(str): Name of the section

        Returns:
            :class:`str`: String containing the bytes for that section
        """
        ...

    def string(self, address):
        r"""
        string(address) -> str

        Reads a null-terminated string from the specified ``address``

        Returns:
            A ``str`` with the string contents (NUL terminator is omitted),
            or an empty string if no NUL terminator could be found.
        """
        ...

    def u16(self, address, *a, **kw):
        r"""
        Unpacks an integer from the specified ``address``.
        """
        ...

    def u32(self, address, *a, **kw):
        r"""
        Unpacks an integer from the specified ``address``.
        """
        ...

    def u64(self, address, *a, **kw):
        r"""
        Unpacks an integer from the specified ``address``.
        """
        ...

    def u8(self, address, *a, **kw):
        r"""
        Unpacks an integer from the specified ``address``.
        """
        ...

    def unpack(self, address, *a, **kw):
        r"""
        Unpacks an integer from the specified ``address``.
        """
        ...

    def vaddr_to_offset(self, address):
        r"""
        vaddr_to_offset(address) -> int

        Translates the specified virtual address to a file offset

        Arguments:
            address(int): Virtual address to translate

        Returns:
            int: Offset within the ELF file which corresponds to the address,
            or :const:`None`.

        Examples:
            >>> bash = ELF(which('bash'))
            >>> bash.vaddr_to_offset(bash.address)
            0
            >>> bash.address += 0x123456
            >>> bash.vaddr_to_offset(bash.address)
            0
            >>> bash.vaddr_to_offset(0) is None
            True
        """
        ...

    def write(self, address, data):
        r"""
        Writes data to the specified virtual address

        Arguments:
            address(int): Virtual address to write
            data(str): Bytes to write

        Note:
            This routine does not check the bounds on the write to ensure
            that it stays in the same segment.

        Examples:
          >>> bash = ELF(which('bash'))
          >>> bash.read(bash.address+1, 3)
          b'ELF'
          >>> bash.write(bash.address, b"HELO")
          >>> bash.read(bash.address, 4)
          b'HELO'
        """
        ...

class Corefile (pwnlib.elf.elf.ELF):
    r"""
    Enhances the information available about a corefile (which is an extension
    of the ELF format) by permitting extraction of information about the mapped
    data segments, and register state.

    Registers can be accessed directly, e.g. via ``core_obj.eax`` and enumerated
    via :data:`Corefile.registers`.

    Memory can be accessed directly via :meth:`.read` or :meth:`.write`, and also
    via :meth:`.pack` or :meth:`.unpack` or even :meth:`.string`.

    Arguments:
        core: Path to the core file.  Alternately, may be a :class:`.process` instance,
              and the core file will be located automatically.

    ::

        >>> c = Corefile('./core')
        >>> hex(c.eax)
        '0xfff5f2e0'
        >>> c.registers
        {'eax': 4294308576,
         'ebp': 1633771891,
         'ebx': 4151132160,
         'ecx': 4294311760,
         'edi': 0,
         'edx': 4294308700,
         'eflags': 66050,
         'eip': 1633771892,
         'esi': 0,
         'esp': 4294308656,
         'orig_eax': 4294967295,
         'xcs': 35,
         'xds': 43,
         'xes': 43,
         'xfs': 0,
         'xgs': 99,
         'xss': 43}

    Mappings can be iterated in order via :attr:`Corefile.mappings`.

    ::

        >>> Corefile('./core').mappings
        [Mapping('/home/user/pwntools/crash', start=0x8048000, stop=0x8049000, size=0x1000, flags=0x5, page_offset=0x0),
         Mapping('/home/user/pwntools/crash', start=0x8049000, stop=0x804a000, size=0x1000, flags=0x4, page_offset=0x1),
         Mapping('/home/user/pwntools/crash', start=0x804a000, stop=0x804b000, size=0x1000, flags=0x6, page_offset=0x2),
         Mapping(None, start=0xf7528000, stop=0xf7529000, size=0x1000, flags=0x6, page_offset=0x0),
         Mapping('/lib/i386-linux-gnu/libc-2.19.so', start=0xf7529000, stop=0xf76d1000, size=0x1a8000, flags=0x5, page_offset=0x0),
         Mapping('/lib/i386-linux-gnu/libc-2.19.so', start=0xf76d1000, stop=0xf76d2000, size=0x1000, flags=0x0, page_offset=0x1a8),
         Mapping('/lib/i386-linux-gnu/libc-2.19.so', start=0xf76d2000, stop=0xf76d4000, size=0x2000, flags=0x4, page_offset=0x1a9),
         Mapping('/lib/i386-linux-gnu/libc-2.19.so', start=0xf76d4000, stop=0xf76d5000, size=0x1000, flags=0x6, page_offset=0x1aa),
         Mapping(None, start=0xf76d5000, stop=0xf76d8000, size=0x3000, flags=0x6, page_offset=0x0),
         Mapping(None, start=0xf76ef000, stop=0xf76f1000, size=0x2000, flags=0x6, page_offset=0x0),
         Mapping('[vdso]', start=0xf76f1000, stop=0xf76f2000, size=0x1000, flags=0x5, page_offset=0x0),
         Mapping('/lib/i386-linux-gnu/ld-2.19.so', start=0xf76f2000, stop=0xf7712000, size=0x20000, flags=0x5, page_offset=0x0),
         Mapping('/lib/i386-linux-gnu/ld-2.19.so', start=0xf7712000, stop=0xf7713000, size=0x1000, flags=0x4, page_offset=0x20),
         Mapping('/lib/i386-linux-gnu/ld-2.19.so', start=0xf7713000, stop=0xf7714000, size=0x1000, flags=0x6, page_offset=0x21),
         Mapping('[stack]', start=0xfff3e000, stop=0xfff61000, size=0x23000, flags=0x6, page_offset=0x0)]

    Examples:

        Let's build an example binary which should eat ``R0=0xdeadbeef``
        and ``PC=0xcafebabe``.

        If we run the binary and then wait for it to exit, we can get its
        core file.

        >>> context.clear(arch='arm')
        >>> shellcode = shellcraft.mov('r0', 0xdeadbeef)
        >>> shellcode += shellcraft.mov('r1', 0xcafebabe)
        >>> shellcode += 'bx r1'
        >>> address = 0x41410000
        >>> elf = ELF.from_assembly(shellcode, vma=address)
        >>> io = elf.process(env={'HELLO': 'WORLD'})
        >>> io.poll(block=True)
        -11

        You can specify a full path a la ``Corefile('/path/to/core')``,
        but you can also just access the :attr:`.process.corefile` attribute.

        There's a lot of behind-the-scenes logic to locate the corefile for
        a given process, but it's all handled transparently by Pwntools.

        >>> core = io.corefile

        The core file has a :attr:`exe` property, which is a :class:`.Mapping`
        object.  Each mapping can be accessed with virtual addresses via subscript, or
        contents can be examined via the :attr:`.Mapping.data` attribute.

        >>> core.exe # doctest: +ELLIPSIS
        Mapping('/.../step3', start=..., stop=..., size=0x1000, flags=0x..., page_offset=...)
        >>> hex(core.exe.address)
        '0x41410000'

        The core file also has registers which can be accessed direclty.
        Pseudo-registers :attr:`pc` and :attr:`sp` are available on all architectures,
        to make writing architecture-agnostic code more simple.
        If this were an amd64 corefile, we could access e.g. ``core.rax``.

        >>> core.pc == 0xcafebabe
        True
        >>> core.r0 == 0xdeadbeef
        True
        >>> core.sp == core.r13
        True

        We may not always know which signal caused the core dump, or what address
        caused a segmentation fault.  Instead of accessing registers directly, we
        can also extract this information from the core dump via :attr:`fault_addr`
        and :attr:`signal`.

        On QEMU-generated core dumps, this information is unavailable, so we
        substitute the value of PC.  In our example, that's correct anyway.

        >>> core.fault_addr == 0xcafebabe
        True
        >>> core.signal
        11

        Core files can also be generated from running processes.
        This requires GDB to be installed, and can only be done with native processes.
        Getting a "complete" corefile requires GDB 7.11 or better.

        >>> elf = ELF(which('bash-static'))
        >>> context.clear(binary=elf)
        >>> env = dict(os.environ)
        >>> env['HELLO'] = 'WORLD'
        >>> io = process(elf.path, env=env)
        >>> io.sendline('echo hello')
        >>> io.recvline()
        b'hello\n'

        The process is still running, but accessing its :attr:`.process.corefile` property
        automatically invokes GDB to attach and dump a corefile.

        >>> core = io.corefile

        The corefile can be inspected and read from, and even exposes various mappings

        >>> core.exe # doctest: +ELLIPSIS
        Mapping('.../bin/bash-static', start=..., stop=..., size=..., flags=..., page_offset=...)
        >>> core.exe.data[0:4]
        b'\x7fELF'

        It also supports all of the features of :class:`ELF`, so you can :meth:`.read`
        or :meth:`.write` or even the helpers like :meth:`.pack` or :meth:`.unpack`.

        Don't forget to call :meth:`.ELF.save` to save the changes to disk.

        >>> core.read(elf.address, 4)
        b'\x7fELF'
        >>> core.pack(core.sp, 0xdeadbeef)
        >>> core.save()

        Let's re-load it as a new :attr:`Corefile` object and have a look!

        >>> core2 = Corefile(core.path)
        >>> hex(core2.unpack(core2.sp))
        '0xdeadbeef'

        Various other mappings are available by name, for the first segment of:

        * :attr:`.exe` the executable
        * :attr:`.libc` the loaded libc, if any
        * :attr:`.stack` the stack mapping
        * :attr:`.vvar`
        * :attr:`.vdso`
        * :attr:`.vsyscall`

        On Linux, 32-bit Intel binaries should have a VDSO section via :attr:`vdso`.  
        Since our ELF is statically linked, there is no libc which gets mapped.

        >>> core.vdso.data[:4]
        b'\x7fELF'
        >>> core.libc

        But if we dump a corefile from a dynamically-linked binary, the :attr:`.libc`
        will be loaded.

        >>> process('bash').corefile.libc # doctest: +ELLIPSIS
        Mapping('/.../libc-....so', start=0x..., stop=0x..., size=0x..., flags=..., page_offset=...)

        The corefile also contains a :attr:`.stack` property, which gives
        us direct access to the stack contents.  On Linux, the very top of the stack
        should contain two pointer-widths of NULL bytes, preceded by the NULL-
        terminated path to the executable (as passed via the first arg to ``execve``).

        >>> core.stack # doctest: +ELLIPSIS
        Mapping('[stack]', start=0x..., stop=0x..., size=0x..., flags=0x6, page_offset=0x0)

        When creating a process, the kernel puts the absolute path of the binary and some
        padding bytes at the end of the stack.  We can look at those by looking at 
        ``core.stack.data``.

        >>> size = len('/bin/bash-static') + 8
        >>> core.stack.data[-size:]
        b'bin/bash-static\x00\x00\x00\x00\x00\x00\x00\x00\x00'

        We can also directly access the environment variables and arguments, via
        :attr:`.argc`, :attr:`.argv`, and :attr:`.env`.

        >>> 'HELLO' in core.env
        True
        >>> core.string(core.env['HELLO'])
        b'WORLD'
        >>> core.getenv('HELLO')
        b'WORLD'
        >>> core.argc
        1
        >>> core.argv[0] in core.stack
        True
        >>> core.string(core.argv[0]) # doctest: +ELLIPSIS
        b'.../bin/bash-static'

        Corefiles can also be pulled from remote machines via SSH!

        >>> s = ssh(user='travis', host='example.pwnme', password='demopass')
        >>> _ = s.set_working_directory()
        >>> elf = ELF.from_assembly(shellcraft.trap())
        >>> path = s.upload(elf.path)
        >>> _ =s.chmod('+x', path)
        >>> io = s.process(path)
        >>> io.wait(1)
        -1
        >>> io.corefile.signal == signal.SIGTRAP # doctest: +SKIP
        True

        Make sure fault_addr synthesis works for amd64 on ret.

        >>> context.clear(arch='amd64')
        >>> elf = ELF.from_assembly('push 1234; ret')
        >>> io = elf.process()
        >>> io.wait(1)
        >>> io.corefile.fault_addr
        1234

        Corefile.getenv() works correctly, even if the environment variable's
        value contains embedded '='. Corefile is able to find the stack, even
        if the stack pointer doesn't point at the stack.

        >>> elf = ELF.from_assembly(shellcraft.crash())
        >>> io = elf.process(env={'FOO': 'BAR=BAZ'})
        >>> io.wait(1)
        >>> core = io.corefile
        >>> core.getenv('FOO')
        b'BAR=BAZ'
        >>> core.sp == 0
        True
        >>> core.sp in core.stack
        False

        Corefile gracefully handles the stack being filled with garbage, including
        argc / argv / envp being overwritten.

        >>> context.clear(arch='i386')
        >>> assembly = '''
        ... LOOP:
        ...   mov dword ptr [esp], 0x41414141
        ...   pop eax
        ...   jmp LOOP
        ... '''
        >>> elf = ELF.from_assembly(assembly)
        >>> io = elf.process()
        >>> io.wait(2)
        >>> core = io.corefile
        [!] End of the stack is corrupted, skipping stack parsing (got: 41414141)
        >>> core.argc, core.argv, core.env
        (0, [], {})
        >>> core.stack.data.endswith(b'AAAA')
        True
        >>> core.fault_addr == core.sp
        True
    """
    def __getattr__(self, attribute):

        ...

    def __getitem__(self, name):
        r"""
        Implement dict-like access to header entries
        
        """
        ...

    def __init__(self, *a, **kw):
        r"""
        Initialize self.  See help(type(self)) for accurate signature.
        """
        ...

    def __repr__(self):
        r"""
        Return repr(self).
        """
        ...

    def _decompress_dwarf_section(section):
        r"""
        Returns the uncompressed contents of the provided DWARF section.
        
        """
        ...

    def _describe(self):

        ...

    def _describe_core(self):

        ...

    def _get_section_header(self, n):
        r"""
        Find the header of section #n, parse it and return the struct
        
        """
        ...

    def _get_section_header_stringtable(self):
        r"""
        Get the string table section corresponding to the section header
        table.
        """
        ...

    def _get_section_name(self, section_header):
        r"""
        Given a section header, find this section's name in the file's
        string table
        """
        ...

    def _get_segment_header(self, n):
        r"""
        Find the header of segment #n, parse it and return the struct
        
        """
        ...

    def _identify_file(self):
        r"""
        Verify the ELF file and identify its class and endianness.
        
        """
        ...

    def _load_mappings(self):

        ...

    def _make_elf_hash_section(self, section_header, name):

        ...

    def _make_gnu_hash_section(self, section_header, name):

        ...

    def _make_gnu_verdef_section(self, section_header, name):
        r"""
        Create a GNUVerDefSection
        
        """
        ...

    def _make_gnu_verneed_section(self, section_header, name):
        r"""
        Create a GNUVerNeedSection
        
        """
        ...

    def _make_gnu_versym_section(self, section_header, name):
        r"""
        Create a GNUVerSymSection
        
        """
        ...

    def _make_section(self, section_header):
        r"""
        Create a section object of the appropriate type
        
        """
        ...

    def _make_segment(self, segment_header):
        r"""
        Create a Segment object of the appropriate type
        
        """
        ...

    def _make_sunwsyminfo_table_section(self, section_header, name):
        r"""
        Create a SUNWSyminfoTableSection
        
        """
        ...

    def _make_symbol_table_index_section(self, section_header, name):
        r"""
        Create a SymbolTableIndexSection object
        
        """
        ...

    def _make_symbol_table_section(self, section_header, name):
        r"""
        Create a SymbolTableSection
        
        """
        ...

    def _parse_auxv(self, note):

        ...

    def _parse_elf_header(self):
        r"""
        Parses the ELF file header and assigns the result to attributes
        of this object.
        """
        ...

    def _parse_nt_file(self, note):

        ...

    def _parse_stack(self):

        ...

    def _patch_elf_and_read_maps(self):
        r"""
        patch_elf_and_read_maps(self) -> dict

        Read ``/proc/self/maps`` as if the ELF were executing.

        This is done by replacing the code at the entry point with shellcode which
        dumps ``/proc/self/maps`` and exits, and **actually executing the binary**.

        Returns:
            A ``dict`` mapping file paths to the lowest address they appear at.
            Does not do any translation for e.g. QEMU emulation, the raw results
            are returned.

            If there is not enough space to inject the shellcode in the segment
            which contains the entry point, returns ``{}``.

        Doctests:

            These tests are just to ensure that our shellcode is correct.

            >>> for arch in CAT_PROC_MAPS_EXIT:
            ...   context.clear()
            ...   with context.local(arch=arch):
            ...     sc = shellcraft.cat("/proc/self/maps")
            ...     sc += shellcraft.exit()
            ...     sc = asm(sc)
            ...     sc = enhex(sc)
            ...     assert sc == CAT_PROC_MAPS_EXIT[arch]
        """
        ...

    def _populate_functions(self):
        r"""
        Builds a dict of 'functions' (i.e. symbols of type 'STT_FUNC')
        by function name that map to a tuple consisting of the func address and size
        in bytes.
        """
        ...

    def _populate_got(*a):
        r"""
        Loads the symbols for all relocations
        """
        ...

    def _populate_kernel_version(self):

        ...

    def _populate_libraries(self):
        r"""
        >>> from os.path import exists
        >>> bash = ELF(which('bash'))
        >>> all(map(exists, bash.libs.keys()))
        True
        >>> any(map(lambda x: 'libc' in x, bash.libs.keys()))
        True
        """
        ...

    def _populate_memory(self):

        ...

    def _populate_mips_got(self):

        ...

    def _populate_plt(*a):
        r"""
        Loads the PLT symbols

        >>> path = pwnlib.data.elf.path
        >>> for test in glob(os.path.join(path, 'test-*')):
        ...     test = ELF(test)
        ...     assert '__stack_chk_fail' in test.got, test
        ...     if test.arch != 'ppc':
        ...         assert '__stack_chk_fail' in test.plt, test
        """
        ...

    def _populate_symbols(self):
        r"""
        >>> bash = ELF(which('bash'))
        >>> bash.symbols['_start'] == bash.entry
        True
        """
        ...

    def _populate_synthetic_symbols(self):
        r"""
        Adds symbols from the GOT and PLT to the symbols dictionary.

        Does not overwrite any existing symbols, and prefers PLT symbols.

        Synthetic plt.xxx and got.xxx symbols are added for each PLT and
        GOT entry, respectively.

        Example:bash.

            >>> bash = ELF(which('bash'))
            >>> bash.symbols.wcscmp == bash.plt.wcscmp
            True
            >>> bash.symbols.wcscmp == bash.symbols.plt.wcscmp
            True
            >>> bash.symbols.stdin  == bash.got.stdin
            True
            >>> bash.symbols.stdin  == bash.symbols.got.stdin
            True
        """
        ...

    def _read_dwarf_section(self, section, relocate_dwarf_sections):
        r"""
        Read the contents of a DWARF section from the stream and return a
        DebugSectionDescriptor. Apply relocations if asked to.
        """
        ...

    def _section_offset(self, n):
        r"""
        Compute the offset of section #n in the file
        
        """
        ...

    def _segment_offset(self, n):
        r"""
        Compute the offset of segment #n in the file
        
        """
        ...

    def _update_args(self, kw):

        ...

    def address_offsets(self, start, size=1):
        r"""
        Yield a file offset for each ELF segment containing a memory region.

        A memory region is defined by the range [start...start+size). The
        offset of the region is yielded.
        """
        ...

    def asm(self, address, assembly):
        r"""
        asm(address, assembly)

        Assembles the specified instructions and inserts them
        into the ELF at the specified address.

        This modifies the ELF in-place.
        The resulting binary can be saved with :meth:`.ELF.save`
        """
        ...

    def bss(self, offset=0):
        r"""
        bss(offset=0) -> int

        Returns:
            Address of the ``.bss`` section, plus the specified offset.
        """
        ...

    def checksec(self, banner=True, color=True):
        r"""
        checksec(banner=True, color=True)

        Prints out information in the binary, similar to ``checksec.sh``.

        Arguments:
            banner(bool): Whether to print the path to the ELF binary.
            color(bool): Whether to use colored output.
        """
        ...

    def debug(self):
        r"""
        Open the corefile under a debugger.
        """
        ...

    def disable_nx(self):
        r"""
        Disables NX for the ELF.

        Zeroes out the ``PT_GNU_STACK`` program header ``p_type`` field.
        """
        ...

    def disasm(self, address, n_bytes):
        r"""
        disasm(address, n_bytes) -> str

        Returns a string of disassembled instructions at
        the specified virtual memory address
        """
        ...

    def dynamic_by_tag(self, tag):
        r"""
        dynamic_by_tag(tag) -> tag

        Arguments:
            tag(str): Named ``DT_XXX`` tag (e.g. ``'DT_STRTAB'``).

        Returns:
            :class:`elftools.elf.dynamic.DynamicTag`
        """
        ...

    def dynamic_string(self, offset):
        r"""
        dynamic_string(offset) -> bytes

        Fetches an enumerated string from the ``DT_STRTAB`` table.

        Arguments:
            offset(int): String index

        Returns:
            :class:`str`: String from the table as raw bytes.
        """
        ...

    def dynamic_value_by_tag(self, tag):
        r"""
        dynamic_value_by_tag(tag) -> int

        Retrieve the value from a dynamic tag a la ``DT_XXX``.

        If the tag is missing, returns ``None``.
        """
        ...

    def fit(self, address, *a, **kw):
        r"""
        Writes fitted data into the specified address.

        See: :func:`.packing.fit`
        """
        ...

    def flat(self, address, *a, **kw):
        r"""
        Writes a full array of values to the specified address.

        See: :func:`.packing.flat`
        """
        ...

    def from_assembly(assembly, *a, **kw):
        r"""
        from_assembly(assembly) -> ELF

        Given an assembly listing, return a fully loaded ELF object
        which contains that assembly at its entry point.

        Arguments:

            assembly(str): Assembly language listing
            vma(int): Address of the entry point and the module's base address.

        Example:

            >>> e = ELF.from_assembly('nop; foo: int 0x80', vma = 0x400000)
            >>> e.symbols['foo'] = 0x400001
            >>> e.disasm(e.entry, 1)
            '  400000:       90                      nop'
            >>> e.disasm(e.symbols['foo'], 2)
            '  400001:       cd 80                   int    0x80'
        """
        ...

    def from_bytes(bytes, *a, **kw):
        r"""
        from_bytes(bytes) -> ELF

        Given a sequence of bytes, return a fully loaded ELF object
        which contains those bytes at its entry point.

        Arguments:

            bytes(str): Shellcode byte string
            vma(int): Desired base address for the ELF.

        Example:

            >>> e = ELF.from_bytes(b'\x90\xcd\x80', vma=0xc000)
            >>> print(e.disasm(e.entry, 3))
                c000:       90                      nop
                c001:       cd 80                   int    0x80
        """
        ...

    def get_data(self):
        r"""
        get_data() -> bytes

        Retrieve the raw data from the ELF file.

        >>> bash = ELF(which('bash'))
        >>> fd   = open(which('bash'), 'rb')
        >>> bash.get_data() == fd.read()
        True
        """
        ...

    def get_dwarf_info(self, relocate_dwarf_sections=True):
        r"""
        Return a DWARFInfo object representing the debugging information in
        this file.

        If relocate_dwarf_sections is True, relocations for DWARF sections
        are looked up and applied.
        """
        ...

    def get_ehabi_infos(self):
        r"""
        Generally, shared library and executable contain 1 .ARM.exidx section.
        Object file contains many .ARM.exidx sections.
        So we must traverse every section and filter sections whose type is SHT_ARM_EXIDX.
        """
        ...

    def get_machine_arch(self):
        r"""
        Return the machine architecture, as detected from the ELF header.
        
        """
        ...

    def get_section(self, n):
        r"""
        Get the section at index #n from the file (Section object or a
        subclass)
        """
        ...

    def get_section_by_name(self, name):
        r"""
        Get a section from the file, by name. Return None if no such
        section exists.
        """
        ...

    def get_segment(self, n):
        r"""
        Get the segment at index #n from the file (Segment object)
        
        """
        ...

    def get_segment_for_address(self, address, size=1):
        r"""
        get_segment_for_address(address, size=1) -> Segment

        Given a virtual address described by a ``PT_LOAD`` segment, return the
        first segment which describes the virtual address.  An optional ``size``
        may be provided to ensure the entire range falls into the same segment.

        Arguments:
            address(int): Virtual address to find
            size(int): Number of bytes which must be available after ``address``
                in **both** the file-backed data for the segment, and the memory
                region which is reserved for the data.

        Returns:
            Either returns a :class:`.segments.Segment` object, or ``None``.
        """
        ...

    def get_shstrndx(self):
        r"""
        Find the string table section index for the section header table
        
        """
        ...

    def getenv(self, name):
        r"""
        getenv(name) -> int

        Read an environment variable off the stack, and return its contents.

        Arguments:
            name(str): Name of the environment variable to read.

        Returns:
            :class:`str`: The contents of the environment variable.

        Example:

            >>> elf = ELF.from_assembly(shellcraft.trap())
            >>> io = elf.process(env={'GREETING': 'Hello!'})
            >>> io.wait(1)
            >>> io.corefile.getenv('GREETING')
            b'Hello!'
        """
        ...

    def has_dwarf_info(self):
        r"""
        Check whether this file appears to have debugging information.
        We assume that if it has the .debug_info or .zdebug_info section, it
        has all the other required sections as well.
        """
        ...

    def has_ehabi_info(self):
        r"""
        Check whether this file appears to have arm exception handler index table.
        
        """
        ...

    def iter_sections(self):
        r"""
        Yield all the sections in the file
        
        """
        ...

    def iter_segments(self):
        r"""
        Yield all the segments in the file
        
        """
        ...

    def iter_segments_by_type(self, t):
        r"""
        Yields:
            Segments matching the specified type.
        """
        ...

    def num_sections(self):
        r"""
        Number of sections in the file
        
        """
        ...

    def num_segments(self):
        r"""
        Number of segments in the file
        
        """
        ...

    def offset_to_vaddr(self, offset):
        r"""
        offset_to_vaddr(offset) -> int

        Translates the specified offset to a virtual address.

        Arguments:
            offset(int): Offset to translate

        Returns:
            `int`: Virtual address which corresponds to the file offset, or
            :const:`None`.

        Examples:

            This example shows that regardless of changes to the virtual
            address layout by modifying :attr:`.ELF.address`, the offset
            for any given address doesn't change.

            >>> bash = ELF('/bin/bash')
            >>> bash.address == bash.offset_to_vaddr(0)
            True
            >>> bash.address += 0x123456
            >>> bash.address == bash.offset_to_vaddr(0)
            True
        """
        ...

    def p16(self, address, data, *a, **kw):
        r"""
        Writes a 16-bit integer ``data`` to the specified ``address``
        """
        ...

    def p32(self, address, data, *a, **kw):
        r"""
        Writes a 32-bit integer ``data`` to the specified ``address``
        """
        ...

    def p64(self, address, data, *a, **kw):
        r"""
        Writes a 64-bit integer ``data`` to the specified ``address``
        """
        ...

    def p8(self, address, data, *a, **kw):
        r"""
        Writes a 8-bit integer ``data`` to the specified ``address``
        """
        ...

    def pack(self, address, data, *a, **kw):
        r"""
        Writes a packed integer ``data`` to the specified ``address``
        """
        ...

    def parse_kconfig(self, data):

        ...

    def process(self, argv=[], *a, **kw):
        r"""
        process(argv=[], *a, **kw) -> process

        Execute the binary with :class:`.process`.  Note that ``argv``
        is a list of arguments, and should not include ``argv[0]``.

        Arguments:
            argv(list): List of arguments to the binary
            *args: Extra arguments to :class:`.process`
            **kwargs: Extra arguments to :class:`.process`

        Returns:
            :class:`.process`
        """
        ...

    def read(self, address, count):
        r"""
        read(address, count) -> bytes

        Read data from the specified virtual address

        Arguments:
            address(int): Virtual address to read
            count(int): Number of bytes to read

        Returns:
            A :class:`str` object, or :const:`None`.

        Examples:
            The simplest example is just to read the ELF header.

            >>> bash = ELF(which('bash'))
            >>> bash.read(bash.address, 4)
            b'\x7fELF'

            ELF segments do not have to contain all of the data on-disk
            that gets loaded into memory.

            First, let's create an ELF file has some code in two sections.

            >>> assembly = '''
            ... .section .A,"awx"
            ... .global A
            ... A: nop
            ... .section .B,"awx"
            ... .global B
            ... B: int3
            ... '''
            >>> e = ELF.from_assembly(assembly, vma=False)

            By default, these come right after eachother in memory.

            >>> e.read(e.symbols.A, 2)
            b'\x90\xcc'
            >>> e.symbols.B - e.symbols.A
            1

            Let's move the sections so that B is a little bit further away.

            >>> objcopy = pwnlib.asm._objcopy()
            >>> objcopy += [
            ...     '--change-section-vma', '.B+5',
            ...     '--change-section-lma', '.B+5',
            ...     e.path
            ... ]
            >>> subprocess.check_call(objcopy)
            0

            Now let's re-load the ELF, and check again

            >>> e = ELF(e.path)
            >>> e.symbols.B - e.symbols.A
            6
            >>> e.read(e.symbols.A, 2)
            b'\x90\x00'
            >>> e.read(e.symbols.A, 7)
            b'\x90\x00\x00\x00\x00\x00\xcc'
            >>> e.read(e.symbols.A, 10)
            b'\x90\x00\x00\x00\x00\x00\xcc\x00\x00\x00'

            Everything is relative to the user-selected base address, so moving
            things around keeps everything working.

            >>> e.address += 0x1000
            >>> e.read(e.symbols.A, 10)
            b'\x90\x00\x00\x00\x00\x00\xcc\x00\x00\x00'
        """
        ...

    def save(self, path=None):
        r"""
        Save the ELF to a file

        >>> bash = ELF(which('bash'))
        >>> bash.save('/tmp/bash_copy')
        >>> copy = open('/tmp/bash_copy', 'rb')
        >>> bash = open(which('bash'), 'rb')
        >>> bash.read() == copy.read()
        True
        """
        ...

    def search(self, needle, writable=False, executable=False):
        r"""
        search(needle, writable = False, executable = False) -> generator

        Search the ELF's virtual address space for the specified string.

        Notes:
            Does not search empty space between segments, or uninitialized
            data.  This will only return data that actually exists in the
            ELF file.  Searching for a long string of NULL bytes probably
            won't work.

        Arguments:
            needle(str): String to search for.
            writable(bool): Search only writable sections.
            executable(bool): Search only executable sections.

        Yields:
            An iterator for each virtual address that matches.

        Examples:

            An ELF header starts with the bytes ``\x7fELF``, so we
            sould be able to find it easily.

            >>> bash = ELF('/bin/bash')
            >>> bash.address + 1 == next(bash.search(b'ELF'))
            True

            We can also search for string the binary.

            >>> len(list(bash.search(b'GNU bash'))) > 0
            True

            It is also possible to search for instructions in executable sections.

            >>> binary = ELF.from_assembly('nop; mov eax, 0; jmp esp; ret')
            >>> jmp_addr = next(binary.search(asm('jmp esp'), executable = True))
            >>> binary.read(jmp_addr, 2) == asm('jmp esp')
            True
        """
        ...

    def section(self, name):
        r"""
        section(name) -> bytes

        Gets data for the named section

        Arguments:
            name(str): Name of the section

        Returns:
            :class:`str`: String containing the bytes for that section
        """
        ...

    def string(self, address):
        r"""
        string(address) -> str

        Reads a null-terminated string from the specified ``address``

        Returns:
            A ``str`` with the string contents (NUL terminator is omitted),
            or an empty string if no NUL terminator could be found.
        """
        ...

    def u16(self, address, *a, **kw):
        r"""
        Unpacks an integer from the specified ``address``.
        """
        ...

    def u32(self, address, *a, **kw):
        r"""
        Unpacks an integer from the specified ``address``.
        """
        ...

    def u64(self, address, *a, **kw):
        r"""
        Unpacks an integer from the specified ``address``.
        """
        ...

    def u8(self, address, *a, **kw):
        r"""
        Unpacks an integer from the specified ``address``.
        """
        ...

    def unpack(self, address, *a, **kw):
        r"""
        Unpacks an integer from the specified ``address``.
        """
        ...

    def vaddr_to_offset(self, address):
        r"""
        vaddr_to_offset(address) -> int

        Translates the specified virtual address to a file offset

        Arguments:
            address(int): Virtual address to translate

        Returns:
            int: Offset within the ELF file which corresponds to the address,
            or :const:`None`.

        Examples:
            >>> bash = ELF(which('bash'))
            >>> bash.vaddr_to_offset(bash.address)
            0
            >>> bash.address += 0x123456
            >>> bash.vaddr_to_offset(bash.address)
            0
            >>> bash.vaddr_to_offset(0) is None
            True
        """
        ...

    def write(self, address, data):
        r"""
        Writes data to the specified virtual address

        Arguments:
            address(int): Virtual address to write
            data(str): Bytes to write

        Note:
            This routine does not check the bounds on the write to ensure
            that it stays in the same segment.

        Examples:
          >>> bash = ELF(which('bash'))
          >>> bash.read(bash.address+1, 3)
          b'ELF'
          >>> bash.write(bash.address, b"HELO")
          >>> bash.read(bash.address, 4)
          b'HELO'
        """
        ...


import pwnlib.elf.elf

class ELF (elftools.elf.elffile.ELFFile):
    r"""
    Encapsulates information about an ELF file.

    Example:

        .. code-block:: python

           >>> bash = ELF(which('bash'))
           >>> hex(bash.symbols['read'])
           0x41dac0
           >>> hex(bash.plt['read'])
           0x41dac0
           >>> u32(bash.read(bash.got['read'], 4))
           0x41dac6
           >>> print(bash.disasm(bash.plt.read, 16))
           0:   ff 25 1a 18 2d 00       jmp    QWORD PTR [rip+0x2d181a]        # 0x2d1820
           6:   68 59 00 00 00          push   0x59
           b:   e9 50 fa ff ff          jmp    0xfffffffffffffa60
    """
    def __getitem__(self, name):
        r"""
        Implement dict-like access to header entries
        
        """
        ...

    def __init__(self, path, checksec=True):
        r"""
        Initialize self.  See help(type(self)) for accurate signature.
        """
        ...

    def __repr__(self):
        r"""
        Return repr(self).
        """
        ...

    def _decompress_dwarf_section(section):
        r"""
        Returns the uncompressed contents of the provided DWARF section.
        
        """
        ...

    def _describe(self, *a, **kw):

        ...

    def _get_section_header(self, n):
        r"""
        Find the header of section #n, parse it and return the struct
        
        """
        ...

    def _get_section_header_stringtable(self):
        r"""
        Get the string table section corresponding to the section header
        table.
        """
        ...

    def _get_section_name(self, section_header):
        r"""
        Given a section header, find this section's name in the file's
        string table
        """
        ...

    def _get_segment_header(self, n):
        r"""
        Find the header of segment #n, parse it and return the struct
        
        """
        ...

    def _identify_file(self):
        r"""
        Verify the ELF file and identify its class and endianness.
        
        """
        ...

    def _make_elf_hash_section(self, section_header, name):

        ...

    def _make_gnu_hash_section(self, section_header, name):

        ...

    def _make_gnu_verdef_section(self, section_header, name):
        r"""
        Create a GNUVerDefSection
        
        """
        ...

    def _make_gnu_verneed_section(self, section_header, name):
        r"""
        Create a GNUVerNeedSection
        
        """
        ...

    def _make_gnu_versym_section(self, section_header, name):
        r"""
        Create a GNUVerSymSection
        
        """
        ...

    def _make_section(self, section_header):
        r"""
        Create a section object of the appropriate type
        
        """
        ...

    def _make_segment(self, segment_header):
        r"""
        Create a Segment object of the appropriate type
        
        """
        ...

    def _make_sunwsyminfo_table_section(self, section_header, name):
        r"""
        Create a SUNWSyminfoTableSection
        
        """
        ...

    def _make_symbol_table_index_section(self, section_header, name):
        r"""
        Create a SymbolTableIndexSection object
        
        """
        ...

    def _make_symbol_table_section(self, section_header, name):
        r"""
        Create a SymbolTableSection
        
        """
        ...

    def _parse_elf_header(self):
        r"""
        Parses the ELF file header and assigns the result to attributes
        of this object.
        """
        ...

    def _patch_elf_and_read_maps(self):
        r"""
        patch_elf_and_read_maps(self) -> dict

        Read ``/proc/self/maps`` as if the ELF were executing.

        This is done by replacing the code at the entry point with shellcode which
        dumps ``/proc/self/maps`` and exits, and **actually executing the binary**.

        Returns:
            A ``dict`` mapping file paths to the lowest address they appear at.
            Does not do any translation for e.g. QEMU emulation, the raw results
            are returned.

            If there is not enough space to inject the shellcode in the segment
            which contains the entry point, returns ``{}``.

        Doctests:

            These tests are just to ensure that our shellcode is correct.

            >>> for arch in CAT_PROC_MAPS_EXIT:
            ...   context.clear()
            ...   with context.local(arch=arch):
            ...     sc = shellcraft.cat("/proc/self/maps")
            ...     sc += shellcraft.exit()
            ...     sc = asm(sc)
            ...     sc = enhex(sc)
            ...     assert sc == CAT_PROC_MAPS_EXIT[arch]
        """
        ...

    def _populate_functions(self):
        r"""
        Builds a dict of 'functions' (i.e. symbols of type 'STT_FUNC')
        by function name that map to a tuple consisting of the func address and size
        in bytes.
        """
        ...

    def _populate_got(self):
        r"""
        Loads the symbols for all relocations
        """
        ...

    def _populate_kernel_version(self):

        ...

    def _populate_libraries(self):
        r"""
        >>> from os.path import exists
        >>> bash = ELF(which('bash'))
        >>> all(map(exists, bash.libs.keys()))
        True
        >>> any(map(lambda x: 'libc' in x, bash.libs.keys()))
        True
        """
        ...

    def _populate_memory(self):

        ...

    def _populate_mips_got(self):

        ...

    def _populate_plt(self):
        r"""
        Loads the PLT symbols

        >>> path = pwnlib.data.elf.path
        >>> for test in glob(os.path.join(path, 'test-*')):
        ...     test = ELF(test)
        ...     assert '__stack_chk_fail' in test.got, test
        ...     if test.arch != 'ppc':
        ...         assert '__stack_chk_fail' in test.plt, test
        """
        ...

    def _populate_symbols(self):
        r"""
        >>> bash = ELF(which('bash'))
        >>> bash.symbols['_start'] == bash.entry
        True
        """
        ...

    def _populate_synthetic_symbols(self):
        r"""
        Adds symbols from the GOT and PLT to the symbols dictionary.

        Does not overwrite any existing symbols, and prefers PLT symbols.

        Synthetic plt.xxx and got.xxx symbols are added for each PLT and
        GOT entry, respectively.

        Example:bash.

            >>> bash = ELF(which('bash'))
            >>> bash.symbols.wcscmp == bash.plt.wcscmp
            True
            >>> bash.symbols.wcscmp == bash.symbols.plt.wcscmp
            True
            >>> bash.symbols.stdin  == bash.got.stdin
            True
            >>> bash.symbols.stdin  == bash.symbols.got.stdin
            True
        """
        ...

    def _read_dwarf_section(self, section, relocate_dwarf_sections):
        r"""
        Read the contents of a DWARF section from the stream and return a
        DebugSectionDescriptor. Apply relocations if asked to.
        """
        ...

    def _section_offset(self, n):
        r"""
        Compute the offset of section #n in the file
        
        """
        ...

    def _segment_offset(self, n):
        r"""
        Compute the offset of segment #n in the file
        
        """
        ...

    def _update_args(self, kw):

        ...

    def address_offsets(self, start, size=1):
        r"""
        Yield a file offset for each ELF segment containing a memory region.

        A memory region is defined by the range [start...start+size). The
        offset of the region is yielded.
        """
        ...

    def asm(self, address, assembly):
        r"""
        asm(address, assembly)

        Assembles the specified instructions and inserts them
        into the ELF at the specified address.

        This modifies the ELF in-place.
        The resulting binary can be saved with :meth:`.ELF.save`
        """
        ...

    def bss(self, offset=0):
        r"""
        bss(offset=0) -> int

        Returns:
            Address of the ``.bss`` section, plus the specified offset.
        """
        ...

    def checksec(self, banner=True, color=True):
        r"""
        checksec(banner=True, color=True)

        Prints out information in the binary, similar to ``checksec.sh``.

        Arguments:
            banner(bool): Whether to print the path to the ELF binary.
            color(bool): Whether to use colored output.
        """
        ...

    def debug(self, argv=[], *a, **kw):
        r"""
        debug(argv=[], *a, **kw) -> tube

        Debug the ELF with :func:`.gdb.debug`.

        Arguments:
            argv(list): List of arguments to the binary
            *args: Extra arguments to :func:`.gdb.debug`
            **kwargs: Extra arguments to :func:`.gdb.debug`

        Returns:
            :class:`.tube`: See :func:`.gdb.debug`
        """
        ...

    def disable_nx(self):
        r"""
        Disables NX for the ELF.

        Zeroes out the ``PT_GNU_STACK`` program header ``p_type`` field.
        """
        ...

    def disasm(self, address, n_bytes):
        r"""
        disasm(address, n_bytes) -> str

        Returns a string of disassembled instructions at
        the specified virtual memory address
        """
        ...

    def dynamic_by_tag(self, tag):
        r"""
        dynamic_by_tag(tag) -> tag

        Arguments:
            tag(str): Named ``DT_XXX`` tag (e.g. ``'DT_STRTAB'``).

        Returns:
            :class:`elftools.elf.dynamic.DynamicTag`
        """
        ...

    def dynamic_string(self, offset):
        r"""
        dynamic_string(offset) -> bytes

        Fetches an enumerated string from the ``DT_STRTAB`` table.

        Arguments:
            offset(int): String index

        Returns:
            :class:`str`: String from the table as raw bytes.
        """
        ...

    def dynamic_value_by_tag(self, tag):
        r"""
        dynamic_value_by_tag(tag) -> int

        Retrieve the value from a dynamic tag a la ``DT_XXX``.

        If the tag is missing, returns ``None``.
        """
        ...

    def fit(self, address, *a, **kw):
        r"""
        Writes fitted data into the specified address.

        See: :func:`.packing.fit`
        """
        ...

    def flat(self, address, *a, **kw):
        r"""
        Writes a full array of values to the specified address.

        See: :func:`.packing.flat`
        """
        ...

    def from_assembly(assembly, *a, **kw):
        r"""
        from_assembly(assembly) -> ELF

        Given an assembly listing, return a fully loaded ELF object
        which contains that assembly at its entry point.

        Arguments:

            assembly(str): Assembly language listing
            vma(int): Address of the entry point and the module's base address.

        Example:

            >>> e = ELF.from_assembly('nop; foo: int 0x80', vma = 0x400000)
            >>> e.symbols['foo'] = 0x400001
            >>> e.disasm(e.entry, 1)
            '  400000:       90                      nop'
            >>> e.disasm(e.symbols['foo'], 2)
            '  400001:       cd 80                   int    0x80'
        """
        ...

    def from_bytes(bytes, *a, **kw):
        r"""
        from_bytes(bytes) -> ELF

        Given a sequence of bytes, return a fully loaded ELF object
        which contains those bytes at its entry point.

        Arguments:

            bytes(str): Shellcode byte string
            vma(int): Desired base address for the ELF.

        Example:

            >>> e = ELF.from_bytes(b'\x90\xcd\x80', vma=0xc000)
            >>> print(e.disasm(e.entry, 3))
                c000:       90                      nop
                c001:       cd 80                   int    0x80
        """
        ...

    def get_data(self):
        r"""
        get_data() -> bytes

        Retrieve the raw data from the ELF file.

        >>> bash = ELF(which('bash'))
        >>> fd   = open(which('bash'), 'rb')
        >>> bash.get_data() == fd.read()
        True
        """
        ...

    def get_dwarf_info(self, relocate_dwarf_sections=True):
        r"""
        Return a DWARFInfo object representing the debugging information in
        this file.

        If relocate_dwarf_sections is True, relocations for DWARF sections
        are looked up and applied.
        """
        ...

    def get_ehabi_infos(self):
        r"""
        Generally, shared library and executable contain 1 .ARM.exidx section.
        Object file contains many .ARM.exidx sections.
        So we must traverse every section and filter sections whose type is SHT_ARM_EXIDX.
        """
        ...

    def get_machine_arch(self):
        r"""
        Return the machine architecture, as detected from the ELF header.
        
        """
        ...

    def get_section(self, n):
        r"""
        Get the section at index #n from the file (Section object or a
        subclass)
        """
        ...

    def get_section_by_name(self, name):
        r"""
        Get a section from the file, by name. Return None if no such
        section exists.
        """
        ...

    def get_segment(self, n):
        r"""
        Get the segment at index #n from the file (Segment object)
        
        """
        ...

    def get_segment_for_address(self, address, size=1):
        r"""
        get_segment_for_address(address, size=1) -> Segment

        Given a virtual address described by a ``PT_LOAD`` segment, return the
        first segment which describes the virtual address.  An optional ``size``
        may be provided to ensure the entire range falls into the same segment.

        Arguments:
            address(int): Virtual address to find
            size(int): Number of bytes which must be available after ``address``
                in **both** the file-backed data for the segment, and the memory
                region which is reserved for the data.

        Returns:
            Either returns a :class:`.segments.Segment` object, or ``None``.
        """
        ...

    def get_shstrndx(self):
        r"""
        Find the string table section index for the section header table
        
        """
        ...

    def has_dwarf_info(self):
        r"""
        Check whether this file appears to have debugging information.
        We assume that if it has the .debug_info or .zdebug_info section, it
        has all the other required sections as well.
        """
        ...

    def has_ehabi_info(self):
        r"""
        Check whether this file appears to have arm exception handler index table.
        
        """
        ...

    def iter_sections(self):
        r"""
        Yield all the sections in the file
        
        """
        ...

    def iter_segments(self):
        r"""
        Yield all the segments in the file
        
        """
        ...

    def iter_segments_by_type(self, t):
        r"""
        Yields:
            Segments matching the specified type.
        """
        ...

    def num_sections(self):
        r"""
        Number of sections in the file
        
        """
        ...

    def num_segments(self):
        r"""
        Number of segments in the file
        
        """
        ...

    def offset_to_vaddr(self, offset):
        r"""
        offset_to_vaddr(offset) -> int

        Translates the specified offset to a virtual address.

        Arguments:
            offset(int): Offset to translate

        Returns:
            `int`: Virtual address which corresponds to the file offset, or
            :const:`None`.

        Examples:

            This example shows that regardless of changes to the virtual
            address layout by modifying :attr:`.ELF.address`, the offset
            for any given address doesn't change.

            >>> bash = ELF('/bin/bash')
            >>> bash.address == bash.offset_to_vaddr(0)
            True
            >>> bash.address += 0x123456
            >>> bash.address == bash.offset_to_vaddr(0)
            True
        """
        ...

    def p16(self, address, data, *a, **kw):
        r"""
        Writes a 16-bit integer ``data`` to the specified ``address``
        """
        ...

    def p32(self, address, data, *a, **kw):
        r"""
        Writes a 32-bit integer ``data`` to the specified ``address``
        """
        ...

    def p64(self, address, data, *a, **kw):
        r"""
        Writes a 64-bit integer ``data`` to the specified ``address``
        """
        ...

    def p8(self, address, data, *a, **kw):
        r"""
        Writes a 8-bit integer ``data`` to the specified ``address``
        """
        ...

    def pack(self, address, data, *a, **kw):
        r"""
        Writes a packed integer ``data`` to the specified ``address``
        """
        ...

    def parse_kconfig(self, data):

        ...

    def process(self, argv=[], *a, **kw):
        r"""
        process(argv=[], *a, **kw) -> process

        Execute the binary with :class:`.process`.  Note that ``argv``
        is a list of arguments, and should not include ``argv[0]``.

        Arguments:
            argv(list): List of arguments to the binary
            *args: Extra arguments to :class:`.process`
            **kwargs: Extra arguments to :class:`.process`

        Returns:
            :class:`.process`
        """
        ...

    def read(self, address, count):
        r"""
        read(address, count) -> bytes

        Read data from the specified virtual address

        Arguments:
            address(int): Virtual address to read
            count(int): Number of bytes to read

        Returns:
            A :class:`str` object, or :const:`None`.

        Examples:
            The simplest example is just to read the ELF header.

            >>> bash = ELF(which('bash'))
            >>> bash.read(bash.address, 4)
            b'\x7fELF'

            ELF segments do not have to contain all of the data on-disk
            that gets loaded into memory.

            First, let's create an ELF file has some code in two sections.

            >>> assembly = '''
            ... .section .A,"awx"
            ... .global A
            ... A: nop
            ... .section .B,"awx"
            ... .global B
            ... B: int3
            ... '''
            >>> e = ELF.from_assembly(assembly, vma=False)

            By default, these come right after eachother in memory.

            >>> e.read(e.symbols.A, 2)
            b'\x90\xcc'
            >>> e.symbols.B - e.symbols.A
            1

            Let's move the sections so that B is a little bit further away.

            >>> objcopy = pwnlib.asm._objcopy()
            >>> objcopy += [
            ...     '--change-section-vma', '.B+5',
            ...     '--change-section-lma', '.B+5',
            ...     e.path
            ... ]
            >>> subprocess.check_call(objcopy)
            0

            Now let's re-load the ELF, and check again

            >>> e = ELF(e.path)
            >>> e.symbols.B - e.symbols.A
            6
            >>> e.read(e.symbols.A, 2)
            b'\x90\x00'
            >>> e.read(e.symbols.A, 7)
            b'\x90\x00\x00\x00\x00\x00\xcc'
            >>> e.read(e.symbols.A, 10)
            b'\x90\x00\x00\x00\x00\x00\xcc\x00\x00\x00'

            Everything is relative to the user-selected base address, so moving
            things around keeps everything working.

            >>> e.address += 0x1000
            >>> e.read(e.symbols.A, 10)
            b'\x90\x00\x00\x00\x00\x00\xcc\x00\x00\x00'
        """
        ...

    def save(self, path=None):
        r"""
        Save the ELF to a file

        >>> bash = ELF(which('bash'))
        >>> bash.save('/tmp/bash_copy')
        >>> copy = open('/tmp/bash_copy', 'rb')
        >>> bash = open(which('bash'), 'rb')
        >>> bash.read() == copy.read()
        True
        """
        ...

    def search(self, needle, writable=False, executable=False):
        r"""
        search(needle, writable = False, executable = False) -> generator

        Search the ELF's virtual address space for the specified string.

        Notes:
            Does not search empty space between segments, or uninitialized
            data.  This will only return data that actually exists in the
            ELF file.  Searching for a long string of NULL bytes probably
            won't work.

        Arguments:
            needle(str): String to search for.
            writable(bool): Search only writable sections.
            executable(bool): Search only executable sections.

        Yields:
            An iterator for each virtual address that matches.

        Examples:

            An ELF header starts with the bytes ``\x7fELF``, so we
            sould be able to find it easily.

            >>> bash = ELF('/bin/bash')
            >>> bash.address + 1 == next(bash.search(b'ELF'))
            True

            We can also search for string the binary.

            >>> len(list(bash.search(b'GNU bash'))) > 0
            True

            It is also possible to search for instructions in executable sections.

            >>> binary = ELF.from_assembly('nop; mov eax, 0; jmp esp; ret')
            >>> jmp_addr = next(binary.search(asm('jmp esp'), executable = True))
            >>> binary.read(jmp_addr, 2) == asm('jmp esp')
            True
        """
        ...

    def section(self, name):
        r"""
        section(name) -> bytes

        Gets data for the named section

        Arguments:
            name(str): Name of the section

        Returns:
            :class:`str`: String containing the bytes for that section
        """
        ...

    def string(self, address):
        r"""
        string(address) -> str

        Reads a null-terminated string from the specified ``address``

        Returns:
            A ``str`` with the string contents (NUL terminator is omitted),
            or an empty string if no NUL terminator could be found.
        """
        ...

    def u16(self, address, *a, **kw):
        r"""
        Unpacks an integer from the specified ``address``.
        """
        ...

    def u32(self, address, *a, **kw):
        r"""
        Unpacks an integer from the specified ``address``.
        """
        ...

    def u64(self, address, *a, **kw):
        r"""
        Unpacks an integer from the specified ``address``.
        """
        ...

    def u8(self, address, *a, **kw):
        r"""
        Unpacks an integer from the specified ``address``.
        """
        ...

    def unpack(self, address, *a, **kw):
        r"""
        Unpacks an integer from the specified ``address``.
        """
        ...

    def vaddr_to_offset(self, address):
        r"""
        vaddr_to_offset(address) -> int

        Translates the specified virtual address to a file offset

        Arguments:
            address(int): Virtual address to translate

        Returns:
            int: Offset within the ELF file which corresponds to the address,
            or :const:`None`.

        Examples:
            >>> bash = ELF(which('bash'))
            >>> bash.vaddr_to_offset(bash.address)
            0
            >>> bash.address += 0x123456
            >>> bash.vaddr_to_offset(bash.address)
            0
            >>> bash.vaddr_to_offset(0) is None
            True
        """
        ...

    def write(self, address, data):
        r"""
        Writes data to the specified virtual address

        Arguments:
            address(int): Virtual address to write
            data(str): Bytes to write

        Note:
            This routine does not check the bounds on the write to ensure
            that it stays in the same segment.

        Examples:
          >>> bash = ELF(which('bash'))
          >>> bash.read(bash.address+1, 3)
          b'ELF'
          >>> bash.write(bash.address, b"HELO")
          >>> bash.read(bash.address, 4)
          b'HELO'
        """
        ...

def load(*args, **kwargs):
    r"""
    Compatibility wrapper for pwntools v1
    """
    ...


import pwnlib.encoders


import pwnlib.encoders.amd64


import pwnlib.encoders.arm


import pwnlib.encoders.encoder

class Encoder:

    def __call__(self, raw_bytes, avoid, pcreg):
        r"""
        avoid(raw_bytes, avoid)

        Arguments:
            raw_bytes(str):
                String of bytes to encode
            avoid(set):
                Set of bytes to avoid
            pcreg(str):
                Register which contains the address of the shellcode.
                May be necessary for some shellcode.
        """
        ...

    def __init__(self):
        r"""
        Shellcode encoder class

        Implements an architecture-specific shellcode encoder
        """
        ...

def alphanumeric(raw_bytes, *a, **kw):
    r"""
    alphanumeric(raw_bytes) -> str

    Encode the shellcode ``raw_bytes`` such that it does not
    contain any bytes except for [A-Za-z0-9].

    Accepts the same arguments as :func:`encode`.
    """
    ...

def encode(raw_bytes, avoid=None, expr=None, force=0, pcreg=''):
    r"""
    encode(raw_bytes, avoid, expr, force) -> str

    Encode shellcode ``raw_bytes`` such that it does not contain
    any bytes in ``avoid`` or ``expr``.

    Arguments:

        raw_bytes(str): Sequence of shellcode bytes to encode.
        avoid(str):     Bytes to avoid
        expr(str):      Regular expression which matches bad characters.
        force(bool):    Force re-encoding of the shellcode, even if it
                        doesn't contain any bytes in ``avoid``.
    """
    ...

def line(raw_bytes, *a, **kw):
    r"""
    line(raw_bytes) -> str

    Encode the shellcode ``raw_bytes`` such that it does not
    contain any NULL bytes or whitespace.

    Accepts the same arguments as :func:`encode`.
    """
    ...

def null(raw_bytes, *a, **kw):
    r"""
    null(raw_bytes) -> str

    Encode the shellcode ``raw_bytes`` such that it does not
    contain any NULL bytes.

    Accepts the same arguments as :func:`encode`.
    """
    ...

def printable(raw_bytes, *a, **kw):
    r"""
    printable(raw_bytes) -> str

    Encode the shellcode ``raw_bytes`` such that it only contains
    non-space printable bytes.

    Accepts the same arguments as :func:`encode`.
    """
    ...

def scramble(raw_bytes, *a, **kw):
    r"""
    scramble(raw_bytes) -> str

    Encodes the input data with a random encoder.

    Accepts the same arguments as :func:`encode`.
    """
    ...


import pwnlib.encoders.i386


import pwnlib.encoders.mips


import pwnlib.exception

class PwnlibException (builtins.Exception):
    r"""
    Exception thrown by :func:`pwnlib.log.error`.

    Pwnlib functions that encounters unrecoverable errors should call the
    :func:`pwnlib.log.error` function instead of throwing this exception directly.
    """
    def __init__(self, msg, reason=None, exit_code=None):
        r"""
        bar
        """
        ...

    def __repr__(self):
        r"""
        Return repr(self).
        """
        ...


import pwnlib.filepointer

class FileStructure:
    r"""
    Crafts a FILE structure, with default values for some fields, like _lock which should point to null ideally, set.

    Arguments:
        null(int)
            A pointer to NULL value in memory. This pointer can lie in any segment (stack, heap, bss, libc etc)

    Examples:

        FILE structure with flags as 0xfbad1807 and _IO_buf_base and _IO_buf_end pointing to 0xcafebabe and 0xfacef00d

        >>> context.clear(arch='amd64')
        >>> fileStr = FileStructure(null=0xdeadbeeef)
        >>> fileStr.flags = 0xfbad1807
        >>> fileStr._IO_buf_base = 0xcafebabe
        >>> fileStr._IO_buf_end = 0xfacef00d
        >>> payload = bytes(fileStr)
        >>> payload
        b'\x07\x18\xad\xfb\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xbe\xba\xfe\xca\x00\x00\x00\x00\r\xf0\xce\xfa\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\xef\xee\xdb\xea\r\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\xef\xee\xdb\xea\r\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

        Check the length of the FileStructure

        >>> len(fileStr)
        224

        The defination for __repr__ orders the structure members and displays then in a dictionary format. It's useful when viewing a structure objet in python/IPython shell

        >>> q=FileStructure(0xdeadbeef)
        >>> q
        { flags: 0x0
         _IO_read_ptr: 0x0
         _IO_read_end: 0x0
         _IO_read_base: 0x0
         _IO_write_base: 0x0
         _IO_write_ptr: 0x0
         _IO_write_end: 0x0
         _IO_buf_base: 0x0
         _IO_buf_end: 0x0
         _IO_save_base: 0x0
         _IO_backup_base: 0x0
         _IO_save_end: 0x0
         markers: 0x0
         chain: 0x0
         fileno: 0x0
         _flags2: 0x0
         _old_offset: 0xffffffffffffffff
         _cur_column: 0x0
         _vtable_offset: 0x0
         _shortbuf: 0x0
         unknown1: 0x0
         _lock: 0xdeadbeef
         _offset: 0xffffffffffffffff
         _codecvt: 0x0
         _wide_data: 0xdeadbeef
         unknown2: 0x0
         vtable: 0x0}
    """
    def __bytes__(self):

        ...

    def __getattr__(self, item):

        ...

    def __init__(self, null=0):
        r"""
        Initialize self.  See help(type(self)) for accurate signature.
        """
        ...

    def __len__(self):

        ...

    def __repr__(self):
        r"""
        Return repr(self).
        """
        ...

    def __setattr__(self, item, value):
        r"""
        Implement setattr(self, name, value).
        """
        ...

    def orange(self, io_list_all, vtable):
        r"""
        Perform a House of Orange (https://github.com/shellphish/how2heap/blob/master/glibc_2.25/house_of_orange.c), provided you have libc leaks.

        Arguments:
            io_list_all(int)
                Address of _IO_list_all in libc.
            vtable(int)
                Address of the fake vtable in memory

        Example:

            Example payload if address of _IO_list_all is 0xfacef00d and fake vtable is at 0xcafebabe -

            >>> context.clear(arch='amd64')
            >>> fileStr = FileStructure(0xdeadbeef)
            >>> payload = fileStr.orange(io_list_all=0xfacef00d, vtable=0xcafebabe)
            >>> payload
            b'/bin/sh\x00a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xfd\xef\xce\xfa\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\xef\xbe\xad\xde\x00\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\xef\xbe\xad\xde\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xbe\xba\xfe\xca\x00\x00\x00\x00'
        """
        ...

    def read(self, addr=0, size=0):
        r"""
        Reading data into arbitrary memory location.

        Arguments:
            addr(int)
                The address into which data is to be written from stdin
            size(int)
                The size, in bytes, of the data to be written

        Example:

            Payload for reading 100 bytes from stdin into the address 0xcafebabe

            >>> context.clear(arch='amd64')
            >>> fileStr = FileStructure(0xdeadbeef)
            >>> payload = fileStr.read(addr=0xcafebabe, size=100)
            >>> payload
            b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xbe\xba\xfe\xca\x00\x00\x00\x00"\xbb\xfe\xca\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        """
        ...

    def setdefault(self, null):

        ...

    def struntil(self, v):
        r"""
        Payload for stuff till 'v' where 'v' is a structure member. This payload includes 'v' as well.

        Arguments:
            v(string)
                The name of the field uptil which the payload should be created.

        Example:

            Payload for data uptil _IO_buf_end

            >>> context.clear(arch='amd64')
            >>> fileStr = FileStructure(0xdeadbeef)
            >>> payload = fileStr.struntil("_IO_buf_end")
            >>> payload
            b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        """
        ...

    def write(self, addr=0, size=0):
        r"""
        Writing data out from arbitrary memory address.

        Arguments:
            addr(int)
                The address from which data is to be printed to stdout
            size(int)
                The size, in bytes, of the data to be printed

        Example:

            Payload for writing 100 bytes to stdout from the address 0xcafebabe

            >>> context.clear(arch='amd64')
            >>> fileStr = FileStructure(0xdeadbeef)
            >>> payload = fileStr.write(addr=0xcafebabe, size=100)
            >>> payload
            b'\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xbe\xba\xfe\xca\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xbe\xba\xfe\xca\x00\x00\x00\x00"\xbb\xfe\xca\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00'
        """
        ...

def update_var(l):
    r"""
    Since different members of the file structure have different sizes, we need to keep track of the sizes. The following function is used by the FileStructure class to initialise the lengths of the various fields.

    Arguments:
        l(int)
            l=8 for 'amd64' architecture and l=4 for 'i386' architecture

    Return Value:
        Returns a dictionary in which each field is mapped to its corresponding length according to the architecture set

    Examples:

        >>> update_var(8)
        {'flags': 8, '_IO_read_ptr': 8, '_IO_read_end': 8, '_IO_read_base': 8, '_IO_write_base': 8, '_IO_write_ptr': 8, '_IO_write_end': 8, '_IO_buf_base': 8, '_IO_buf_end': 8, '_IO_save_base': 8, '_IO_backup_base': 8, '_IO_save_end': 8, 'markers': 8, 'chain': 8, 'fileno': 4, '_flags2': 4, '_old_offset': 8, '_cur_column': 2, '_vtable_offset': 1, '_shortbuf': 1, 'unknown1': 4, '_lock': 8, '_offset': 8, '_codecvt': 8, '_wide_data': 8, 'unknown2': 48, 'vtable': 8}
    """
    ...


import pwnlib.filesystem.ssh

class SSHPath (pathlib.PosixPath):
    r"""
    Represents a file that exists on a remote filesystem.

    See :class:`.ssh` for more information on how to set up an SSH connection.
    See :py:class:`pathlib.Path` for documentation on what members and
    properties this object has.

    Arguments:
        name(str): Name of the file
        ssh(ssh): :class:`.ssh` object for manipulating remote files

    Note:

        You can avoid having to supply ``ssh=`` on every ``SSHPath`` by setting
        :data:`.context.ssh_session`.  
        In these examples we provide ``ssh=`` for clarity.

    Examples:

        First, create an SSH connection to the server.

        >>> ssh_conn = ssh('travis', 'example.pwnme')

        Let's use a temporary directory for our tests

        >>> _ = ssh_conn.set_working_directory()

        Next, you can create SSHPath objects to represent the paths to files
        on the remote system.

        >>> f = SSHPath('filename', ssh=ssh_conn)
        >>> f.touch()
        >>> f.exists()
        True
        >>> f.resolve().path # doctests: +ELLIPSIS
        '/tmp/.../filename'
        >>> f.write_text('asdf ❤️')
        >>> f.read_bytes()
        b'asdf \xe2\x9d\xa4\xef\xb8\x8f'

        ``context.ssh_session`` must be set to use the :meth:`.SSHPath.mktemp`
        or :meth:`.SSHPath.mkdtemp` methods.

        >>> context.ssh_session = ssh_conn
        >>> SSHPath.mktemp() # doctest: +ELLIPSIS
        SSHPath('...', ssh=ssh(user='travis', host='127.0.0.1'))
    """
    def __bytes__(self):
        r"""
        Return the bytes representation of the path.  This is only
        recommended to use under Unix.
        """
        ...

    def __enter__(self):

        ...

    def __eq__(self, other):
        r"""
        Return self==value.
        """
        ...

    def __exit__(self, t, v, tb):

        ...

    def __fspath__(self):

        ...

    def __ge__(*a, **kw):

        ...

    def __gt__(*a, **kw):

        ...

    def __hash__(*a, **kw):

        ...

    def __init__(self, path, ssh=None):
        r"""
        Initialize self.  See help(type(self)) for accurate signature.
        """
        ...

    def __le__(*a, **kw):

        ...

    def __lt__(*a, **kw):

        ...

    def __new__(cls, *args, **kwargs):
        r"""
        Construct a PurePath from one or several strings and or existing
        PurePath objects.  The strings and path objects are combined so as
        to yield a canonicalized path, which is incorporated into the
        new PurePath object.
        """
        ...

    def __reduce__(self):
        r"""
        Helper for pickle.
        """
        ...

    def __repr__(self):
        r"""
        Return repr(self).
        """
        ...

    def __rtruediv__(self, key):

        ...

    def __str__(self):
        r"""
        Return the string representation of the path, suitable for
        passing to system calls.
        """
        ...

    def __truediv__(self, key):

        ...

    def _init(self, template=None):

        ...

    def _make_child(self, args):

        ...

    def _make_child_relpath(self, part):

        ...

    def _new(self, path, *a, **kw):

        ...

    def _opener(self, name, flags, mode=438):

        ...

    def _raw_open(self, flags, mode=511):
        r"""
        Open the file pointed by this path and return a file descriptor,
        as os.open() does.
        """
        ...

    def _run(self, *a, **kw):

        ...

    def _s(self, other):

        ...

    def absolute(self):
        r"""
        Return the absolute path to a file, preserving e.g. "../".
        The current working directory is determined via the :class:`.ssh`
        member :attr:`.ssh.cwd`.

        Example:
    
            >>> f = SSHPath('absA/../absB/file', ssh=ssh_conn)
            >>> f.absolute().path # doctest: +ELLIPSIS
            '/.../absB/file'
        """
        ...

    def as_posix(self):
        r"""
        Return the string representation of the path with forward (/)
        slashes.
        """
        ...

    def as_uri(self):
        r"""
        Return the path as a 'file' URI.
        """
        ...

    def chmod(self, mode):
        r"""
        Change the permissions of a file

        >>> f = SSHPath('chmod_me', ssh=ssh_conn)
        >>> f.touch() # E
        >>> '0o%o' % f.stat().st_mode
        '0o100664'
        >>> f.chmod(0o777)
        >>> '0o%o' % f.stat().st_mode
        '0o100777'
        """
        ...

    def exists(self):
        r"""
        Returns True if the path exists

        Example:

            >>> a = SSHPath('exists', ssh=ssh_conn)
            >>> a.exists()
            False
            >>> a.touch()
            >>> a.exists()
            True
            >>> a.unlink()
            >>> a.exists()
            False
        """
        ...

    def expanduser(self):
        r"""
        Expands a path that starts with a tilde

        Example:

            >>> f = SSHPath('~/my-file', ssh=ssh_conn)
            >>> f.path
            '~/my-file'
            >>> f.expanduser().path # doctest: +ELLIPSIS
            '/home/.../my-file'
        """
        ...

    def glob(self, pattern):
        r"""
        Iterate over this subtree and yield all existing files (of any
        kind, including directories) matching the given relative pattern.
        """
        ...

    def group(self):
        r"""
        Return the group name of the file gid.
        """
        ...

    def is_absolute(self):
        r"""
        Returns whether a path is absolute or not.

        >>> f = SSHPath('hello/world/file.txt', ssh=ssh_conn)
        >>> f.is_absolute()
        False

        >>> f = SSHPath('/hello/world/file.txt', ssh=ssh_conn)
        >>> f.is_absolute()
        True
        """
        ...

    def is_block_device(self):
        r"""
        Whether this path is a block device.
        """
        ...

    def is_char_device(self):
        r"""
        Whether this path is a character device.
        """
        ...

    def is_dir(self):
        r"""
        Returns True if the path exists and is a directory

        Example:

            >>> f = SSHPath('is_dir', ssh=ssh_conn)
            >>> f.is_dir()
            False
            >>> f.touch()
            >>> f.is_dir()
            False
            >>> f.unlink()
            >>> f.mkdir()
            >>> f.is_dir()
            True
        """
        ...

    def is_fifo(self):
        r"""
        Whether this path is a FIFO.
        """
        ...

    def is_file(self):
        r"""
        Returns True if the path exists and is a file

        Example:

            >>> f = SSHPath('is_file', ssh=ssh_conn)
            >>> f.is_file()
            False
            >>> f.touch()
            >>> f.is_file()
            True
            >>> f.unlink()
            >>> f.mkdir()
            >>> f.is_file()
            False
        """
        ...

    def is_mount(self):
        r"""
        Check if this path is a POSIX mount point
        """
        ...

    def is_relative_to(self, *other):
        r"""
        Return True if the path is relative to another path or False.
        
        """
        ...

    def is_reserved(self):
        r"""
        Return True if the path contains one of the special names reserved
        by the system, if any.
        """
        ...

    def is_socket(self):
        r"""
        Whether this path is a socket.
        """
        ...

    def is_symlink(self):
        r"""
        Whether this path is a symbolic link.
        """
        ...

    def iterdir(self):
        r"""
        Iterates over the contents of the directory

        >>> directory = SSHPath('iterdir', ssh=ssh_conn)
        >>> directory.mkdir()
        >>> fileA = directory.joinpath('fileA')
        >>> fileA.touch()
        >>> fileB = directory.joinpath('fileB')
        >>> fileB.touch()
        >>> dirC = directory.joinpath('dirC')
        >>> dirC.mkdir()
        >>> [p.name for p in directory.iterdir()]
        ['dirC', 'fileA', 'fileB']
        """
        ...

    def joinpath(self, *args):
        r"""
        Combine this path with one or several arguments.

        >>> f = SSHPath('hello', ssh=ssh_conn)
        >>> f.joinpath('world').path
        'hello/world'
        """
        ...

    def lchmod(*a, **kw):
        r"""
        Like chmod(), except if the path points to a symlink, the symlink's
        permissions are changed, rather than its target's.
        """
        ...

    def link_to(self, target):
        r"""
        Create a hard link pointing to a path named target.
        """
        ...

    def lstat(self):
        r"""
        Like stat(), except if the path points to a symlink, the symlink's
        status information is returned, rather than its target's.
        """
        ...

    def match(self, path_pattern):
        r"""
        Return True if this path matches the given pattern.
        """
        ...

    def mkdir(self, mode=511, parents=False, exist_ok=True):
        r"""
        Make a directory at the specified path

        >>> f = SSHPath('dirname', ssh=ssh_conn)
        >>> f.mkdir()
        >>> f.exists()
        True

        >>> f = SSHPath('dirA/dirB/dirC', ssh=ssh_conn)
        >>> f.mkdir(parents=True)
        >>> ssh_conn.run(['ls', '-la', f.absolute().path]).recvline()
        b'total 8\n'
        """
        ...

    def open(self, *a, **kw):
        r"""
        Return a file-like object for this path.

        This currently seems to be broken in Paramiko.

        >>> f = SSHPath('filename', ssh=ssh_conn)
        >>> f.write_text('Hello')
        >>> fo = f.open(mode='r+')
        >>> fo                      # doctest: +ELLIPSIS
        <paramiko.sftp_file.SFTPFile object at ...>
        >>> fo.read('asdfasdf')     # doctest: +SKIP
        b'Hello'
        """
        ...

    def owner(self):
        r"""
        Return the login name of the file owner.
        """
        ...

    def read_bytes(self):
        r"""
        Read bytes from the file at this path

        >>> f = SSHPath('/etc/passwd', ssh=ssh_conn)
        >>> f.read_bytes()[:10]
        b'root:x:0:0'
        """
        ...

    def read_text(self):
        r"""
        Read text from the file at this path

        >>> f = SSHPath('/etc/passwd', ssh=ssh_conn)
        >>> f.read_text()[:10]
        'root:x:0:0'
        """
        ...

    def readlink(self):
        r"""
        Return the path to which the symbolic link points.
        """
        ...

    def relative_to(self, *other):
        r"""
        Return the relative path to another path identified by the passed
        arguments.  If the operation is not possible (because this is not
        a subpath of the other path), raise ValueError.
        """
        ...

    def rename(self, target):
        r"""
        Rename a file to the target path

        Example:

            >>> a = SSHPath('rename_from', ssh=ssh_conn)
            >>> b = SSHPath('rename_to', ssh=ssh_conn)
            >>> a.touch()
            >>> b.exists()
            False
            >>> a.rename(b)
            >>> b.exists()
            True
        """
        ...

    def replace(self, target):
        r"""
        Replace target file with file at this path

        Example:

            >>> a = SSHPath('rename_from', ssh=ssh_conn)
            >>> a.write_text('A')
            >>> b = SSHPath('rename_to', ssh=ssh_conn)
            >>> b.write_text('B')
            >>> a.replace(b)
            >>> b.read_text()
            'A'
        """
        ...

    def resolve(self, strict=False):
        r"""
        Return the absolute path to a file, resolving any '..' or symlinks.
        The current working directory is determined via the :class:`.ssh`
        member :attr:`.ssh.cwd`.

        Note:

            The file must exist to call resolve().

        Examples:

            >>> f = SSHPath('resA/resB/../resB/file', ssh=ssh_conn)

            >>> f.resolve().path # doctest: +ELLIPSIS
            Traceback (most recent call last):
            ...
            ValueError: Could not normalize path: '/.../resA/resB/file'

            >>> f.parent.absolute().mkdir(parents=True)
            >>> list(f.parent.iterdir())
            []

            >>> f.touch()
            >>> f.resolve() # doctest: +ELLIPSIS
            SSHPath('/.../resA/resB/file', ssh=ssh(user='...', host='127.0.0.1'))
        """
        ...

    def rglob(self, pattern):
        r"""
        Recursively yield all existing files (of any kind, including
        directories) matching the given relative pattern, anywhere in
        this subtree.
        """
        ...

    def rmdir(self):
        r"""
        Remove an existing directory.

        Example:

            >>> f = SSHPath('rmdir_me', ssh=ssh_conn)
            >>> f.mkdir()
            >>> f.is_dir()
            True
            >>> f.rmdir()
            >>> f.exists()
            False
        """
        ...

    def samefile(self, other_path):
        r"""
        Returns whether two files are the same

        >>> a = SSHPath('a', ssh=ssh_conn)
        >>> A = SSHPath('a', ssh=ssh_conn)
        >>> x = SSHPath('x', ssh=ssh_conn)

        >>> a.samefile(A)
        True
        >>> a.samefile(x)
        False
        """
        ...

    def stat(self):
        r"""
        Returns the permissions and other information about the file

        >>> f = SSHPath('filename', ssh=ssh_conn)
        >>> f.touch()
        >>> stat = f.stat()
        >>> stat.st_size
        0
        >>> '%o' % stat.st_mode # doctest: +ELLIPSIS
        '...664'
        """
        ...

    def symlink_to(self, target):
        r"""
        Create a symlink at this path to the provided target

        Todo:

            Paramiko's documentation is wrong and inverted.
            https://github.com/paramiko/paramiko/issues/1821

        Example:

            >>> a = SSHPath('link_name', ssh=ssh_conn)
            >>> b = SSHPath('link_target', ssh=ssh_conn)
            >>> a.symlink_to(b)
            >>> a.write_text("Hello")
            >>> b.read_text()
            'Hello'
        """
        ...

    def touch(self):
        r"""
        Touch a file (i.e. make it exist)

        >>> f = SSHPath('touchme', ssh=ssh_conn)
        >>> f.exists()
        False
        >>> f.touch()
        >>> f.exists()
        True
        """
        ...

    def unlink(self, missing_ok=False):
        r"""
        Remove an existing file.

        TODO:

            This test fails catastrophically if the file name is unlink_me
            (note the underscore)

        Example:

            >>> f = SSHPath('unlink_me', ssh=ssh_conn)
            >>> f.exists()
            False
            >>> f.touch()
            >>> f.exists()
            True
            >>> f.unlink()
            >>> f.exists()
            False

            Note that unlink only works on files.

            >>> f.mkdir()
            >>> f.unlink()
            Traceback (most recent call last):
            ...
            ValueError: Cannot unlink SSHPath(...)): is not a file
        """
        ...

    def with_name(self, name):
        r"""
        Return a new path with the file name changed

        >>> f = SSHPath('hello/world', ssh=ssh_conn)
        >>> f.path
        'hello/world'
        >>> f.with_name('asdf').path
        'hello/asdf'
        """
        ...

    def with_stem(self, name):
        r"""
        Return a new path with the stem changed.

        >>> f = SSHPath('hello/world.tar.gz', ssh=ssh_conn)
        >>> f.with_stem('asdf').path
        'hello/asdf.tar.gz'
        """
        ...

    def with_suffix(self, suffix):
        r"""
        Return a new path with the file suffix changed

        >>> f = SSHPath('hello/world.tar.gz', ssh=ssh_conn)
        >>> f.with_suffix('.tgz').path
        'hello/world.tgz'
        """
        ...

    def write_bytes(self, data):
        r"""
        Write bytes to the file at this path

        >>> f = SSHPath('somefile', ssh=ssh_conn)
        >>> f.write_bytes(b'\x00HELLO\x00')
        >>> f.read_bytes()
        b'\x00HELLO\x00'
        """
        ...

    def write_text(self, data):
        r"""
        Write text to the file at this path

        >>> f = SSHPath('somefile', ssh=ssh_conn)
        >>> f.write_text("HELLO 😭")
        >>> f.read_bytes()
        b'HELLO \xf0\x9f\x98\xad'
        >>> f.read_text()
        'HELLO 😭'
        """
        ...


import pwnlib.flag.flag

def submit_flag(flag, exploit='unnamed-exploit', target='unknown-target', server='flag-submission-server', port='31337', team='unknown-team'):
    r"""
    Submits a flag to the game server

    Arguments:
        flag(str): The flag to submit.
        exploit(str): Exploit identifier, optional
        target(str): Target identifier, optional
        server(str): Flag server host name, optional
        port(int): Flag server port, optional
        team(str): Team identifier, optional

    Optional arguments are inferred from the environment,
    or omitted if none is set.

    Returns:
        A string indicating the status of the key submission,
        or an error code.

    Doctest:

        >>> l = listen()
        >>> _ = submit_flag('flag', server='localhost', port=l.lport)
        >>> c = l.wait_for_connection()
        >>> c.recvall().split()
        [b'flag', b'unnamed-exploit', b'unknown-target', b'unknown-team']
    """
    ...


import pwnlib.fmtstr

class FmtStr:
    r"""
    Provides an automated format string exploitation.

    It takes a function which is called every time the automated
    process want to communicate with the vulnerable process. this
    function takes a parameter with the payload that you have to
    send to the vulnerable process and must return the process
    returns.

    If the `offset` parameter is not given, then try to find the right
    offset by leaking stack data.

    Arguments:
            execute_fmt(function): function to call for communicate with the vulnerable process
            offset(int): the first formatter's offset you control
            padlen(int): size of the pad you want to add before the payload
            numbwritten(int): number of already written bytes
    """
    def __init__(self, execute_fmt, offset=None, padlen=0, numbwritten=0):
        r"""
        Initialize self.  See help(type(self)) for accurate signature.
        """
        ...

    def _leaker(self, addr):

        ...

    def execute_writes(self):
        r"""
        execute_writes() -> None

        Makes payload and send it to the vulnerable process

        Returns:
            None
        """
        ...

    def find_offset(self):

        ...

    def leak_stack(self, offset, prefix=b''):

        ...

    def write(self, addr, data):
        r"""
        write(addr, data) -> None

        In order to tell : I want to write ``data`` at ``addr``.

        Arguments:
            addr(int): the address where you want to write
            data(int): the data that you want to write ``addr``

        Returns:
            None

        Examples:

            >>> def send_fmt_payload(payload):
            ...     print(repr(payload))
            ...
            >>> f = FmtStr(send_fmt_payload, offset=5)
            >>> f.write(0x08040506, 0x1337babe)
            >>> f.execute_writes()
            b'%19c%16$hhn%36c%17$hhn%131c%18$hhn%4c%19$hhn\t\x05\x04\x08\x08\x05\x04\x08\x07\x05\x04\x08\x06\x05\x04\x08'
        """
        ...

def fmtstr_payload(offset, writes, numbwritten=0, write_size='byte', write_size_max='long', overflows=16, strategy='small', badbytes=frozenset(), offset_bytes=0):
    r"""
    fmtstr_payload(offset, writes, numbwritten=0, write_size='byte') -> str

    Makes payload with given parameter.
    It can generate payload for 32 or 64 bits architectures.
    The size of the addr is taken from ``context.bits``

    The overflows argument is a format-string-length to output-amount tradeoff:
    Larger values for ``overflows`` produce shorter format strings that generate more output at runtime.

    Arguments:
        offset(int): the first formatter's offset you control
        writes(dict): dict with addr, value ``{addr: value, addr2: value2}``
        numbwritten(int): number of byte already written by the printf function
        write_size(str): must be ``byte``, ``short`` or ``int``. Tells if you want to write byte by byte, short by short or int by int (hhn, hn or n)
        overflows(int): how many extra overflows (at size sz) to tolerate to reduce the length of the format string
        strategy(str): either 'fast' or 'small' ('small' is default, 'fast' can be used if there are many writes)
    Returns:
        The payload in order to do needed writes

    Examples:
        >>> context.clear(arch = 'amd64')
        >>> fmtstr_payload(1, {0x0: 0x1337babe}, write_size='int')
        b'%322419390c%4$llnaaaabaa\x00\x00\x00\x00\x00\x00\x00\x00'
        >>> fmtstr_payload(1, {0x0: 0x1337babe}, write_size='short')
        b'%47806c%5$lln%22649c%6$hnaaaabaa\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00'
        >>> fmtstr_payload(1, {0x0: 0x1337babe}, write_size='byte')
        b'%190c%7$lln%85c%8$hhn%36c%9$hhn%131c%10$hhnaaaab\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00'
        >>> context.clear(arch = 'i386')
        >>> fmtstr_payload(1, {0x0: 0x1337babe}, write_size='int')
        b'%322419390c%5$na\x00\x00\x00\x00'
        >>> fmtstr_payload(1, {0x0: 0x1337babe}, write_size='short')
        b'%4919c%7$hn%42887c%8$hna\x02\x00\x00\x00\x00\x00\x00\x00'
        >>> fmtstr_payload(1, {0x0: 0x1337babe}, write_size='byte')
        b'%19c%12$hhn%36c%13$hhn%131c%14$hhn%4c%15$hhn\x03\x00\x00\x00\x02\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00'
        >>> fmtstr_payload(1, {0x0: 0x00000001}, write_size='byte')
        b'%1c%3$na\x00\x00\x00\x00'
        >>> fmtstr_payload(1, {0x0: b"\xff\xff\x04\x11\x00\x00\x00\x00"}, write_size='short')
        b'%327679c%7$lln%18c%8$hhn\x00\x00\x00\x00\x03\x00\x00\x00'
    """
    ...

def fmtstr_split(offset, writes, numbwritten=0, write_size='byte', write_size_max='long', overflows=16, strategy='small', badbytes=frozenset()):
    r"""
    Build a format string like fmtstr_payload but return the string and data separately.
    """
    ...


import pwnlib.gdb

def attach(target, gdbscript='', exe=None, gdb_args=None, ssh=None, sysroot=None, api=False):
    r"""
    Start GDB in a new terminal and attach to `target`.

    Arguments:
        target: The target to attach to.
        gdbscript(:obj:`str` or :obj:`file`): GDB script to run after attaching.
        exe(str): The path of the target binary.
        arch(str): Architechture of the target binary.  If `exe` known GDB will
          detect the architechture automatically (if it is supported).
        gdb_args(list): List of additional arguments to pass to GDB.
        sysroot(str): Foreign-architecture sysroot, used for QEMU-emulated binaries
            and Android targets.
        api(bool): Enable access to GDB Python API.

    Returns:
        PID of the GDB process (or the window which it is running in).
        When ``api=True``, a (PID, :class:`Gdb`) tuple.

    Notes:

        The ``target`` argument is very robust, and can be any of the following:

        :obj:`int`
            PID of a process
        :obj:`str`
            Process name.  The youngest process is selected.
        :obj:`tuple`
            Host, port pair of a listening ``gdbserver``
        :class:`.process`
            Process to connect to
        :class:`.sock`
            Connected socket. The executable on the other end of the connection is attached to.
            Can be any socket type, including :class:`.listen` or :class:`.remote`.
        :class:`.ssh_channel`
            Remote process spawned via :meth:`.ssh.process`.
            This will use the GDB installed on the remote machine.
            If a password is required to connect, the ``sshpass`` program must be installed.

    Examples:

        Attach to a process by PID

        >>> pid = gdb.attach(1234) # doctest: +SKIP

        Attach to the youngest process by name

        >>> pid = gdb.attach('bash') # doctest: +SKIP

        Attach a debugger to a :class:`.process` tube and automate interaction

        >>> io = process('bash')
        >>> pid = gdb.attach(io, gdbscript='''
        ... call puts("Hello from process debugger!")
        ... detach
        ... quit
        ... ''')
        >>> io.recvline()
        b'Hello from process debugger!\n'
        >>> io.sendline('echo Hello from bash && exit')
        >>> io.recvall()
        b'Hello from bash\n'

        Using GDB Python API:

        .. doctest
           :skipif: six.PY2

            >>> io = process('bash')

            Attach a debugger

            >>> pid, io_gdb = gdb.attach(io, api=True)

            Force the program to write something it normally wouldn't

            >>> io_gdb.execute('call puts("Hello from process debugger!")')

            Resume the program

            >>> io_gdb.continue_nowait()

            Observe the forced line

            >>> io.recvline()
            b'Hello from process debugger!\n'

            Interact with the program in a regular way

            >>> io.sendline('echo Hello from bash && exit')

            Observe the results

            >>> io.recvall()
            b'Hello from bash\n'

        Attach to the remote process from a :class:`.remote` or :class:`.listen` tube,
        as long as it is running on the same machine.

        >>> server = process(['socat', 'tcp-listen:12345,reuseaddr,fork', 'exec:/bin/bash,nofork'])
        >>> sleep(1) # Wait for socat to start
        >>> io = remote('127.0.0.1', 12345)
        >>> sleep(1) # Wait for process to fork
        >>> pid = gdb.attach(io, gdbscript='''
        ... call puts("Hello from remote debugger!")
        ... detach
        ... quit
        ... ''')
        >>> io.recvline()
        b'Hello from remote debugger!\n'
        >>> io.sendline('echo Hello from bash && exit')
        >>> io.recvall()
        b'Hello from bash\n'

        Attach to processes running on a remote machine via an SSH :class:`.ssh` process

        >>> shell = ssh('travis', 'example.pwnme', password='demopass')
        >>> io = shell.process(['cat'])
        >>> pid = gdb.attach(io, gdbscript='''
        ... call sleep(5)
        ... call puts("Hello from ssh debugger!")
        ... detach
        ... quit
        ... ''')
        >>> io.recvline(timeout=5)  # doctest: +SKIP
        b'Hello from ssh debugger!\n'
        >>> io.sendline('This will be echoed back')
        >>> io.recvline()
        b'This will be echoed back\n'
        >>> io.close()
    """
    ...

def debug_assembly(asm, gdbscript=None, vma=None, api=False):
    r"""
    debug_assembly(asm, gdbscript=None, vma=None, api=False) -> tube

    Creates an ELF file, and launches it under a debugger.

    This is identical to debug_shellcode, except that
    any defined symbols are available in GDB, and it
    saves you the explicit call to asm().

    Arguments:
        asm(str): Assembly code to debug
        gdbscript(str): Script to run in GDB
        vma(int): Base address to load the shellcode at
        api(bool): Enable access to GDB Python API
        \**kwargs: Override any :obj:`pwnlib.context.context` values.

    Returns:
        :class:`.process`

    Example:

    >>> assembly = shellcraft.echo("Hello world!\n")
    >>> io = gdb.debug_assembly(assembly)
    >>> io.recvline()
    b'Hello world!\n'
    """
    ...

def debug_shellcode(data, gdbscript=None, vma=None, api=False):
    r"""
    debug_shellcode(data, gdbscript=None, vma=None, api=False) -> tube
    Creates an ELF file, and launches it under a debugger.

    Arguments:
        data(str): Assembled shellcode bytes
        gdbscript(str): Script to run in GDB
        vma(int): Base address to load the shellcode at
        api(bool): Enable access to GDB Python API
        \**kwargs: Override any :obj:`pwnlib.context.context` values.

    Returns:
        :class:`.process`

    Example:

    >>> assembly = shellcraft.echo("Hello world!\n")
    >>> shellcode = asm(assembly)
    >>> io = gdb.debug_shellcode(shellcode)
    >>> io.recvline()
    b'Hello world!\n'
    """
    ...


import pwnlib.libcdb


import pwnlib.log

def getLogger(name):

    ...


import pwnlib.memleak

class MemLeak:
    r"""
    MemLeak is a caching and heuristic tool for exploiting memory leaks.

    It can be used as a decorator, around functions of the form:

        def some_leaker(addr):
            ...
            return data_as_string_or_None

    It will cache leaked memory (which requires either non-randomized static
    data or a continouous session). If required, dynamic or known data can be
    set with the set-functions, but this is usually not required. If a byte
    cannot be recovered, it will try to leak nearby bytes in the hope that the
    byte is recovered as a side-effect.

    Arguments:
        f (function): The leaker function.
        search_range (int): How many bytes to search backwards in case an address does not work.
        reraise (bool): Whether to reraise call :func:`pwnlib.log.warning` in case the leaker function throws an exception.

    Example:

        >>> import pwnlib
        >>> binsh = pwnlib.util.misc.read('/bin/sh')
        >>> @pwnlib.memleak.MemLeak
        ... def leaker(addr):
        ...     print("leaking 0x%x" % addr)
        ...     return binsh[addr:addr+4]
        >>> leaker.s(0)[:4]
        leaking 0x0
        leaking 0x4
        b'\x7fELF'
        >>> leaker[:4]
        b'\x7fELF'
        >>> hex(leaker.d(0))
        '0x464c457f'
        >>> hex(leaker.clearb(1))
        '0x45'
        >>> hex(leaker.d(0))
        leaking 0x1
        '0x464c457f'
        >>> @pwnlib.memleak.MemLeak
        ... def leaker_nonulls(addr):
        ...     print("leaking 0x%x" % addr)
        ...     if addr & 0xff == 0:
        ...         return None
        ...     return binsh[addr:addr+4]
        >>> leaker_nonulls.d(0) is None
        leaking 0x0
        True
        >>> leaker_nonulls[0x100:0x104] == binsh[0x100:0x104]
        leaking 0x100
        leaking 0xff
        leaking 0x103
        True

        >>> memory = {-4+i: c.encode() for i,c in enumerate('wxyzABCDE')}
        >>> def relative_leak(index):
        ...     return memory.get(index, None)
        >>> leak = pwnlib.memleak.MemLeak(relative_leak, relative = True)
        >>> leak[-1:2]
        b'zAB'
    """
    def NoNewlines(function):
        r"""
        Wrapper for leak functions such that addresses which contain newline
        bytes are not leaked.

        This is useful if the address which is used for the leak is provided by
        e.g. ``fgets()``.
        """
        ...

    def NoNulls(function):
        r"""
        Wrapper for leak functions such that addresses which contain NULL
        bytes are not leaked.

        This is useful if the address which is used for the leak is read in via
        a string-reading function like ``scanf("%s")`` or smilar.
        """
        ...

    def NoWhitespace(function):
        r"""
        Wrapper for leak functions such that addresses which contain whitespace
        bytes are not leaked.

        This is useful if the address which is used for the leak is read in via
        e.g. ``scanf()``.
        """
        ...

    def String(function):
        r"""
        Wrapper for leak functions which leak strings, such that a NULL
        terminator is automaticall added.

        This is useful if the data leaked is printed out as a NULL-terminated
        string, via e.g. ``printf()``.
        """
        ...

    def __call__(self, *a, **kw):
        r"""
        Call self as a function.
        """
        ...

    def __getitem__(self, item):

        ...

    def __init__(self, f, search_range=20, reraise=True, relative=False):
        r"""
        Initialize self.  See help(type(self)) for accurate signature.
        """
        ...

    def __repr__(self):
        r"""
        Return repr(self).
        """
        ...

    def _b(self, addr, ndx, size):

        ...

    def _clear(self, addr, ndx, size):

        ...

    def _leak(self, addr, n, recurse=True):
        r"""
        _leak(addr, n) => str

        Leak ``n`` consecutive bytes starting at ``addr``.

        Returns:
            A string of length ``n``, or :const:`None`.
        """
        ...

    def _set(self, addr, val, ndx, size):

        ...

    def b(self, addr, ndx=0):
        r"""
        b(addr, ndx = 0) -> int

        Leak byte at ``((uint8_t*) addr)[ndx]``

        Examples:

            >>> import string
            >>> data = string.ascii_lowercase.encode()
            >>> l = MemLeak(lambda a: data[a:a+2], reraise=False)
            >>> l.b(0) == ord('a')
            True
            >>> l.b(25) == ord('z')
            True
            >>> l.b(26) is None
            True
        """
        ...

    def clearb(self, addr, ndx=0):
        r"""
        clearb(addr, ndx = 0) -> int

        Clears byte at ``((uint8_t*)addr)[ndx]`` from the cache and
        returns the removed value or `None` if the address was not completely set.

        Examples:

            >>> l = MemLeak(lambda a: None)
            >>> l.cache = {0:b'a'}
            >>> l.n(0,1) == b'a'
            True
            >>> l.clearb(0) == unpack(b'a', 8)
            True
            >>> l.cache
            {}
            >>> l.clearb(0) is None
            True
        """
        ...

    def cleard(self, addr, ndx=0):
        r"""
        cleard(addr, ndx = 0) -> int

        Clears dword at ``((uint32_t*)addr)[ndx]`` from the cache and
        returns the removed value or `None` if the address was not completely set.

        Examples:

            >>> l = MemLeak(lambda a: None)
            >>> l.cache = {0: b'a', 1: b'b', 2: b'c', 3: b'd'}
            >>> l.n(0, 4) == b'abcd'
            True
            >>> l.cleard(0) == unpack(b'abcd', 32)
            True
            >>> l.cache
            {}
        """
        ...

    def clearq(self, addr, ndx=0):
        r"""
        clearq(addr, ndx = 0) -> int

        Clears qword at ``((uint64_t*)addr)[ndx]`` from the cache and
        returns the removed value or `None` if the address was not completely set.

        Examples:

            >>> c = MemLeak(lambda addr: b'')
            >>> c.cache = {x:b'x' for x in range(0x100, 0x108)}
            >>> c.clearq(0x100) == unpack(b'xxxxxxxx', 64)
            True
            >>> c.cache == {}
            True
        """
        ...

    def clearw(self, addr, ndx=0):
        r"""
        clearw(addr, ndx = 0) -> int

        Clears word at ``((uint16_t*)addr)[ndx]`` from the cache and
        returns the removed value or `None` if the address was not completely set.

        Examples:

            >>> l = MemLeak(lambda a: None)
            >>> l.cache = {0: b'a', 1: b'b'}
            >>> l.n(0, 2) == b'ab'
            True
            >>> l.clearw(0) == unpack(b'ab', 16)
            True
            >>> l.cache
            {}
        """
        ...

    def compare(self, address, bts):

        ...

    def d(self, addr, ndx=0):
        r"""
        d(addr, ndx = 0) -> int

        Leak dword at ``((uint32_t*) addr)[ndx]``

        Examples:

            >>> import string
            >>> data = string.ascii_lowercase.encode()
            >>> l = MemLeak(lambda a: data[a:a+8], reraise=False)
            >>> l.d(0) == unpack(b'abcd', 32)
            True
            >>> l.d(22) == unpack(b'wxyz', 32)
            True
            >>> l.d(23) is None
            True
        """
        ...

    def field(self, address, obj):
        r"""
        field(address, field) => a structure field.

        Leak a field from a structure.

        Arguments:
            address(int): Base address to calculate offsets from
            field(obj):   Instance of a ctypes field

        Return Value:
            The type of the return value will be dictated by
            the type of ``field``.
        """
        ...

    def field_compare(self, address, obj, expected):
        r"""
        field_compare(address, field, expected) ==> bool

        Leak a field from a structure, with an expected value.
        As soon as any mismatch is found, stop leaking the structure.

        Arguments:
            address(int): Base address to calculate offsets from
            field(obj):   Instance of a ctypes field
            expected(int,bytes): Expected value

        Return Value:
            The type of the return value will be dictated by
            the type of ``field``.
        """
        ...

    def n(self, addr, numb):
        r"""
        n(addr, ndx = 0) -> str

        Leak `numb` bytes at `addr`.

        Returns:
            A string with the leaked bytes, will return `None` if any are missing

        Examples:

            >>> import string
            >>> data = string.ascii_lowercase.encode()
            >>> l = MemLeak(lambda a: data[a:a+4], reraise=False)
            >>> l.n(0,1) == b'a'
            True
            >>> l.n(0,26) == data
            True
            >>> len(l.n(0,26)) == 26
            True
            >>> l.n(0,27) is None
            True
        """
        ...

    def p(self, addr, ndx=0):
        r"""
        p(addr, ndx = 0) -> int

        Leak a pointer-width value at ``((void**) addr)[ndx]``
        """
        ...

    def p16(self, addr, val, ndx=0):
        r"""
        Sets word at ``((uint16_t*)addr)[ndx]`` to `val` in the cache.

        Examples:

            >>> l = MemLeak(lambda x: b'')
            >>> l.cache == {}
            True
            >>> l.setw(33, 0x41)
            >>> l.cache == {33: b'A', 34: b'\x00'}
            True
        """
        ...

    def p32(self, addr, val, ndx=0):
        r"""
        Sets dword at ``((uint32_t*)addr)[ndx]`` to `val` in the cache.

        Examples:
            See :meth:`setw`.
        """
        ...

    def p64(self, addr, val, ndx=0):
        r"""
        Sets qword at ``((uint64_t*)addr)[ndx]`` to `val` in the cache.

        Examples:
            See :meth:`setw`.
        """
        ...

    def p8(self, addr, val, ndx=0):
        r"""
        Sets byte at ``((uint8_t*)addr)[ndx]`` to `val` in the cache.

        Examples:

            >>> l = MemLeak(lambda x: b'')
            >>> l.cache == {}
            True
            >>> l.setb(33, 0x41)
            >>> l.cache == {33: b'A'}
            True
        """
        ...

    def q(self, addr, ndx=0):
        r"""
        q(addr, ndx = 0) -> int

        Leak qword at ``((uint64_t*) addr)[ndx]``

        Examples:

            >>> import string
            >>> data = string.ascii_lowercase.encode()
            >>> l = MemLeak(lambda a: data[a:a+16], reraise=False)
            >>> l.q(0) == unpack(b'abcdefgh', 64)
            True
            >>> l.q(18) == unpack(b'stuvwxyz', 64)
            True
            >>> l.q(19) is None
            True
        """
        ...

    def raw(self, addr, numb):
        r"""
        raw(addr, numb) -> list

        Leak `numb` bytes at `addr`
        """
        ...

    def s(self, addr):
        r"""
        s(addr) -> str

        Leak bytes at `addr` until failure or a nullbyte is found

        Return:
            A string, without a NULL terminator.
            The returned string will be empty if the first byte is
            a NULL terminator, or if the first byte could not be
            retrieved.

        Examples:

            >>> data = b"Hello\x00World"
            >>> l = MemLeak(lambda a: data[a:a+4], reraise=False)
            >>> l.s(0) == b"Hello"
            True
            >>> l.s(5) == b""
            True
            >>> l.s(6) == b"World"
            True
            >>> l.s(999) == b""
            True
        """
        ...

    def setb(self, addr, val, ndx=0):
        r"""
        Sets byte at ``((uint8_t*)addr)[ndx]`` to `val` in the cache.

        Examples:

            >>> l = MemLeak(lambda x: b'')
            >>> l.cache == {}
            True
            >>> l.setb(33, 0x41)
            >>> l.cache == {33: b'A'}
            True
        """
        ...

    def setd(self, addr, val, ndx=0):
        r"""
        Sets dword at ``((uint32_t*)addr)[ndx]`` to `val` in the cache.

        Examples:
            See :meth:`setw`.
        """
        ...

    def setq(self, addr, val, ndx=0):
        r"""
        Sets qword at ``((uint64_t*)addr)[ndx]`` to `val` in the cache.

        Examples:
            See :meth:`setw`.
        """
        ...

    def sets(self, addr, val, null_terminate=True):
        r"""
        Set known string at `addr`, which will be optionally be null-terminated

        Note that this method is a bit dumb about how it handles the data.
        It will null-terminate the data, but it will not stop at the first null.

        Examples:

            >>> l = MemLeak(lambda x: b'')
            >>> l.cache == {}
            True
            >>> l.sets(0, b'H\x00ello')
            >>> l.cache == {0: b'H', 1: b'\x00', 2: b'e', 3: b'l', 4: b'l', 5: b'o', 6: b'\x00'}
            True
        """
        ...

    def setw(self, addr, val, ndx=0):
        r"""
        Sets word at ``((uint16_t*)addr)[ndx]`` to `val` in the cache.

        Examples:

            >>> l = MemLeak(lambda x: b'')
            >>> l.cache == {}
            True
            >>> l.setw(33, 0x41)
            >>> l.cache == {33: b'A', 34: b'\x00'}
            True
        """
        ...

    def struct(self, address, struct):
        r"""
        struct(address, struct) => structure object
        Leak an entire structure.
        Arguments:
            address(int):  Addess of structure in memory
            struct(class): A ctypes structure to be instantiated with leaked data
        Return Value:
            An instance of the provided struct class, with the leaked data decoded

        Examples:

            >>> @pwnlib.memleak.MemLeak
            ... def leaker(addr):
            ...     return b"A"
            >>> e = leaker.struct(0, pwnlib.elf.Elf32_Phdr)
            >>> hex(e.p_paddr)
            '0x41414141'
        """
        ...

    def u16(self, addr, ndx=0):
        r"""
        w(addr, ndx = 0) -> int

        Leak word at ``((uint16_t*) addr)[ndx]``

        Examples:

            >>> import string
            >>> data = string.ascii_lowercase.encode()
            >>> l = MemLeak(lambda a: data[a:a+4], reraise=False)
            >>> l.w(0) == unpack(b'ab', 16)
            True
            >>> l.w(24) == unpack(b'yz', 16)
            True
            >>> l.w(25) is None
            True
        """
        ...

    def u32(self, addr, ndx=0):
        r"""
        d(addr, ndx = 0) -> int

        Leak dword at ``((uint32_t*) addr)[ndx]``

        Examples:

            >>> import string
            >>> data = string.ascii_lowercase.encode()
            >>> l = MemLeak(lambda a: data[a:a+8], reraise=False)
            >>> l.d(0) == unpack(b'abcd', 32)
            True
            >>> l.d(22) == unpack(b'wxyz', 32)
            True
            >>> l.d(23) is None
            True
        """
        ...

    def u64(self, addr, ndx=0):
        r"""
        q(addr, ndx = 0) -> int

        Leak qword at ``((uint64_t*) addr)[ndx]``

        Examples:

            >>> import string
            >>> data = string.ascii_lowercase.encode()
            >>> l = MemLeak(lambda a: data[a:a+16], reraise=False)
            >>> l.q(0) == unpack(b'abcdefgh', 64)
            True
            >>> l.q(18) == unpack(b'stuvwxyz', 64)
            True
            >>> l.q(19) is None
            True
        """
        ...

    def u8(self, addr, ndx=0):
        r"""
        b(addr, ndx = 0) -> int

        Leak byte at ``((uint8_t*) addr)[ndx]``

        Examples:

            >>> import string
            >>> data = string.ascii_lowercase.encode()
            >>> l = MemLeak(lambda a: data[a:a+2], reraise=False)
            >>> l.b(0) == ord('a')
            True
            >>> l.b(25) == ord('z')
            True
            >>> l.b(26) is None
            True
        """
        ...

    def w(self, addr, ndx=0):
        r"""
        w(addr, ndx = 0) -> int

        Leak word at ``((uint16_t*) addr)[ndx]``

        Examples:

            >>> import string
            >>> data = string.ascii_lowercase.encode()
            >>> l = MemLeak(lambda a: data[a:a+4], reraise=False)
            >>> l.w(0) == unpack(b'ab', 16)
            True
            >>> l.w(24) == unpack(b'yz', 16)
            True
            >>> l.w(25) is None
            True
        """
        ...

class RelativeMemLeak (pwnlib.memleak.MemLeak):
    r"""
    MemLeak is a caching and heuristic tool for exploiting memory leaks.

    It can be used as a decorator, around functions of the form:

        def some_leaker(addr):
            ...
            return data_as_string_or_None

    It will cache leaked memory (which requires either non-randomized static
    data or a continouous session). If required, dynamic or known data can be
    set with the set-functions, but this is usually not required. If a byte
    cannot be recovered, it will try to leak nearby bytes in the hope that the
    byte is recovered as a side-effect.

    Arguments:
        f (function): The leaker function.
        search_range (int): How many bytes to search backwards in case an address does not work.
        reraise (bool): Whether to reraise call :func:`pwnlib.log.warning` in case the leaker function throws an exception.

    Example:

        >>> import pwnlib
        >>> binsh = pwnlib.util.misc.read('/bin/sh')
        >>> @pwnlib.memleak.MemLeak
        ... def leaker(addr):
        ...     print("leaking 0x%x" % addr)
        ...     return binsh[addr:addr+4]
        >>> leaker.s(0)[:4]
        leaking 0x0
        leaking 0x4
        b'\x7fELF'
        >>> leaker[:4]
        b'\x7fELF'
        >>> hex(leaker.d(0))
        '0x464c457f'
        >>> hex(leaker.clearb(1))
        '0x45'
        >>> hex(leaker.d(0))
        leaking 0x1
        '0x464c457f'
        >>> @pwnlib.memleak.MemLeak
        ... def leaker_nonulls(addr):
        ...     print("leaking 0x%x" % addr)
        ...     if addr & 0xff == 0:
        ...         return None
        ...     return binsh[addr:addr+4]
        >>> leaker_nonulls.d(0) is None
        leaking 0x0
        True
        >>> leaker_nonulls[0x100:0x104] == binsh[0x100:0x104]
        leaking 0x100
        leaking 0xff
        leaking 0x103
        True

        >>> memory = {-4+i: c.encode() for i,c in enumerate('wxyzABCDE')}
        >>> def relative_leak(index):
        ...     return memory.get(index, None)
        >>> leak = pwnlib.memleak.MemLeak(relative_leak, relative = True)
        >>> leak[-1:2]
        b'zAB'
    """
    def NoNewlines(function):
        r"""
        Wrapper for leak functions such that addresses which contain newline
        bytes are not leaked.

        This is useful if the address which is used for the leak is provided by
        e.g. ``fgets()``.
        """
        ...

    def NoNulls(function):
        r"""
        Wrapper for leak functions such that addresses which contain NULL
        bytes are not leaked.

        This is useful if the address which is used for the leak is read in via
        a string-reading function like ``scanf("%s")`` or smilar.
        """
        ...

    def NoWhitespace(function):
        r"""
        Wrapper for leak functions such that addresses which contain whitespace
        bytes are not leaked.

        This is useful if the address which is used for the leak is read in via
        e.g. ``scanf()``.
        """
        ...

    def String(function):
        r"""
        Wrapper for leak functions which leak strings, such that a NULL
        terminator is automaticall added.

        This is useful if the data leaked is printed out as a NULL-terminated
        string, via e.g. ``printf()``.
        """
        ...

    def __call__(self, *a, **kw):
        r"""
        Call self as a function.
        """
        ...

    def __getitem__(self, item):

        ...

    def __init__(self, *a, **kw):
        r"""
        Initialize self.  See help(type(self)) for accurate signature.
        """
        ...

    def __repr__(self):
        r"""
        Return repr(self).
        """
        ...

    def _b(self, addr, ndx, size):

        ...

    def _clear(self, addr, ndx, size):

        ...

    def _leak(self, addr, n, recurse=True):
        r"""
        _leak(addr, n) => str

        Leak ``n`` consecutive bytes starting at ``addr``.

        Returns:
            A string of length ``n``, or :const:`None`.
        """
        ...

    def _set(self, addr, val, ndx, size):

        ...

    def b(self, addr, ndx=0):
        r"""
        b(addr, ndx = 0) -> int

        Leak byte at ``((uint8_t*) addr)[ndx]``

        Examples:

            >>> import string
            >>> data = string.ascii_lowercase.encode()
            >>> l = MemLeak(lambda a: data[a:a+2], reraise=False)
            >>> l.b(0) == ord('a')
            True
            >>> l.b(25) == ord('z')
            True
            >>> l.b(26) is None
            True
        """
        ...

    def clearb(self, addr, ndx=0):
        r"""
        clearb(addr, ndx = 0) -> int

        Clears byte at ``((uint8_t*)addr)[ndx]`` from the cache and
        returns the removed value or `None` if the address was not completely set.

        Examples:

            >>> l = MemLeak(lambda a: None)
            >>> l.cache = {0:b'a'}
            >>> l.n(0,1) == b'a'
            True
            >>> l.clearb(0) == unpack(b'a', 8)
            True
            >>> l.cache
            {}
            >>> l.clearb(0) is None
            True
        """
        ...

    def cleard(self, addr, ndx=0):
        r"""
        cleard(addr, ndx = 0) -> int

        Clears dword at ``((uint32_t*)addr)[ndx]`` from the cache and
        returns the removed value or `None` if the address was not completely set.

        Examples:

            >>> l = MemLeak(lambda a: None)
            >>> l.cache = {0: b'a', 1: b'b', 2: b'c', 3: b'd'}
            >>> l.n(0, 4) == b'abcd'
            True
            >>> l.cleard(0) == unpack(b'abcd', 32)
            True
            >>> l.cache
            {}
        """
        ...

    def clearq(self, addr, ndx=0):
        r"""
        clearq(addr, ndx = 0) -> int

        Clears qword at ``((uint64_t*)addr)[ndx]`` from the cache and
        returns the removed value or `None` if the address was not completely set.

        Examples:

            >>> c = MemLeak(lambda addr: b'')
            >>> c.cache = {x:b'x' for x in range(0x100, 0x108)}
            >>> c.clearq(0x100) == unpack(b'xxxxxxxx', 64)
            True
            >>> c.cache == {}
            True
        """
        ...

    def clearw(self, addr, ndx=0):
        r"""
        clearw(addr, ndx = 0) -> int

        Clears word at ``((uint16_t*)addr)[ndx]`` from the cache and
        returns the removed value or `None` if the address was not completely set.

        Examples:

            >>> l = MemLeak(lambda a: None)
            >>> l.cache = {0: b'a', 1: b'b'}
            >>> l.n(0, 2) == b'ab'
            True
            >>> l.clearw(0) == unpack(b'ab', 16)
            True
            >>> l.cache
            {}
        """
        ...

    def compare(self, address, bts):

        ...

    def d(self, addr, ndx=0):
        r"""
        d(addr, ndx = 0) -> int

        Leak dword at ``((uint32_t*) addr)[ndx]``

        Examples:

            >>> import string
            >>> data = string.ascii_lowercase.encode()
            >>> l = MemLeak(lambda a: data[a:a+8], reraise=False)
            >>> l.d(0) == unpack(b'abcd', 32)
            True
            >>> l.d(22) == unpack(b'wxyz', 32)
            True
            >>> l.d(23) is None
            True
        """
        ...

    def field(self, address, obj):
        r"""
        field(address, field) => a structure field.

        Leak a field from a structure.

        Arguments:
            address(int): Base address to calculate offsets from
            field(obj):   Instance of a ctypes field

        Return Value:
            The type of the return value will be dictated by
            the type of ``field``.
        """
        ...

    def field_compare(self, address, obj, expected):
        r"""
        field_compare(address, field, expected) ==> bool

        Leak a field from a structure, with an expected value.
        As soon as any mismatch is found, stop leaking the structure.

        Arguments:
            address(int): Base address to calculate offsets from
            field(obj):   Instance of a ctypes field
            expected(int,bytes): Expected value

        Return Value:
            The type of the return value will be dictated by
            the type of ``field``.
        """
        ...

    def n(self, addr, numb):
        r"""
        n(addr, ndx = 0) -> str

        Leak `numb` bytes at `addr`.

        Returns:
            A string with the leaked bytes, will return `None` if any are missing

        Examples:

            >>> import string
            >>> data = string.ascii_lowercase.encode()
            >>> l = MemLeak(lambda a: data[a:a+4], reraise=False)
            >>> l.n(0,1) == b'a'
            True
            >>> l.n(0,26) == data
            True
            >>> len(l.n(0,26)) == 26
            True
            >>> l.n(0,27) is None
            True
        """
        ...

    def p(self, addr, ndx=0):
        r"""
        p(addr, ndx = 0) -> int

        Leak a pointer-width value at ``((void**) addr)[ndx]``
        """
        ...

    def p16(self, addr, val, ndx=0):
        r"""
        Sets word at ``((uint16_t*)addr)[ndx]`` to `val` in the cache.

        Examples:

            >>> l = MemLeak(lambda x: b'')
            >>> l.cache == {}
            True
            >>> l.setw(33, 0x41)
            >>> l.cache == {33: b'A', 34: b'\x00'}
            True
        """
        ...

    def p32(self, addr, val, ndx=0):
        r"""
        Sets dword at ``((uint32_t*)addr)[ndx]`` to `val` in the cache.

        Examples:
            See :meth:`setw`.
        """
        ...

    def p64(self, addr, val, ndx=0):
        r"""
        Sets qword at ``((uint64_t*)addr)[ndx]`` to `val` in the cache.

        Examples:
            See :meth:`setw`.
        """
        ...

    def p8(self, addr, val, ndx=0):
        r"""
        Sets byte at ``((uint8_t*)addr)[ndx]`` to `val` in the cache.

        Examples:

            >>> l = MemLeak(lambda x: b'')
            >>> l.cache == {}
            True
            >>> l.setb(33, 0x41)
            >>> l.cache == {33: b'A'}
            True
        """
        ...

    def q(self, addr, ndx=0):
        r"""
        q(addr, ndx = 0) -> int

        Leak qword at ``((uint64_t*) addr)[ndx]``

        Examples:

            >>> import string
            >>> data = string.ascii_lowercase.encode()
            >>> l = MemLeak(lambda a: data[a:a+16], reraise=False)
            >>> l.q(0) == unpack(b'abcdefgh', 64)
            True
            >>> l.q(18) == unpack(b'stuvwxyz', 64)
            True
            >>> l.q(19) is None
            True
        """
        ...

    def raw(self, addr, numb):
        r"""
        raw(addr, numb) -> list

        Leak `numb` bytes at `addr`
        """
        ...

    def s(self, addr):
        r"""
        s(addr) -> str

        Leak bytes at `addr` until failure or a nullbyte is found

        Return:
            A string, without a NULL terminator.
            The returned string will be empty if the first byte is
            a NULL terminator, or if the first byte could not be
            retrieved.

        Examples:

            >>> data = b"Hello\x00World"
            >>> l = MemLeak(lambda a: data[a:a+4], reraise=False)
            >>> l.s(0) == b"Hello"
            True
            >>> l.s(5) == b""
            True
            >>> l.s(6) == b"World"
            True
            >>> l.s(999) == b""
            True
        """
        ...

    def setb(self, addr, val, ndx=0):
        r"""
        Sets byte at ``((uint8_t*)addr)[ndx]`` to `val` in the cache.

        Examples:

            >>> l = MemLeak(lambda x: b'')
            >>> l.cache == {}
            True
            >>> l.setb(33, 0x41)
            >>> l.cache == {33: b'A'}
            True
        """
        ...

    def setd(self, addr, val, ndx=0):
        r"""
        Sets dword at ``((uint32_t*)addr)[ndx]`` to `val` in the cache.

        Examples:
            See :meth:`setw`.
        """
        ...

    def setq(self, addr, val, ndx=0):
        r"""
        Sets qword at ``((uint64_t*)addr)[ndx]`` to `val` in the cache.

        Examples:
            See :meth:`setw`.
        """
        ...

    def sets(self, addr, val, null_terminate=True):
        r"""
        Set known string at `addr`, which will be optionally be null-terminated

        Note that this method is a bit dumb about how it handles the data.
        It will null-terminate the data, but it will not stop at the first null.

        Examples:

            >>> l = MemLeak(lambda x: b'')
            >>> l.cache == {}
            True
            >>> l.sets(0, b'H\x00ello')
            >>> l.cache == {0: b'H', 1: b'\x00', 2: b'e', 3: b'l', 4: b'l', 5: b'o', 6: b'\x00'}
            True
        """
        ...

    def setw(self, addr, val, ndx=0):
        r"""
        Sets word at ``((uint16_t*)addr)[ndx]`` to `val` in the cache.

        Examples:

            >>> l = MemLeak(lambda x: b'')
            >>> l.cache == {}
            True
            >>> l.setw(33, 0x41)
            >>> l.cache == {33: b'A', 34: b'\x00'}
            True
        """
        ...

    def struct(self, address, struct):
        r"""
        struct(address, struct) => structure object
        Leak an entire structure.
        Arguments:
            address(int):  Addess of structure in memory
            struct(class): A ctypes structure to be instantiated with leaked data
        Return Value:
            An instance of the provided struct class, with the leaked data decoded

        Examples:

            >>> @pwnlib.memleak.MemLeak
            ... def leaker(addr):
            ...     return b"A"
            >>> e = leaker.struct(0, pwnlib.elf.Elf32_Phdr)
            >>> hex(e.p_paddr)
            '0x41414141'
        """
        ...

    def u16(self, addr, ndx=0):
        r"""
        w(addr, ndx = 0) -> int

        Leak word at ``((uint16_t*) addr)[ndx]``

        Examples:

            >>> import string
            >>> data = string.ascii_lowercase.encode()
            >>> l = MemLeak(lambda a: data[a:a+4], reraise=False)
            >>> l.w(0) == unpack(b'ab', 16)
            True
            >>> l.w(24) == unpack(b'yz', 16)
            True
            >>> l.w(25) is None
            True
        """
        ...

    def u32(self, addr, ndx=0):
        r"""
        d(addr, ndx = 0) -> int

        Leak dword at ``((uint32_t*) addr)[ndx]``

        Examples:

            >>> import string
            >>> data = string.ascii_lowercase.encode()
            >>> l = MemLeak(lambda a: data[a:a+8], reraise=False)
            >>> l.d(0) == unpack(b'abcd', 32)
            True
            >>> l.d(22) == unpack(b'wxyz', 32)
            True
            >>> l.d(23) is None
            True
        """
        ...

    def u64(self, addr, ndx=0):
        r"""
        q(addr, ndx = 0) -> int

        Leak qword at ``((uint64_t*) addr)[ndx]``

        Examples:

            >>> import string
            >>> data = string.ascii_lowercase.encode()
            >>> l = MemLeak(lambda a: data[a:a+16], reraise=False)
            >>> l.q(0) == unpack(b'abcdefgh', 64)
            True
            >>> l.q(18) == unpack(b'stuvwxyz', 64)
            True
            >>> l.q(19) is None
            True
        """
        ...

    def u8(self, addr, ndx=0):
        r"""
        b(addr, ndx = 0) -> int

        Leak byte at ``((uint8_t*) addr)[ndx]``

        Examples:

            >>> import string
            >>> data = string.ascii_lowercase.encode()
            >>> l = MemLeak(lambda a: data[a:a+2], reraise=False)
            >>> l.b(0) == ord('a')
            True
            >>> l.b(25) == ord('z')
            True
            >>> l.b(26) is None
            True
        """
        ...

    def w(self, addr, ndx=0):
        r"""
        w(addr, ndx = 0) -> int

        Leak word at ``((uint16_t*) addr)[ndx]``

        Examples:

            >>> import string
            >>> data = string.ascii_lowercase.encode()
            >>> l = MemLeak(lambda a: data[a:a+4], reraise=False)
            >>> l.w(0) == unpack(b'ab', 16)
            True
            >>> l.w(24) == unpack(b'yz', 16)
            True
            >>> l.w(25) is None
            True
        """
        ...


import pwnlib.pep237


import pwnlib.regsort

def check_cycle(reg, assignments):
    r"""
    Walk down the assignment list of a register,
    return the path walked if it is encountered again.

    Returns:

        The list of register involved in the cycle.
        If there is no cycle, this is an empty list.

    Example:

        >>> check_cycle('a', {'a': 1})
        []
        >>> check_cycle('a', {'a': 'a'})
        ['a']
        >>> check_cycle('a', {'a': 'b', 'b': 'a'})
        ['a', 'b']
        >>> check_cycle('a', {'a': 'b', 'b': 'c', 'c': 'b', 'd': 'a'})
        []
        >>> check_cycle('a', {'a': 'b', 'b': 'c', 'c': 'd', 'd': 'a'})
        ['a', 'b', 'c', 'd']
    """
    ...

def check_cycle_(reg, assignments, path):

    ...

def depends_on_cycle(reg, assignments, in_cycles):

    ...

def extract_dependencies(reg, assignments):
    r"""
    Return a list of all registers which directly
    depend on the specified register.

    Example:

        >>> extract_dependencies('a', {'a': 1})
        []
        >>> extract_dependencies('a', {'a': 'b', 'b': 1})
        []
        >>> extract_dependencies('a', {'a': 1, 'b': 'a'})
        ['b']
        >>> extract_dependencies('a', {'a': 1, 'b': 'a', 'c': 'a'})
        ['b', 'c']
    """
    ...

def regsort(in_out, all_regs, tmp=None, xchg=True, randomize=None):
    r"""
    Sorts register dependencies.

    Given a dictionary of registers to desired register contents,
    return the optimal order in which to set the registers to
    those contents.

    The implementation assumes that it is possible to move from
    any register to any other register.

    If a dependency cycle is encountered, one of the following will
    occur:

    - If ``xchg`` is :const:`True`, it is assumed that dependency cyles can
      be broken by swapping the contents of two register (a la the
      ``xchg`` instruction on i386).
    - If ``xchg`` is not set, but not all destination registers in
      ``in_out`` are involved in a cycle, one of the registers
      outside the cycle will be used as a temporary register,
      and then overwritten with its final value.
    - If ``xchg`` is not set, and all registers are involved in
      a dependency cycle, the named register ``temporary`` is used
      as a temporary register.
    - If the dependency cycle cannot be resolved as described above,
      an exception is raised.

    Arguments:

        in_out(dict):
            Dictionary of desired register states.
            Keys are registers, values are either registers or any other value.
        all_regs(list):
            List of all possible registers.
            Used to determine which values in ``in_out`` are registers, versus
            regular values.
        tmp(obj, str):
            Named register (or other sentinel value) to use as a temporary
            register.  If ``tmp`` is a named register **and** appears
            as a source value in ``in_out``, dependencies are handled
            appropriately.  ``tmp`` cannot be a destination register
            in ``in_out``.
            If ``bool(tmp)==True``, this mode is enabled.
        xchg(obj):
            Indicates the existence of an instruction which can swap the
            contents of two registers without use of a third register.
            If ``bool(xchg)==False``, this mode is disabled.
        random(bool):
            Randomize as much as possible about the order or registers.

    Returns:

        A list of tuples of ``(src, dest)``.

        Each register may appear more than once, if a register is used
        as a temporary register, and later overwritten with its final
        value.

        If ``xchg`` is :const:`True` and it is used to break a dependency cycle,
        then ``reg_name`` will be :const:`None` and ``value`` will be a tuple
        of the instructions to swap.

    Example:

        >>> R = ['a', 'b', 'c', 'd', 'x', 'y', 'z']

        If order doesn't matter for any subsequence, alphabetic
        order is used.

        >>> regsort({'a': 1, 'b': 2}, R)
        [('mov', 'a', 1), ('mov', 'b', 2)]
        >>> regsort({'a': 'b', 'b': 'a'}, R)
        [('xchg', 'a', 'b')]
        >>> regsort({'a': 'b', 'b': 'a'}, R, tmp='X') #doctest: +NORMALIZE_WHITESPACE
        [('mov', 'X', 'a'),
         ('mov', 'a', 'b'),
         ('mov', 'b', 'X')]
        >>> regsort({'a': 1, 'b': 'a'}, R) #doctest: +NORMALIZE_WHITESPACE
        [('mov', 'b', 'a'),
         ('mov', 'a', 1)]
        >>> regsort({'a': 'b', 'b': 'a', 'c': 3}, R) #doctest: +NORMALIZE_WHITESPACE
        [('mov', 'c', 3),
         ('xchg', 'a', 'b')]
        >>> regsort({'a': 'b', 'b': 'a', 'c': 'b'}, R) #doctest: +NORMALIZE_WHITESPACE
        [('mov', 'c', 'b'),
         ('xchg', 'a', 'b')]
        >>> regsort({'a':'b', 'b':'a', 'x':'b'}, R, tmp='y', xchg=False) #doctest: +NORMALIZE_WHITESPACE
        [('mov', 'x', 'b'),
         ('mov', 'y', 'a'),
         ('mov', 'a', 'b'),
         ('mov', 'b', 'y')]
        >>> regsort({'a':'b', 'b':'a', 'x':'b'}, R, tmp='x', xchg=False) #doctest: +ELLIPSIS
        Traceback (most recent call last):
        ...
        PwnlibException: Cannot break dependency cycles ...
        >>> regsort({'a':'b','b':'c','c':'a','x':'1','y':'z','z':'c'}, R) #doctest: +NORMALIZE_WHITESPACE
        [('mov', 'x', '1'),
         ('mov', 'y', 'z'),
         ('mov', 'z', 'c'),
         ('xchg', 'a', 'b'),
         ('xchg', 'b', 'c')]
        >>> regsort({'a':'b','b':'c','c':'a','x':'1','y':'z','z':'c'}, R, tmp='x') #doctest: +NORMALIZE_WHITESPACE
        [('mov', 'y', 'z'),
         ('mov', 'z', 'c'),
         ('mov', 'x', 'a'),
         ('mov', 'a', 'b'),
         ('mov', 'b', 'c'),
         ('mov', 'c', 'x'),
         ('mov', 'x', '1')]
        >>> regsort({'a':'b','b':'c','c':'a','x':'1','y':'z','z':'c'}, R, xchg=0) #doctest: +NORMALIZE_WHITESPACE
        [('mov', 'y', 'z'),
         ('mov', 'z', 'c'),
         ('mov', 'x', 'a'),
         ('mov', 'a', 'b'),
         ('mov', 'b', 'c'),
         ('mov', 'c', 'x'),
         ('mov', 'x', '1')]
         >>> regsort({'a': 'b', 'b': 'c'}, ['a','b','c'], xchg=0)
         [('mov', 'a', 'b'), ('mov', 'b', 'c')]
    """
    ...

def resolve_order(reg, deps):
    r"""
    Resolve the order of all dependencies starting at a given register.

    Example:

        >>> want = {'a': 1, 'b': 'c', 'c': 'd', 'd': 7, 'x': 'd'}
        >>> deps = {'a': [], 'b': [], 'c': ['b'], 'd': ['c', 'x'], 'x': []}
        >>> resolve_order('a', deps)
        ['a']
        >>> resolve_order('b', deps)
        ['b']
        >>> resolve_order('c', deps)
        ['b', 'c']
        >>> resolve_order('d', deps)
        ['b', 'c', 'x', 'd']
    """
    ...


import pwnlib.replacements

def sleep(n):
    r"""
    sleep(n)

    Replacement for :func:`time.sleep()`, which does not return if a signal is received.

    Arguments:
      n (int):  Number of seconds to sleep.
    """
    ...


import pwnlib.rop


import pwnlib.rop.call

class AppendedArgument (pwnlib.rop.call.Unresolved):
    r"""
    Encapsulates information about a pointer argument, and the data
    which is pointed to, where the absolute address of the data must
    be known, and the data can be appended to the ROP chain.

    Examples:

        >>> context.clear()
        >>> context.arch = 'amd64'
        >>> u = AppendedArgument([1,2,'hello',3])
        >>> len(u)
        32
        >>> u.resolve()
        [1, 2, b'hello\x00$$', 3]

        >>> u = AppendedArgument([1,2,['hello'],3])
        >>> u.resolve()
        [1, 2, 32, 3, b'hello\x00$$']
        >>> u.resolve(10000)
        [1, 2, 10032, 3, b'hello\x00$$']
        >>> u.address = 20000
        >>> u.resolve()
        [1, 2, 20032, 3, b'hello\x00$$']

        >>> u = AppendedArgument([[[[[[[[['pointers!']]]]]]]]], 1000)
        >>> u.resolve()
        [1008, 1016, 1024, 1032, 1040, 1048, 1056, 1064, b'pointers!\x00$$$$$$']
    """
    def __bytes__(self):

        ...

    def __init__(self, value, address=0):
        r"""
        Initialize self.  See help(type(self)) for accurate signature.
        """
        ...

    def __len__(self):

        ...

    def __repr__(self):
        r"""
        Return repr(self).
        """
        ...

    def local(self, address):

        ...

    def resolve(self, addr=None):
        r"""
        Return a flat list of ``int`` or ``str`` objects which can be
        passed to :func:`.flat`.

        Arguments:
            addr(int): Address at which the data starts in memory.
                If :const:`None`, ``self.addr`` is used.
        """
        ...


import pwnlib.rop.ret2dlresolve

class Ret2dlresolvePayload:
    r"""
    Create a ret2dlresolve payload

    Arguments:
        elf (ELF): Binary to search
        symbol (str): Function to search for
        args (list): List of arguments to pass to the function

    Returns:
        A ``Ret2dlresolvePayload`` object which can be passed to ``rop.ret2dlresolve``
    """
    def __init__(self, elf, symbol, args, data_addr=None):
        r"""
        Initialize self.  See help(type(self)) for accurate signature.
        """
        ...

    def _build(self):

        ...

    def _build_args(self):

        ...

    def _build_structures(self):

        ...

    def _format_args(self):

        ...

    def _get_recommended_address(self):

        ...


import pwnlib.rop.rop

class ROP:
    r"""
    Class which simplifies the generation of ROP-chains.

    Example:

    .. code-block:: python

       elf = ELF('ropasaurusrex')
       rop = ROP(elf)
       rop.read(0, elf.bss(0x80))
       rop.dump()
       # ['0x0000:        0x80482fc (read)',
       #  '0x0004:       0xdeadbeef',
       #  '0x0008:              0x0',
       #  '0x000c:        0x80496a8']
       bytes(rop)
       # '\xfc\x82\x04\x08\xef\xbe\xad\xde\x00\x00\x00\x00\xa8\x96\x04\x08'

    >>> context.clear(arch = "i386", kernel = 'amd64')
    >>> assembly = 'int 0x80; ret; add esp, 0x10; ret; pop eax; ret'
    >>> e = ELF.from_assembly(assembly)
    >>> e.symbols['funcname'] = e.entry + 0x1234
    >>> r = ROP(e)
    >>> r.funcname(1, 2)
    >>> r.funcname(3)
    >>> r.execve(4, 5, 6)
    >>> print(r.dump())
    0x0000:       0x10001234 funcname(1, 2)
    0x0004:       0x10000003 <adjust @0x18> add esp, 0x10; ret
    0x0008:              0x1 arg0
    0x000c:              0x2 arg1
    0x0010:          b'eaaa' <pad>
    0x0014:          b'faaa' <pad>
    0x0018:       0x10001234 funcname(3)
    0x001c:       0x10000007 <adjust @0x24> pop eax; ret
    0x0020:              0x3 arg0
    0x0024:       0x10000007 pop eax; ret
    0x0028:             0x77 [arg0] eax = SYS_sigreturn
    0x002c:       0x10000000 int 0x80; ret
    0x0030:              0x0 gs
    0x0034:              0x0 fs
    0x0038:              0x0 es
    0x003c:              0x0 ds
    0x0040:              0x0 edi
    0x0044:              0x0 esi
    0x0048:              0x0 ebp
    0x004c:              0x0 esp
    0x0050:              0x4 ebx
    0x0054:              0x6 edx
    0x0058:              0x5 ecx
    0x005c:              0xb eax = SYS_execve
    0x0060:              0x0 trapno
    0x0064:              0x0 err
    0x0068:       0x10000000 int 0x80; ret
    0x006c:             0x23 cs
    0x0070:              0x0 eflags
    0x0074:              0x0 esp_at_signal
    0x0078:             0x2b ss
    0x007c:              0x0 fpstate

    >>> r = ROP(e, 0x8048000)
    >>> r.funcname(1, 2)
    >>> r.funcname(3)
    >>> r.execve(4, 5, 6)
    >>> print(r.dump())
    0x8048000:       0x10001234 funcname(1, 2)
    0x8048004:       0x10000003 <adjust @0x8048018> add esp, 0x10; ret
    0x8048008:              0x1 arg0
    0x804800c:              0x2 arg1
    0x8048010:          b'eaaa' <pad>
    0x8048014:          b'faaa' <pad>
    0x8048018:       0x10001234 funcname(3)
    0x804801c:       0x10000007 <adjust @0x8048024> pop eax; ret
    0x8048020:              0x3 arg0
    0x8048024:       0x10000007 pop eax; ret
    0x8048028:             0x77 [arg0] eax = SYS_sigreturn
    0x804802c:       0x10000000 int 0x80; ret
    0x8048030:              0x0 gs
    0x8048034:              0x0 fs
    0x8048038:              0x0 es
    0x804803c:              0x0 ds
    0x8048040:              0x0 edi
    0x8048044:              0x0 esi
    0x8048048:              0x0 ebp
    0x804804c:        0x8048080 esp
    0x8048050:              0x4 ebx
    0x8048054:              0x6 edx
    0x8048058:              0x5 ecx
    0x804805c:              0xb eax = SYS_execve
    0x8048060:              0x0 trapno
    0x8048064:              0x0 err
    0x8048068:       0x10000000 int 0x80; ret
    0x804806c:             0x23 cs
    0x8048070:              0x0 eflags
    0x8048074:              0x0 esp_at_signal
    0x8048078:             0x2b ss
    0x804807c:              0x0 fpstate


    >>> elf = ELF.from_assembly('ret')
    >>> r = ROP(elf)
    >>> r.ret.address == 0x10000000
    True
    >>> r = ROP(elf, badchars=b'\x00')
    >>> r.gadgets == {}
    True
    >>> r.ret is None
    True
    """
    def _ROP__cache_load(self, elf):

        ...

    def _ROP__cache_save(self, elf, data):

        ...

    def _ROP__get_cachefile_name(self, files):
        r"""
        Given an ELF or list of ELF objects, return a cache file for the set of files
        """
        ...

    def _ROP__load(self):
        r"""
        Load all ROP gadgets for the selected ELF files
        """
        ...

    def __bytes__(self):
        r"""
        Returns: Raw bytes of the ROP chain
        """
        ...

    def __call__(self, *args, **kwargs):
        r"""
        Set the given register(s)' by constructing a rop chain.

        This is a thin wrapper around :meth:`setRegisters` which
        actually executes the rop chain.

        You can call this :class:`ROP` instance and provide keyword arguments,
        or a dictionary.

        Arguments:
            regs(dict): Mapping of registers to values.
                        Can instead provide ``kwargs``.

        >>> context.clear(arch='amd64')
        >>> assembly = 'pop rax; pop rdi; pop rsi; ret; pop rax; ret;'
        >>> e = ELF.from_assembly(assembly)
        >>> r = ROP(e)
        >>> r(rax=0xdead, rdi=0xbeef, rsi=0xcafe)
        >>> print(r.dump())
        0x0000:       0x10000000
        0x0008:           0xdead
        0x0010:           0xbeef
        0x0018:           0xcafe
        >>> r = ROP(e)
        >>> r({'rax': 0xdead, 'rdi': 0xbeef, 'rsi': 0xcafe})
        >>> print(r.dump())
        0x0000:       0x10000000
        0x0008:           0xdead
        0x0010:           0xbeef
        0x0018:           0xcafe
        """
        ...

    def __getattr__(self, attr):
        r"""
        Helper to make finding ROP gadgets easier.

        Also provides a shorthand for ``.call()``:
            ``rop.function(args)`` is equivalent to ``rop.call(function, args)``

        >>> context.clear(arch='i386')
        >>> elf=ELF(which('bash'))
        >>> rop=ROP([elf])
        >>> rop.rdi     == rop.search(regs=['rdi'], order = 'regs')
        True
        >>> rop.r13_r14_r15_rbp == rop.search(regs=['r13','r14','r15','rbp'], order = 'regs')
        True
        >>> rop.ret_8   == rop.search(move=8)
        True
        >>> rop.ret is not None
        True
        >>> with context.local(arch='amd64', bits='64'):
        ...     r = ROP(ELF.from_assembly('syscall; ret'))
        >>> r.syscall is not None
        True
        """
        ...

    def __init__(self, elfs, base=None, badchars=b'', **kwargs):
        r"""
        Arguments:
            elfs(list): List of :class:`.ELF` objects for mining
            base(int): Stack address where the first byte of the ROP chain lies, if known.
            badchars(str): Characters which should not appear in ROP gadget addresses.
        """
        ...

    def __repr__(self):
        r"""
        Return repr(self).
        """
        ...

    def __setattr__(self, attr, value):
        r"""
        Helper for setting registers.

        This convenience feature allows one to set the values of registers
        with simple python assignment syntax.

        Warning:
            Only one register is set at a time (one per rop chain).
            This may lead to some previously set to registers be overwritten!

        Note:
            If you would like to set multiple registers in as few rop chains
            as possible, see :meth:`__call__`.

        >>> context.clear(arch='amd64')
        >>> assembly = 'pop rax; pop rdi; pop rsi; ret; pop rax; ret;'
        >>> e = ELF.from_assembly(assembly)
        >>> r = ROP(e)
        >>> r.rax = 0xdead
        >>> r.rdi = 0xbeef
        >>> r.rsi = 0xcafe
        >>> print(r.dump())
        0x0000:       0x10000004 pop rax; ret
        0x0008:           0xdead
        0x0010:       0x10000001 pop rdi; pop rsi; ret
        0x0018:           0xbeef
        0x0020:      b'iaaajaaa' <pad rsi>
        0x0028:       0x10000002 pop rsi; ret
        0x0030:           0xcafe
        """
        ...

    def _srop_call(self, resolvable, arguments):

        ...

    def build(self, base=None, description=None):
        r"""
        Construct the ROP chain into a list of elements which can be passed
        to :func:`.flat`.

        Arguments:
            base(int):
                The base address to build the rop-chain from. Defaults to
                :attr:`base`.
            description(dict):
                Optional output argument, which will gets a mapping of
                ``address: description`` for each address on the stack,
                starting at ``base``.
        """
        ...

    def call(self, resolvable, arguments=(), abi=None, **kwargs):
        r"""
        Add a call to the ROP chain

        Arguments:
            resolvable(str,int): Value which can be looked up via 'resolve',
                or is already an integer.
            arguments(list): List of arguments which can be passed to pack().
                Alternately, if a base address is set, arbitrarily nested
                structures of strings or integers can be provided.
        """
        ...

    def chain(self, base=None):
        r"""
        Build the ROP chain

        Arguments:
            base(int):
                The base address to build the rop-chain from. Defaults to
                :attr:`base`.

        Returns:
            str containing raw ROP bytes
        """
        ...

    def clear_cache():
        r"""
        Clears the ROP gadget cache
        """
        ...

    def describe(self, object):
        r"""
        Return a description for an object in the ROP stack
        """
        ...

    def dump(self, base=None):
        r"""
        Dump the ROP chain in an easy-to-read manner

        Arguments:
            base(int):
                The base address to build the rop-chain from. Defaults to
                :attr:`base`.
        """
        ...

    def find_gadget(self, instructions):
        r"""
        Returns a gadget with the exact sequence of instructions specified
        in the ``instructions`` argument.
        """
        ...

    def find_stack_adjustment(self, slots):

        ...

    def from_blob(blob, *a, **kw):

        ...

    def generatePadding(self, offset, count):
        r"""
        Generates padding to be inserted into the ROP stack.

        >>> context.clear(arch='i386')
        >>> rop = ROP([])
        >>> val = rop.generatePadding(5,15)
        >>> cyclic_find(val[:4])
        5
        >>> len(val)
        15
        >>> rop.generatePadding(0,0)
        b''
        """
        ...

    def migrate(self, next_base):
        r"""
        Explicitly set $sp, by using a ``leave; ret`` gadget
        """
        ...

    def raw(self, value):
        r"""
        Adds a raw integer or string to the ROP chain.

        If your architecture requires aligned values, then make
        sure that any given string is aligned!

        Arguments:
            data(int/str): The raw value to put onto the rop chain.

        >>> context.clear(arch='i386')
        >>> rop = ROP([])
        >>> rop.raw('AAAAAAAA')
        >>> rop.raw('BBBBBBBB')
        >>> rop.raw('CCCCCCCC')
        >>> print(rop.dump())
        0x0000:          b'AAAA' 'AAAAAAAA'
        0x0004:          b'AAAA'
        0x0008:          b'BBBB' 'BBBBBBBB'
        0x000c:          b'BBBB'
        0x0010:          b'CCCC' 'CCCCCCCC'
        0x0014:          b'CCCC'
        """
        ...

    def regs(self, registers=None, **kw):

        ...

    def resolve(self, resolvable):
        r"""
        Resolves a symbol to an address

        Arguments:
            resolvable(str,int): Thing to convert into an address

        Returns:
            int containing address of 'resolvable', or None
        """
        ...

    def ret2dlresolve(self, dlresolve):

        ...

    def search(self, move=0, regs=None, order='size'):
        r"""
        Search for a gadget which matches the specified criteria.

        Arguments:
            move(int): Minimum number of bytes by which the stack
                pointer is adjusted.
            regs(list): Minimum list of registers which are popped off the
                stack.
            order(str): Either the string 'size' or 'regs'. Decides how to
                order multiple gadgets the fulfill the requirements.

        The search will try to minimize the number of bytes popped more than
        requested, the number of registers touched besides the requested and
        the address.

        If ``order == 'size'``, then gadgets are compared lexicographically
        by ``(total_moves, total_regs, addr)``, otherwise by ``(total_regs, total_moves, addr)``.

        Returns:
            A :class:`.Gadget` object
        """
        ...

    def search_iter(self, move=None, regs=None):
        r"""
        Iterate through all gadgets which move the stack pointer by
        *at least* ``move`` bytes, and which allow you to set all
        registers in ``regs``.
        """
        ...

    def setRegisters(self, registers):
        r"""
        Returns an list of addresses/values which will set the specified register context.

        Arguments:
            registers(dict): Dictionary of ``{register name: value}``

        Returns:
            A list of tuples, ordering the stack.

            Each tuple is in the form of ``(value, name)`` where ``value`` is either a
            gadget address or literal value to go on the stack, and ``name`` is either
            a string name or other item which can be "unresolved".

        Note:
            This is basically an implementation of the Set Cover Problem, which is
            NP-hard.  This means that we will take polynomial time N**2, where N is
            the number of gadgets.  We can reduce runtime by discarding useless and
            inferior gadgets ahead of time.
        """
        ...

    def unresolve(self, value):
        r"""
        Inverts 'resolve'.  Given an address, it attempts to find a symbol
        for it in the loaded ELF files.  If none is found, it searches all
        known gadgets, and returns the disassembly

        Arguments:
            value(int): Address to look up

        Returns:
            String containing the symbol name for the address, disassembly for a gadget
            (if there's one at that address), or an empty string.
        """
        ...


import pwnlib.rop.srop

class SigreturnFrame (builtins.dict):
    r"""
    Crafts a sigreturn frame with values that are loaded up into
    registers.

    Arguments:
        arch(str):
            The architecture. Currently ``i386`` and ``amd64`` are
            supported.

    Examples:

        Crafting a SigreturnFrame that calls mprotect on amd64

        >>> context.clear(arch='amd64')
        >>> s = SigreturnFrame()
        >>> unpack_many(bytes(s))
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 51, 0, 0, 0, 0, 0, 0, 0]
        >>> assert len(s) == 248
        >>> s.rax = 0xa
        >>> s.rdi = 0x00601000
        >>> s.rsi = 0x1000
        >>> s.rdx = 0x7
        >>> assert len(bytes(s)) == 248
        >>> unpack_many(bytes(s))
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 6295552, 4096, 0, 0, 7, 10, 0, 0, 0, 0, 51, 0, 0, 0, 0, 0, 0, 0]

        Crafting a SigreturnFrame that calls mprotect on i386

        >>> context.clear(arch='i386')
        >>> s = SigreturnFrame(kernel='i386')
        >>> unpack_many(bytes(s))
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 115, 0, 0, 123, 0]
        >>> assert len(s) == 80
        >>> s.eax = 125
        >>> s.ebx = 0x00601000
        >>> s.ecx = 0x1000
        >>> s.edx = 0x7
        >>> assert len(bytes(s)) == 80
        >>> unpack_many(bytes(s))
        [0, 0, 0, 0, 0, 0, 0, 0, 6295552, 7, 4096, 125, 0, 0, 0, 115, 0, 0, 123, 0]

        Crafting a SigreturnFrame that calls mprotect on ARM

        >>> s = SigreturnFrame(arch='arm')
        >>> unpack_many(bytes(s))
        [0, 0, 0, 0, 0, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1073741840, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1447448577, 288]
        >>> s.r0 = 125
        >>> s.r1 = 0x00601000
        >>> s.r2 = 0x1000
        >>> s.r3 = 0x7
        >>> assert len(bytes(s)) == 240
        >>> unpack_many(bytes(s))
        [0, 0, 0, 0, 0, 6, 0, 0, 125, 6295552, 4096, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1073741840, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1447448577, 288]

        Crafting a SigreturnFrame that calls mprotect on MIPS

        >>> context.clear()
        >>> context.endian = "big"
        >>> s = SigreturnFrame(arch='mips')
        >>> unpack_many(bytes(s))
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        >>> s.v0 = 0x101d
        >>> s.a0 = 0x00601000
        >>> s.a1 = 0x1000
        >>> s.a2 = 0x7
        >>> assert len(bytes(s)) == 296
        >>> unpack_many(bytes(s))
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4125, 0, 0, 0, 6295552, 0, 4096, 0, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]

        Crafting a SigreturnFrame that calls mprotect on MIPSel

        >>> context.clear()
        >>> context.endian = "little"
        >>> s = SigreturnFrame(arch='mips')
        >>> unpack_many(bytes(s))
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        >>> s.v0 = 0x101d
        >>> s.a0 = 0x00601000
        >>> s.a1 = 0x1000
        >>> s.a2 = 0x7
        >>> assert len(bytes(s)) == 292
        >>> unpack_many(bytes(s))
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4125, 0, 0, 0, 6295552, 0, 4096, 0, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]

        Crafting a SigreturnFrame that calls mprotect on Aarch64

        >>> context.clear()
        >>> context.endian = "little"
        >>> s = SigreturnFrame(arch='aarch64')
        >>> unpack_many(bytes(s))
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1179680769, 528]
        >>> s.x8 = 0xe2
        >>> s.x0 = 0x4000
        >>> s.x1 = 0x1000
        >>> s.x2 = 0x7
        >>> assert len(bytes(s)) == 600
        >>> unpack_many(bytes(s))
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16384, 0, 4096, 0, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 226, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1179680769, 528]
    """
    def __bytes__(self):

        ...

    def __flat__(self):

        ...

    def __getattr__(self, attr):

        ...

    def __init__(self):
        r"""
        Initialize self.  See help(type(self)) for accurate signature.
        """
        ...

    def __len__(self):
        r"""
        Return len(self).
        """
        ...

    def __setattr__(self, attr, value):
        r"""
        Implement setattr(self, name, value).
        """
        ...

    def __setitem__(self, item, value):
        r"""
        Set self[key] to value.
        """
        ...

    def __str__(self):
        r"""
        Return str(self).
        """
        ...

    def get_spindex(self):

        ...

    def set_regvalue(self, reg, val):
        r"""
        Sets a specific ``reg`` to a ``val``
        """
        ...


import pwnlib.runner

def run_assembly(assembly):
    r"""
    Given an assembly listing, assemble and execute it.

    Returns:

        A :class:`pwnlib.tubes.process.process` tube to interact with the process.

    Example:

        >>> p = run_assembly('mov ebx, 3; mov eax, SYS_exit; int 0x80;')
        >>> p.wait_for_close()
        >>> p.poll()
        3

        >>> p = run_assembly('mov r0, #12; mov r7, #1; svc #0', arch='arm')
        >>> p.wait_for_close()
        >>> p.poll()
        12
    """
    ...

def run_assembly_exitcode(assembly):
    r"""
    Given an assembly listing, assemble and execute it, and wait for
    the process to die.

    Returns:

        The exit code of the process.

    Example:

        >>> run_assembly_exitcode('mov ebx, 3; mov eax, SYS_exit; int 0x80;')
        3
    """
    ...

def run_shellcode(bytes, **kw):
    r"""
    Given assembled machine code bytes, execute them.

    Example:

        >>> bytes = asm('mov ebx, 3; mov eax, SYS_exit; int 0x80;')
        >>> p = run_shellcode(bytes)
        >>> p.wait_for_close()
        >>> p.poll()
        3

        >>> bytes = asm('mov r0, #12; mov r7, #1; svc #0', arch='arm')
        >>> p = run_shellcode(bytes, arch='arm')
        >>> p.wait_for_close()
        >>> p.poll()
        12
    """
    ...

def run_shellcode_exitcode(bytes):
    r"""
    Given assembled machine code bytes, execute them, and wait for
    the process to die.

    Returns:

        The exit code of the process.

    Example:

        >>> bytes = asm('mov ebx, 3; mov eax, SYS_exit; int 0x80;')
        >>> run_shellcode_exitcode(bytes)
        3
    """
    ...


import pwnlib.shellcraft


import pwnlib.term


import pwnlib.term.readline

def raw_input(prompt='', float=True):
    r"""
    raw_input(prompt='', float=True)

    Replacement for the built-in ``raw_input`` using ``pwnlib`` readline
    implementation.

    Arguments:
        prompt(str): The prompt to show to the user.
        float(bool): If set to `True`, prompt and input will float to the
                     bottom of the screen when `term.term_mode` is enabled.
    """
    ...

def str_input(prompt='', float=True):
    r"""
    str_input(prompt='', float=True)

    Replacement for the built-in ``input`` in python3 using ``pwnlib`` readline
    implementation.

    Arguments:
        prompt(str): The prompt to show to the user.
        float(bool): If set to `True`, prompt and input will float to the
                     bottom of the screen when `term.term_mode` is enabled.
    """
    ...


import pwnlib.term.text


import pwnlib.timeout

class Timeout:
    r"""
    Implements a basic class which has a timeout, and support for
    scoped timeout countdowns.

    Valid timeout values are:

    - ``Timeout.default`` use the global default value (``context.default``)
    - ``Timeout.forever`` or :const:`None` never time out
    - Any positive float, indicates timeouts in seconds

    Example:

        >>> context.timeout = 30
        >>> t = Timeout()
        >>> t.timeout == 30
        True
        >>> t = Timeout(5)
        >>> t.timeout == 5
        True
        >>> i = 0
        >>> with t.countdown():
        ...     print(4 <= t.timeout and t.timeout <= 5)
        ...
        True
        >>> with t.countdown(0.5): # doctest: +ELLIPSIS
        ...     while t.timeout:
        ...         print(round(t.timeout,1))
        ...         time.sleep(0.1)
        0.5
        0.4
        0.3
        0.2
        0.1
        >>> print(t.timeout)
        5.0
        >>> with t.local(0.5):# doctest: +ELLIPSIS
        ...     for i in range(5):
        ...         print(round(t.timeout,1))
        ...         time.sleep(0.1)
        0.5
        0.5
        0.5
        0.5
        ...
        >>> print(t.timeout)
        5.0
    """
    def __init__(self, timeout=pwnlib.timeout.Timeout.default):
        r"""
        Initialize self.  See help(type(self)) for accurate signature.
        """
        ...

    def _get_timeout_seconds(self, value):

        ...

    def countdown(self, timeout=pwnlib.timeout.Timeout.default):
        r"""
        Scoped timeout setter.  Sets the timeout within the scope,
        and restores it when leaving the scope.

        When accessing :attr:`timeout` within the scope, it will be
        calculated against the time when the scope was entered, in a
        countdown fashion.

        If :const:`None` is specified for ``timeout``, then the current
        timeout is used is made.  This allows :const:`None` to be specified
        as a default argument with less complexity.
        """
        ...

    def countdown_active(self):

        ...

    def local(self, timeout):
        r"""
        Scoped timeout setter.  Sets the timeout within the scope,
        and restores it when leaving the scope.
        """
        ...

    def timeout_change(self):
        r"""
        Callback for subclasses to hook a timeout change.
        """
        ...


import pwnlib.tubes


import pwnlib.tubes.buffer

class Buffer (builtins.Exception):
    r"""
    List of strings with some helper routines.

    Example:

        >>> b = Buffer()
        >>> b.add(b"A" * 10)
        >>> b.add(b"B" * 10)
        >>> len(b)
        20
        >>> b.get(1)
        b'A'
        >>> len(b)
        19
        >>> b.get(9999)
        b'AAAAAAAAABBBBBBBBBB'
        >>> len(b)
        0
        >>> b.get(1)
        b''

    Implementation Details:

        Implemented as a list.  Strings are added onto the end.
        The ``0th`` item in the buffer is the oldest item, and
        will be received first.
    """
    def __contains__(self, x):
        r"""
        >>> b = Buffer()
        >>> b.add(b'asdf')
        >>> b'x' in b
        False
        >>> b.add(b'x')
        >>> b'x' in b
        True
        """
        ...

    def __init__(self, buffer_fill_size=None):
        r"""
        Initialize self.  See help(type(self)) for accurate signature.
        """
        ...

    def __len__(self):
        r"""
        >>> b = Buffer()
        >>> b.add(b'lol')
        >>> len(b) == 3
        True
        >>> b.add(b'foobar')
        >>> len(b) == 9
        True
        """
        ...

    def __nonzero__(self):

        ...

    def add(self, data):
        r"""
        Adds data to the buffer.

        Arguments:
            data(str,Buffer): Data to add
        """
        ...

    def get(self, want=inf):
        r"""
        Retrieves bytes from the buffer.

        Arguments:
            want(int): Maximum number of bytes to fetch

        Returns:
            Data as string

        Example:

            >>> b = Buffer()
            >>> b.add(b'hello')
            >>> b.add(b'world')
            >>> b.get(1)
            b'h'
            >>> b.get()
            b'elloworld'
        """
        ...

    def get_fill_size(self, size=None):
        r"""
        Retrieves the default fill size for this buffer class.

        Arguments:
            size (int): (Optional) If set and not None, returns the size variable back.

        Returns:
            Fill size as integer if size is None, else size.
        """
        ...

    def index(self, x):
        r"""
        >>> b = Buffer()
        >>> b.add(b'asdf')
        >>> b.add(b'qwert')
        >>> b.index(b't') == len(b) - 1
        True
        """
        ...

    def unget(self, data):
        r"""
        Places data at the front of the buffer.

        Arguments:
            data(str,Buffer): Data to place at the beginning of the buffer.

        Example:

            >>> b = Buffer()
            >>> b.add(b"hello")
            >>> b.add(b"world")
            >>> b.get(5)
            b'hello'
            >>> b.unget(b"goodbye")
            >>> b.get()
            b'goodbyeworld'
        """
        ...


import pwnlib.tubes.listen

class listen (pwnlib.tubes.sock.sock):
    r"""
    Creates an TCP or UDP-socket to receive data on. It supports
    both IPv4 and IPv6.

    The returned object supports all the methods from
    :class:`pwnlib.tubes.sock` and :class:`pwnlib.tubes.tube`.

    Arguments:
        port(int): The port to connect to.
            Defaults to a port auto-selected by the operating system.
        bindaddr(str): The address to bind to.
            Defaults to ``0.0.0.0`` / `::`.
        fam: The string "any", "ipv4" or "ipv6" or an integer to pass to :func:`socket.getaddrinfo`.
        typ: The string "tcp" or "udp" or an integer to pass to :func:`socket.getaddrinfo`.

    Examples:

        >>> l = listen(1234)
        >>> r = remote('localhost', l.lport)
        >>> _ = l.wait_for_connection()
        >>> l.sendline(b'Hello')
        >>> r.recvline()
        b'Hello\n'

        >>> # It works with ipv4 by default
        >>> l = listen()
        >>> l.spawn_process('/bin/sh')
        >>> r = remote('127.0.0.1', l.lport)
        >>> r.sendline(b'echo Goodbye')
        >>> r.recvline()
        b'Goodbye\n'

        >>> # and it works with ipv6 by defaut, too!
        >>> l = listen()
        >>> r = remote('::1', l.lport)
        >>> r.sendline(b'Bye-bye')
        >>> l.recvline()
        b'Bye-bye\n'
    """
    def __enter__(self):
        r"""
        Permit use of 'with' to control scoping and closing sessions.

        Examples:

            >>> t = tube()
            >>> def p(x): print(x)
            >>> t.close = lambda: p("Closed!")
            >>> with t: pass
            Closed!
        """
        ...

    def __exit__(self, type, value, traceback):
        r"""
        Handles closing for 'with' statement

        See :meth:`__enter__`
        """
        ...

    def __getattr__(self, key):

        ...

    def __init__(self, port=0, bindaddr='::', fam='any', typ='tcp', *args, **kwargs):
        r"""
        Initialize self.  See help(type(self)) for accurate signature.
        """
        ...

    def __lshift__(self, other):
        r"""
        Shorthand for connecting multiple tubes.

        See :meth:`connect_input` for more information.

        Examples:

            The following are equivalent ::

                tube_a >> tube.b
                tube_a.connect_input(tube_b)

            This is useful when chaining multiple tubes ::

                tube_a >> tube_b >> tube_a
                tube_a.connect_input(tube_b)
                tube_b.connect_input(tube_a)
        """
        ...

    def __ne__(self, other):
        r"""
        Shorthand for connecting tubes to eachother.

        The following are equivalent ::

            a >> b >> a
            a <> b

        See :meth:`connect_input` for more information.
        """
        ...

    def __rshift__(self, other):
        r"""
        Inverse of the ``<<`` operator.  See :meth:`__lshift__`.

        See :meth:`connect_input` for more information.
        """
        ...

    def _close_msg(self):

        ...

    def _fillbuffer(self, timeout=pwnlib.timeout.Timeout.default):
        r"""
        _fillbuffer(timeout = default)

        Fills the internal buffer from the pipe, by calling
        :meth:`recv_raw` exactly once.

        Returns:

            The bytes of data received, or ``''`` if no data was received.

        Examples:

            >>> t = tube()
            >>> t.recv_raw = lambda *a: b'abc'
            >>> len(t.buffer)
            0
            >>> t._fillbuffer()
            b'abc'
            >>> len(t.buffer)
            3
        """
        ...

    def _get_timeout_seconds(self, value):

        ...

    def _getlevel(self, levelString):

        ...

    def _log(self, level, msg, args, kwargs, msgtype, progress=None):

        ...

    def _read(self, *a, **kw):
        r"""
        Alias for :meth:`_recv`
        """
        ...

    def _recv(self, numb=None, timeout=pwnlib.timeout.Timeout.default):
        r"""
        _recv(numb = 4096, timeout = default) -> str

        Receives one chunk of from the internal buffer or from the OS if the
        buffer is empty.
        """
        ...

    def addHandler(self, handler):
        r"""
        addHandler(handler)

        Add the specified handler to the underlying logger.
        """
        ...

    def can_read(self, *a, **kw):
        r"""
        Alias for :meth:`can_recv`
        """
        ...

    def can_read_raw(self, *a, **kw):
        r"""
        Alias for :meth:`can_recv_raw`
        """
        ...

    def can_recv(self, timeout=0):
        r"""
        can_recv(timeout = 0) -> bool

        Returns True, if there is data available within `timeout` seconds.

        Examples:

            >>> import time
            >>> t = tube()
            >>> t.can_recv_raw = lambda *a: False
            >>> t.can_recv()
            False
            >>> _=t.unrecv(b'data')
            >>> t.can_recv()
            True
            >>> _=t.recv()
            >>> t.can_recv()
            False
        """
        ...

    def can_recv_raw(self, timeout):
        r"""
        Tests:

            >>> l = listen()
            >>> r = remote('localhost', l.lport)
            >>> r.can_recv_raw(timeout=0)
            False
            >>> l.send(b'a')
            >>> r.can_recv_raw(timeout=1)
            True
            >>> r.recv()
            b'a'
            >>> r.can_recv_raw(timeout=0)
            False
            >>> l.close()
            >>> r.can_recv_raw(timeout=1)
            False
            >>> r.closed['recv']
            True
        """
        ...

    def clean(self, timeout=0.05):
        r"""
        clean(timeout = 0.05)

        Removes all the buffered data from a tube by calling
        :meth:`pwnlib.tubes.tube.tube.recv` with a low timeout until it fails.

        If ``timeout`` is zero, only cached data will be cleared.

        Note: If timeout is set to zero, the underlying network is
        not actually polled; only the internal buffer is cleared.

        Returns:

            All data received

        Examples:

            >>> t = tube()
            >>> t.unrecv(b'clean me up')
            >>> t.clean(0)
            b'clean me up'
            >>> len(t.buffer)
            0
        """
        ...

    def clean_and_log(self, timeout=0.05):
        r"""
        clean_and_log(timeout = 0.05)

        Works exactly as :meth:`pwnlib.tubes.tube.tube.clean`, but logs received
        data with :meth:`pwnlib.self.info`.

        Returns:

            All data received

        Examples:

            >>> def recv(n, data=[b'', b'hooray_data']):
            ...     while data: return data.pop()
            >>> t = tube()
            >>> t.recv_raw      = recv
            >>> t.connected_raw = lambda d: True
            >>> t.fileno        = lambda: 1234
            >>> with context.local(log_level='info'):
            ...     data = t.clean_and_log() #doctest: +ELLIPSIS
            [DEBUG] Received 0xb bytes:
                b'hooray_data'
            >>> data
            b'hooray_data'
            >>> context.clear()
        """
        ...

    def close(self):
        r"""
        close()

        Closes the tube.
        """
        ...

    def connect_both(self, other):
        r"""
        connect_both(other)

        Connects the both ends of this tube object with another tube object.
        """
        ...

    def connect_input(self, other):
        r"""
        connect_input(other)

        Connects the input of this tube to the output of another tube object.


        Examples:

            >>> def p(x): print(x.decode())
            >>> def recvone(n, data=[b'data']):
            ...     while data: return data.pop()
            ...     raise EOFError
            >>> a = tube()
            >>> b = tube()
            >>> a.recv_raw = recvone
            >>> b.send_raw = p
            >>> a.connected_raw = lambda d: True
            >>> b.connected_raw = lambda d: True
            >>> a.shutdown      = lambda d: True
            >>> b.shutdown      = lambda d: True
            >>> import time
            >>> _=(b.connect_input(a), time.sleep(0.1))
            data
        """
        ...

    def connect_output(self, other):
        r"""
        connect_output(other)

        Connects the output of this tube to the input of another tube object.

        Examples:

            >>> def p(x): print(repr(x))
            >>> def recvone(n, data=[b'data']):
            ...     while data: return data.pop()
            ...     raise EOFError
            >>> a = tube()
            >>> b = tube()
            >>> a.recv_raw = recvone
            >>> b.send_raw = p
            >>> a.connected_raw = lambda d: True
            >>> b.connected_raw = lambda d: True
            >>> a.shutdown      = lambda d: True
            >>> b.shutdown      = lambda d: True
            >>> _=(a.connect_output(b), time.sleep(0.1))
            b'data'
        """
        ...

    def connected(self, direction='any'):
        r"""
        connected(direction = 'any') -> bool

        Returns True if the tube is connected in the specified direction.

        Arguments:
          direction(str): Can be the string 'any', 'in', 'read', 'recv',
                          'out', 'write', 'send'.

        Doctest:

            >>> def p(x): print(x)
            >>> t = tube()
            >>> t.connected_raw = p
            >>> _=list(map(t.connected, ('any', 'in', 'read', 'recv', 'out', 'write', 'send')))
            any
            recv
            recv
            recv
            send
            send
            send
            >>> t.connected('bad_value') #doctest: +ELLIPSIS
            Traceback (most recent call last):
            ...
            KeyError: "direction must be in ['any', 'in', 'out', 'read', 'recv', 'send', 'write']"
        """
        ...

    def connected_raw(self, direction):
        r"""
        Tests:

            >>> l = listen()
            >>> r = remote('localhost', l.lport)
            >>> r.connected()
            True
            >>> l.close()
            >>> time.sleep(0.1) # Avoid race condition
            >>> r.connected()
            False
        """
        ...

    def countdown(self, timeout=pwnlib.timeout.Timeout.default):
        r"""
        Scoped timeout setter.  Sets the timeout within the scope,
        and restores it when leaving the scope.

        When accessing :attr:`timeout` within the scope, it will be
        calculated against the time when the scope was entered, in a
        countdown fashion.

        If :const:`None` is specified for ``timeout``, then the current
        timeout is used is made.  This allows :const:`None` to be specified
        as a default argument with less complexity.
        """
        ...

    def countdown_active(self):

        ...

    def critical(self, message, *args, **kwargs):
        r"""
        critical(message, *args, **kwargs)

        Logs a critical message.
        """
        ...

    def debug(self, message, *args, **kwargs):
        r"""
        debug(message, *args, **kwargs)

        Logs a debug message.
        """
        ...

    def error(self, message, *args, **kwargs):
        r"""
        error(message, *args, **kwargs)

        To be called outside an exception handler.

        Logs an error message, then raises a ``PwnlibException``.
        """
        ...

    def exception(self, message, *args, **kwargs):
        r"""
        exception(message, *args, **kwargs)

        To be called from an exception handler.

        Logs a error message, then re-raises the current exception.
        """
        ...

    def failure(self, message, *args, **kwargs):
        r"""
        failure(message, *args, **kwargs)

        Logs a failure message.
        """
        ...

    def fileno(self):
        r"""
        fileno() -> int

        Returns the file number used for reading.
        """
        ...

    def fit(self, *a, **kw):

        ...

    def flat(self, *a, **kw):

        ...

    def hexdump(self, message, *args, **kwargs):

        ...

    def indented(self, message, *args, **kwargs):
        r"""
        indented(message, *args, level = logging.INFO, **kwargs)

        Log a message but don't put a line prefix on it.

        Arguments:
            level(int): Alternate log level at which to set the indented
                        message.  Defaults to :const:`logging.INFO`.
        """
        ...

    def info(self, message, *args, **kwargs):
        r"""
        info(message, *args, **kwargs)

        Logs an info message.
        """
        ...

    def info_once(self, message, *args, **kwargs):
        r"""
        info_once(message, *args, **kwargs)

        Logs an info message.  The same message is never printed again.
        """
        ...

    def interactive(self, prompt='\x1b[1m\x1b[31m$\x1b[m '):
        r"""
        interactive(prompt = pwnlib.term.text.bold_red('$') + ' ')

        Does simultaneous reading and writing to the tube. In principle this just
        connects the tube to standard in and standard out, but in practice this
        is much more usable, since we are using :mod:`pwnlib.term` to print a
        floating prompt.

        Thus it only works in while in :data:`pwnlib.term.term_mode`.
        """
        ...

    def isEnabledFor(self, level):
        r"""
        isEnabledFor(level) -> bool

        See if the underlying logger is enabled for the specified level.
        """
        ...

    def local(self, timeout):
        r"""
        Scoped timeout setter.  Sets the timeout within the scope,
        and restores it when leaving the scope.
        """
        ...

    def log(self, level, message, *args, **kwargs):
        r"""
        log(level, message, *args, **kwargs)

        Logs a message with log level `level`.  The ``pwnlib`` formatter will
        use the default :mod:`logging` formater to format this message.
        """
        ...

    def p16(self, *a, **kw):

        ...

    def p32(self, *a, **kw):

        ...

    def p64(self, *a, **kw):

        ...

    def p8(self, *a, **kw):

        ...

    def pack(self, *a, **kw):

        ...

    def progress(self, message, status='', *args, **kwargs):
        r"""
        progress(message, status = '', *args, level = logging.INFO, **kwargs) -> Progress

        Creates a new progress logger which creates log records with log level
        `level`.

        Progress status can be updated using :meth:`Progress.status` and stopped
        using :meth:`Progress.success` or :meth:`Progress.failure`.

        If `term.term_mode` is enabled the progress logger will be animated.

        The progress manager also functions as a context manager.  Using context
        managers ensures that animations stop even if an exception is raised.

        .. code-block:: python

           with log.progress('Trying something...') as p:
               for i in range(10):
                   p.status("At %i" % i)
                   time.sleep(0.5)
               x = 1/0
        """
        ...

    def read(self, *a, **kw):
        r"""
        Alias for :meth:`recv`
        """
        ...

    def readS(self, *a, **kw):
        r"""
        Alias for :meth:`recvS`
        """
        ...

    def read_raw(self, *a, **kw):
        r"""
        Alias for :meth:`recv_raw`
        """
        ...

    def readall(self, *a, **kw):
        r"""
        Alias for :meth:`recvall`
        """
        ...

    def readallS(self, *a, **kw):
        r"""
        Alias for :meth:`recvallS`
        """
        ...

    def readallb(self, *a, **kw):
        r"""
        Alias for :meth:`recvallb`
        """
        ...

    def readb(self, *a, **kw):
        r"""
        Alias for :meth:`recvb`
        """
        ...

    def readline(self, *a, **kw):
        r"""
        Alias for :meth:`recvline`
        """
        ...

    def readlineS(self, *a, **kw):
        r"""
        Alias for :meth:`recvlineS`
        """
        ...

    def readline_contains(self, *a, **kw):
        r"""
        Alias for :meth:`recvline_contains`
        """
        ...

    def readline_containsS(self, *a, **kw):
        r"""
        Alias for :meth:`recvline_containsS`
        """
        ...

    def readline_containsb(self, *a, **kw):
        r"""
        Alias for :meth:`recvline_containsb`
        """
        ...

    def readline_endswith(self, *a, **kw):
        r"""
        Alias for :meth:`recvline_endswith`
        """
        ...

    def readline_endswithS(self, *a, **kw):
        r"""
        Alias for :meth:`recvline_endswithS`
        """
        ...

    def readline_endswithb(self, *a, **kw):
        r"""
        Alias for :meth:`recvline_endswithb`
        """
        ...

    def readline_pred(self, *a, **kw):
        r"""
        Alias for :meth:`recvline_pred`
        """
        ...

    def readline_regex(self, *a, **kw):
        r"""
        Alias for :meth:`recvline_regex`
        """
        ...

    def readline_regexS(self, *a, **kw):
        r"""
        Alias for :meth:`recvline_regexS`
        """
        ...

    def readline_regexb(self, *a, **kw):
        r"""
        Alias for :meth:`recvline_regexb`
        """
        ...

    def readline_startswith(self, *a, **kw):
        r"""
        Alias for :meth:`recvline_startswith`
        """
        ...

    def readline_startswithS(self, *a, **kw):
        r"""
        Alias for :meth:`recvline_startswithS`
        """
        ...

    def readline_startswithb(self, *a, **kw):
        r"""
        Alias for :meth:`recvline_startswithb`
        """
        ...

    def readlineb(self, *a, **kw):
        r"""
        Alias for :meth:`recvlineb`
        """
        ...

    def readlines(self, *a, **kw):
        r"""
        Alias for :meth:`recvlines`
        """
        ...

    def readlinesS(self, *a, **kw):
        r"""
        Alias for :meth:`recvlinesS`
        """
        ...

    def readlinesb(self, *a, **kw):
        r"""
        Alias for :meth:`recvlinesb`
        """
        ...

    def readn(self, *a, **kw):
        r"""
        Alias for :meth:`recvn`
        """
        ...

    def readnS(self, *a, **kw):
        r"""
        Alias for :meth:`recvnS`
        """
        ...

    def readnb(self, *a, **kw):
        r"""
        Alias for :meth:`recvnb`
        """
        ...

    def readpred(self, *a, **kw):
        r"""
        Alias for :meth:`recvpred`
        """
        ...

    def readpredS(self, *a, **kw):
        r"""
        Alias for :meth:`recvpredS`
        """
        ...

    def readpredb(self, *a, **kw):
        r"""
        Alias for :meth:`recvpredb`
        """
        ...

    def readregex(self, *a, **kw):
        r"""
        Alias for :meth:`recvregex`
        """
        ...

    def readregexS(self, *a, **kw):
        r"""
        Alias for :meth:`recvregexS`
        """
        ...

    def readregexb(self, *a, **kw):
        r"""
        Alias for :meth:`recvregexb`
        """
        ...

    def readrepeat(self, *a, **kw):
        r"""
        Alias for :meth:`recvrepeat`
        """
        ...

    def readrepeatS(self, *a, **kw):
        r"""
        Alias for :meth:`recvrepeatS`
        """
        ...

    def readrepeatb(self, *a, **kw):
        r"""
        Alias for :meth:`recvrepeatb`
        """
        ...

    def readuntil(self, *a, **kw):
        r"""
        Alias for :meth:`recvuntil`
        """
        ...

    def readuntilS(self, *a, **kw):
        r"""
        Alias for :meth:`recvuntilS`
        """
        ...

    def readuntilb(self, *a, **kw):
        r"""
        Alias for :meth:`recvuntilb`
        """
        ...

    def recv(self, numb=None, timeout=pwnlib.timeout.Timeout.default):
        r"""
        recv(numb = 4096, timeout = default) -> bytes

        Receives up to `numb` bytes of data from the tube, and returns
        as soon as any quantity of data is available.

        If the request is not satisfied before ``timeout`` seconds pass,
        all data is buffered and an empty string (``''``) is returned.

        Raises:
            exceptions.EOFError: The connection is closed

        Returns:
            A bytes object containing bytes received from the socket,
            or ``''`` if a timeout occurred while waiting.

        Examples:

            >>> t = tube()
            >>> # Fake a data source
            >>> t.recv_raw = lambda n: b'Hello, world'
            >>> t.recv() == b'Hello, world'
            True
            >>> t.unrecv(b'Woohoo')
            >>> t.recv() == b'Woohoo'
            True
            >>> with context.local(log_level='debug'):
            ...    _ = t.recv() # doctest: +ELLIPSIS
            [...] Received 0xc bytes:
                b'Hello, world'
        """
        ...

    def recvS(self, *a, **kw):
        r"""
        Same as :meth:`recv`, but returns a str, decoding the result using `context.encoding`. (note that the binary versions are way faster)
        """
        ...

    def recv_raw(self, numb, *a):
        r"""
        recv_raw(numb) -> str

        Should not be called directly. Receives data without using the buffer
        on the object.

        Unless there is a timeout or closed connection, this should always
        return data. In case of a timeout, it should return None, in case
        of a closed connection it should raise an ``exceptions.EOFError``.
        """
        ...

    def recvall(self, timeout=None):
        r"""
        recvall() -> str

        Receives data until the socket is closed.
        """
        ...

    def recvallS(self, *a, **kw):
        r"""
        Same as :meth:`recvall`, but returns a str, decoding the result using `context.encoding`. (note that the binary versions are way faster)
        """
        ...

    def recvallb(self, *a, **kw):
        r"""
        Same as :meth:`recvall`, but returns a bytearray
        """
        ...

    def recvb(self, *a, **kw):
        r"""
        Same as :meth:`recv`, but returns a bytearray
        """
        ...

    def recvline(self, keepends=True, timeout=pwnlib.timeout.Timeout.default):
        r"""
        recvline(keepends=True, timeout=default) -> bytes

        Receive a single line from the tube.

        A "line" is any sequence of bytes terminated by the byte sequence
        set in :attr:`newline`, which defaults to ``'\n'``.

        If the request is not satisfied before ``timeout`` seconds pass,
        all data is buffered and an empty string (``''``) is returned.

        Arguments:
            keepends(bool): Keep the line ending (:const:`True`).
            timeout(int): Timeout

        Return:
            All bytes received over the tube until the first
            newline ``'\n'`` is received.  Optionally retains
            the ending.

        Examples:

            >>> t = tube()
            >>> t.recv_raw = lambda n: b'Foo\nBar\r\nBaz\n'
            >>> t.recvline()
            b'Foo\n'
            >>> t.recvline()
            b'Bar\r\n'
            >>> t.recvline(keepends = False)
            b'Baz'
            >>> t.newline = b'\r\n'
            >>> t.recvline(keepends = False)
            b'Foo\nBar'
        """
        ...

    def recvlineS(self, *a, **kw):
        r"""
        Same as :meth:`recvline`, but returns a str, decoding the result using `context.encoding`. (note that the binary versions are way faster)
        """
        ...

    def recvline_contains(self, items, keepends=False, timeout=pwnlib.timeout.Timeout.default):
        r"""
        Receive lines until one line is found which contains at least
        one of `items`.

        Arguments:
            items(str,tuple): List of strings to search for, or a single string.
            keepends(bool): Return lines with newlines if :const:`True`
            timeout(int): Timeout, in seconds

        Examples:

            >>> t = tube()
            >>> t.recv_raw = lambda n: b"Hello\nWorld\nXylophone\n"
            >>> t.recvline_contains(b'r')
            b'World'
            >>> f = lambda n: b"cat dog bird\napple pear orange\nbicycle car train\n"
            >>> t = tube()
            >>> t.recv_raw = f
            >>> t.recvline_contains(b'pear')
            b'apple pear orange'
            >>> t = tube()
            >>> t.recv_raw = f
            >>> t.recvline_contains((b'car', b'train'))
            b'bicycle car train'
        """
        ...

    def recvline_containsS(self, *a, **kw):
        r"""
        Same as :meth:`recvline_contains`, but returns a str, decoding the result using `context.encoding`. (note that the binary versions are way faster)
        """
        ...

    def recvline_containsb(self, *a, **kw):
        r"""
        Same as :meth:`recvline_contains`, but returns a bytearray
        """
        ...

    def recvline_endswith(self, delims, keepends=False, timeout=pwnlib.timeout.Timeout.default):
        r"""
        recvline_endswith(delims, keepends=False, timeout=default) -> bytes

        Keep receiving lines until one is found that ends with one of
        `delims`.  Returns the last line received.

        If the request is not satisfied before ``timeout`` seconds pass,
        all data is buffered and an empty string (``''``) is returned.

        See :meth:`recvline_startswith` for more details.

        Examples:

            >>> t = tube()
            >>> t.recv_raw = lambda n: b'Foo\nBar\nBaz\nKaboodle\n'
            >>> t.recvline_endswith(b'r')
            b'Bar'
            >>> t.recvline_endswith((b'a',b'b',b'c',b'd',b'e'), True)
            b'Kaboodle\n'
            >>> t.recvline_endswith(b'oodle')
            b'Kaboodle'
        """
        ...

    def recvline_endswithS(self, *a, **kw):
        r"""
        Same as :meth:`recvline_endswith`, but returns a str, decoding the result using `context.encoding`. (note that the binary versions are way faster)
        """
        ...

    def recvline_endswithb(self, *a, **kw):
        r"""
        Same as :meth:`recvline_endswith`, but returns a bytearray
        """
        ...

    def recvline_pred(self, pred, keepends=False, timeout=pwnlib.timeout.Timeout.default):
        r"""
        recvline_pred(pred, keepends=False) -> bytes

        Receive data until ``pred(line)`` returns a truthy value.
        Drop all other data.

        If the request is not satisfied before ``timeout`` seconds pass,
        all data is buffered and an empty string (``''``) is returned.

        Arguments:
            pred(callable): Function to call.  Returns the line for which
                this function returns :const:`True`.

        Examples:

            >>> t = tube()
            >>> t.recv_raw = lambda n: b"Foo\nBar\nBaz\n"
            >>> t.recvline_pred(lambda line: line == b"Bar\n")
            b'Bar'
            >>> t.recvline_pred(lambda line: line == b"Bar\n", keepends=True)
            b'Bar\n'
            >>> t.recvline_pred(lambda line: line == b'Nope!', timeout=0.1)
            b''
        """
        ...

    def recvline_regex(self, regex, exact=False, keepends=False, timeout=pwnlib.timeout.Timeout.default):
        r"""
        recvline_regex(regex, exact=False, keepends=False, timeout=default) -> bytes

        Wrapper around :func:`recvline_pred`, which will return when a regex
        matches a line.

        By default :func:`re.RegexObject.search` is used, but if `exact` is
        set to True, then :func:`re.RegexObject.match` will be used instead.

        If the request is not satisfied before ``timeout`` seconds pass,
        all data is buffered and an empty string (``''``) is returned.
        """
        ...

    def recvline_regexS(self, *a, **kw):
        r"""
        Same as :meth:`recvline_regex`, but returns a str, decoding the result using `context.encoding`. (note that the binary versions are way faster)
        """
        ...

    def recvline_regexb(self, *a, **kw):
        r"""
        Same as :meth:`recvline_regex`, but returns a bytearray
        """
        ...

    def recvline_startswith(self, delims, keepends=False, timeout=pwnlib.timeout.Timeout.default):
        r"""
        recvline_startswith(delims, keepends=False, timeout=default) -> bytes

        Keep receiving lines until one is found that starts with one of
        `delims`.  Returns the last line received.

        If the request is not satisfied before ``timeout`` seconds pass,
        all data is buffered and an empty string (``''``) is returned.

        Arguments:
            delims(str,tuple): List of strings to search for, or string of single characters
            keepends(bool): Return lines with newlines if :const:`True`
            timeout(int): Timeout, in seconds

        Returns:
            The first line received which starts with a delimiter in ``delims``.

        Examples:

            >>> t = tube()
            >>> t.recv_raw = lambda n: b"Hello\nWorld\nXylophone\n"
            >>> t.recvline_startswith((b'W',b'X',b'Y',b'Z'))
            b'World'
            >>> t.recvline_startswith((b'W',b'X',b'Y',b'Z'), True)
            b'Xylophone\n'
            >>> t.recvline_startswith(b'Wo')
            b'World'
        """
        ...

    def recvline_startswithS(self, *a, **kw):
        r"""
        Same as :meth:`recvline_startswith`, but returns a str, decoding the result using `context.encoding`. (note that the binary versions are way faster)
        """
        ...

    def recvline_startswithb(self, *a, **kw):
        r"""
        Same as :meth:`recvline_startswith`, but returns a bytearray
        """
        ...

    def recvlineb(self, *a, **kw):
        r"""
        Same as :meth:`recvline`, but returns a bytearray
        """
        ...

    def recvlines(self, numlines=1048576, keepends=False, timeout=pwnlib.timeout.Timeout.default):
        r"""
        recvlines(numlines, keepends=False, timeout=default) -> list of bytes objects

        Receive up to ``numlines`` lines.

        A "line" is any sequence of bytes terminated by the byte sequence
        set by :attr:`newline`, which defaults to ``'\n'``.

        If the request is not satisfied before ``timeout`` seconds pass,
        all data is buffered and an empty string (``''``) is returned.

        Arguments:
            numlines(int): Maximum number of lines to receive
            keepends(bool): Keep newlines at the end of each line (:const:`False`).
            timeout(int): Maximum timeout

        Raises:
            exceptions.EOFError: The connection closed before the request could be satisfied

        Returns:
            A string containing bytes received from the socket,
            or ``''`` if a timeout occurred while waiting.

        Examples:

            >>> t = tube()
            >>> t.recv_raw = lambda n: b'\n'
            >>> t.recvlines(3)
            [b'', b'', b'']
            >>> t.recv_raw = lambda n: b'Foo\nBar\nBaz\n'
            >>> t.recvlines(3)
            [b'Foo', b'Bar', b'Baz']
            >>> t.recvlines(3, True)
            [b'Foo\n', b'Bar\n', b'Baz\n']
        """
        ...

    def recvlinesS(self, numlines=1048576, keepends=False, timeout=pwnlib.timeout.Timeout.default):
        r"""
        recvlinesS(numlines, keepends=False, timeout=default) -> str list

        This function is identical to :meth:`recvlines`, but decodes
        the received bytes into string using :func:`context.encoding`.
        You should use :meth:`recvlines` whenever possible for better performance.

        Examples:

            >>> t = tube()
            >>> t.recv_raw = lambda n: b'\n'
            >>> t.recvlinesS(3)
            ['', '', '']
            >>> t.recv_raw = lambda n: b'Foo\nBar\nBaz\n'
            >>> t.recvlinesS(3)
            ['Foo', 'Bar', 'Baz']
        """
        ...

    def recvlinesb(self, numlines=1048576, keepends=False, timeout=pwnlib.timeout.Timeout.default):
        r"""
        recvlinesb(numlines, keepends=False, timeout=default) -> bytearray list

        This function is identical to :meth:`recvlines`, but returns a bytearray.

        Examples:

            >>> t = tube()
            >>> t.recv_raw = lambda n: b'\n'
            >>> t.recvlinesb(3)
            [bytearray(b''), bytearray(b''), bytearray(b'')]
            >>> t.recv_raw = lambda n: b'Foo\nBar\nBaz\n'
            >>> t.recvlinesb(3)
            [bytearray(b'Foo'), bytearray(b'Bar'), bytearray(b'Baz')]
        """
        ...

    def recvn(self, numb, timeout=pwnlib.timeout.Timeout.default):
        r"""
        recvn(numb, timeout = default) -> str

        Receives exactly `n` bytes.

        If the request is not satisfied before ``timeout`` seconds pass,
        all data is buffered and an empty string (``''``) is returned.

        Raises:
            exceptions.EOFError: The connection closed before the request could be satisfied

        Returns:
            A string containing bytes received from the socket,
            or ``''`` if a timeout occurred while waiting.

        Examples:

            >>> t = tube()
            >>> data = b'hello world'
            >>> t.recv_raw = lambda *a: data
            >>> t.recvn(len(data)) == data
            True
            >>> t.recvn(len(data)+1) == data + data[:1]
            True
            >>> t.recv_raw = lambda *a: None
            >>> # The remaining data is buffered
            >>> t.recv() == data[1:]
            True
            >>> t.recv_raw = lambda *a: time.sleep(0.01) or b'a'
            >>> t.recvn(10, timeout=0.05)
            b''
            >>> t.recvn(10, timeout=0.06) # doctest: +ELLIPSIS
            b'aaaaaa...'
        """
        ...

    def recvnS(self, *a, **kw):
        r"""
        Same as :meth:`recvn`, but returns a str, decoding the result using `context.encoding`. (note that the binary versions are way faster)
        """
        ...

    def recvnb(self, *a, **kw):
        r"""
        Same as :meth:`recvn`, but returns a bytearray
        """
        ...

    def recvpred(self, pred, timeout=pwnlib.timeout.Timeout.default):
        r"""
        recvpred(pred, timeout = default) -> bytes

        Receives one byte at a time from the tube, until ``pred(all_bytes)``
        evaluates to True.

        If the request is not satisfied before ``timeout`` seconds pass,
        all data is buffered and an empty string (``''``) is returned.

        Arguments:
            pred(callable): Function to call, with the currently-accumulated data.
            timeout(int): Timeout for the operation

        Raises:
            exceptions.EOFError: The connection is closed

        Returns:
            A bytes object containing bytes received from the socket,
            or ``''`` if a timeout occurred while waiting.
        """
        ...

    def recvpredS(self, *a, **kw):
        r"""
        Same as :meth:`recvpred`, but returns a str, decoding the result using `context.encoding`. (note that the binary versions are way faster)
        """
        ...

    def recvpredb(self, *a, **kw):
        r"""
        Same as :meth:`recvpred`, but returns a bytearray
        """
        ...

    def recvregex(self, regex, exact=False, timeout=pwnlib.timeout.Timeout.default):
        r"""
        recvregex(regex, exact=False, timeout=default) -> bytes

        Wrapper around :func:`recvpred`, which will return when a regex
        matches the string in the buffer.

        By default :func:`re.RegexObject.search` is used, but if `exact` is
        set to True, then :func:`re.RegexObject.match` will be used instead.

        If the request is not satisfied before ``timeout`` seconds pass,
        all data is buffered and an empty string (``''``) is returned.
        """
        ...

    def recvregexS(self, *a, **kw):
        r"""
        Same as :meth:`recvregex`, but returns a str, decoding the result using `context.encoding`. (note that the binary versions are way faster)
        """
        ...

    def recvregexb(self, *a, **kw):
        r"""
        Same as :meth:`recvregex`, but returns a bytearray
        """
        ...

    def recvrepeat(self, timeout=pwnlib.timeout.Timeout.default):
        r"""
        recvrepeat(timeout=default) -> bytes

        Receives data until a timeout or EOF is reached.

        Examples:

            >>> data = [
            ... b'd',
            ... b'', # simulate timeout
            ... b'c',
            ... b'b',
            ... b'a',
            ... ]
            >>> def delayrecv(n, data=data):
            ...     return data.pop()
            >>> t = tube()
            >>> t.recv_raw = delayrecv
            >>> t.recvrepeat(0.2)
            b'abc'
            >>> t.recv()
            b'd'
        """
        ...

    def recvrepeatS(self, *a, **kw):
        r"""
        Same as :meth:`recvrepeat`, but returns a str, decoding the result using `context.encoding`. (note that the binary versions are way faster)
        """
        ...

    def recvrepeatb(self, *a, **kw):
        r"""
        Same as :meth:`recvrepeat`, but returns a bytearray
        """
        ...

    def recvuntil(self, delims, drop=False, timeout=pwnlib.timeout.Timeout.default):
        r"""
        recvuntil(delims, drop=False, timeout=default) -> bytes

        Receive data until one of `delims` is encountered.

        If the request is not satisfied before ``timeout`` seconds pass,
        all data is buffered and an empty string (``''``) is returned.

        arguments:
            delims(bytes,tuple): Byte-string of delimiters characters, or list of delimiter byte-strings.
            drop(bool): Drop the ending.  If :const:`True` it is removed from the end of the return value.

        Raises:
            exceptions.EOFError: The connection closed before the request could be satisfied

        Returns:
            A string containing bytes received from the socket,
            or ``''`` if a timeout occurred while waiting.

        Examples:

            >>> t = tube()
            >>> t.recv_raw = lambda n: b"Hello World!"
            >>> t.recvuntil(b' ')
            b'Hello '
            >>> _=t.clean(0)
            >>> # Matches on 'o' in 'Hello'
            >>> t.recvuntil((b' ',b'W',b'o',b'r'))
            b'Hello'
            >>> _=t.clean(0)
            >>> # Matches expressly full string
            >>> t.recvuntil(b' Wor')
            b'Hello Wor'
            >>> _=t.clean(0)
            >>> # Matches on full string, drops match
            >>> t.recvuntil(b' Wor', drop=True)
            b'Hello'

            >>> # Try with regex special characters
            >>> t = tube()
            >>> t.recv_raw = lambda n: b"Hello|World"
            >>> t.recvuntil(b'|', drop=True)
            b'Hello'
        """
        ...

    def recvuntilS(self, *a, **kw):
        r"""
        Same as :meth:`recvuntil`, but returns a str, decoding the result using `context.encoding`. (note that the binary versions are way faster)
        """
        ...

    def recvuntilb(self, *a, **kw):
        r"""
        Same as :meth:`recvuntil`, but returns a bytearray
        """
        ...

    def removeHandler(self, handler):
        r"""
        removeHandler(handler)

        Remove the specified handler from the underlying logger.
        """
        ...

    def send(self, data):
        r"""
        send(data)

        Sends data.

        If log level ``DEBUG`` is enabled, also prints out the data
        received.

        If it is not possible to send anymore because of a closed
        connection, it raises ``exceptions.EOFError``

        Examples:

            >>> def p(x): print(repr(x))
            >>> t = tube()
            >>> t.send_raw = p
            >>> t.send(b'hello')
            b'hello'
        """
        ...

    def send_raw(self, data):
        r"""
        send_raw(data)

        Should not be called directly. Sends data to the tube.

        Should return ``exceptions.EOFError``, if it is unable to send any
        more, because of a close tube.
        """
        ...

    def sendafter(self, delim, data, timeout=pwnlib.timeout.Timeout.default):
        r"""
        sendafter(delim, data, timeout = default) -> str

        A combination of ``recvuntil(delim, timeout=timeout)`` and ``send(data)``.
        """
        ...

    def sendline(self, line=b''):
        r"""
        sendline(data)

        Shorthand for ``t.send(data + t.newline)``.

        Examples:

            >>> def p(x): print(repr(x))
            >>> t = tube()
            >>> t.send_raw = p
            >>> t.sendline(b'hello')
            b'hello\n'
            >>> t.newline = b'\r\n'
            >>> t.sendline(b'hello')
            b'hello\r\n'
        """
        ...

    def sendlineafter(self, delim, data, timeout=pwnlib.timeout.Timeout.default):
        r"""
        sendlineafter(delim, data, timeout = default) -> str

        A combination of ``recvuntil(delim, timeout=timeout)`` and ``sendline(data)``.
        """
        ...

    def sendlines(self, lines=[]):

        ...

    def sendlinethen(self, delim, data, timeout=pwnlib.timeout.Timeout.default):
        r"""
        sendlinethen(delim, data, timeout = default) -> str

        A combination of ``sendline(data)`` and ``recvuntil(delim, timeout=timeout)``.
        """
        ...

    def sendthen(self, delim, data, timeout=pwnlib.timeout.Timeout.default):
        r"""
        sendthen(delim, data, timeout = default) -> str

        A combination of ``send(data)`` and ``recvuntil(delim, timeout=timeout)``.
        """
        ...

    def setLevel(self, level):
        r"""
        setLevel(level)

        Set the logging level for the underlying logger.
        """
        ...

    def settimeout(self, timeout):
        r"""
        settimeout(timeout)

        Set the timeout for receiving operations. If the string "default"
        is given, then :data:`context.timeout` will be used. If None is given,
        then there will be no timeout.

        Examples:

            >>> t = tube()
            >>> t.settimeout_raw = lambda t: None
            >>> t.settimeout(3)
            >>> t.timeout == 3
            True
        """
        ...

    def settimeout_raw(self, timeout):
        r"""
        settimeout_raw(timeout)

        Should not be called directly. Sets the timeout for
        the tube.
        """
        ...

    def shutdown(self, direction='send'):
        r"""
        shutdown(direction = "send")

        Closes the tube for futher reading or writing depending on `direction`.

        Arguments:
          direction(str): Which direction to close; "in", "read" or "recv"
            closes the tube in the ingoing direction, "out", "write" or "send"
            closes it in the outgoing direction.

        Returns:
          :const:`None`

        Examples:

            >>> def p(x): print(x)
            >>> t = tube()
            >>> t.shutdown_raw = p
            >>> _=list(map(t.shutdown, ('in', 'read', 'recv', 'out', 'write', 'send')))
            recv
            recv
            recv
            send
            send
            send
            >>> t.shutdown('bad_value') #doctest: +ELLIPSIS
            Traceback (most recent call last):
            ...
            KeyError: "direction must be in ['in', 'out', 'read', 'recv', 'send', 'write']"
        """
        ...

    def shutdown_raw(self, direction):
        r"""
        shutdown_raw(direction)

        Should not be called directly.  Closes the tube for further reading or
        writing.
        """
        ...

    def spawn_process(self, *args, **kwargs):
        r"""
        Spawns a new process having this tube as stdin, stdout and stderr.

        Takes the same arguments as :class:`subprocess.Popen`.
        """
        ...

    def stream(self, line_mode=True):
        r"""
        stream()

        Receive data until the tube exits, and print it to stdout.

        Similar to :func:`interactive`, except that no input is sent.

        Similar to ``print(tube.recvall())`` except that data is printed
        as it is received, rather than after all data is received.

        Arguments:
            line_mode(bool): Whether to receive line-by-line or raw data.

        Returns:
            All data printed.
        """
        ...

    def success(self, message, *args, **kwargs):
        r"""
        success(message, *args, **kwargs)

        Logs a success message.
        """
        ...

    def timeout_change(self):
        r"""
        Informs the raw layer of the tube that the timeout has changed.

        Should not be called directly.

        Inherited from :class:`Timeout`.
        """
        ...

    def u16(self, *a, **kw):

        ...

    def u32(self, *a, **kw):

        ...

    def u64(self, *a, **kw):

        ...

    def u8(self, *a, **kw):

        ...

    def unpack(self, *a, **kw):

        ...

    def unread(self, *a, **kw):
        r"""
        Alias for :meth:`unrecv`
        """
        ...

    def unrecv(self, data):
        r"""
        unrecv(data)

        Puts the specified data back at the beginning of the receive
        buffer.

        Examples:

            >>> t = tube()
            >>> t.recv_raw = lambda n: b'hello'
            >>> t.recv()
            b'hello'
            >>> t.recv()
            b'hello'
            >>> t.unrecv(b'world')
            >>> t.recv()
            b'world'
            >>> t.recv()
            b'hello'
        """
        ...

    def wait(self, timeout=pwnlib.timeout.Timeout.default):
        r"""
        Waits until the tube is closed.
        """
        ...

    def wait_for_close(self, timeout=pwnlib.timeout.Timeout.default):
        r"""
        Waits until the tube is closed.
        """
        ...

    def wait_for_connection(self):
        r"""
        Blocks until a connection has been established.
        """
        ...

    def waitfor(self, *args, **kwargs):
        r"""
        Alias for :meth:`progress`.
        """
        ...

    def warn(self, *args, **kwargs):
        r"""
        Alias for :meth:`warning`.
        """
        ...

    def warn_once(self, *args, **kwargs):
        r"""
        Alias for :meth:`warning_once`.
        """
        ...

    def warning(self, message, *args, **kwargs):
        r"""
        warning(message, *args, **kwargs)

        Logs a warning message.
        """
        ...

    def warning_once(self, message, *args, **kwargs):
        r"""
        warning_once(message, *args, **kwargs)

        Logs a warning message.  The same message is never printed again.
        """
        ...

    def write(self, *a, **kw):
        r"""
        Alias for :meth:`send`
        """
        ...

    def write_raw(self, *a, **kw):
        r"""
        Alias for :meth:`send_raw`
        """
        ...

    def writeafter(self, *a, **kw):
        r"""
        Alias for :meth:`sendafter`
        """
        ...

    def writeline(self, *a, **kw):
        r"""
        Alias for :meth:`sendline`
        """
        ...

    def writelineafter(self, *a, **kw):
        r"""
        Alias for :meth:`sendlineafter`
        """
        ...

    def writelines(self, *a, **kw):
        r"""
        Alias for :meth:`sendlines`
        """
        ...

    def writelinethen(self, *a, **kw):
        r"""
        Alias for :meth:`sendlinethen`
        """
        ...

    def writethen(self, *a, **kw):
        r"""
        Alias for :meth:`sendthen`
        """
        ...


import pwnlib.tubes.process

class process (pwnlib.tubes.tube.tube):
    r"""
    Spawns a new process, and wraps it with a tube for communication.

    Arguments:

        argv(list):
            List of arguments to pass to the spawned process.
        shell(bool):
            Set to `True` to interpret `argv` as a string
            to pass to the shell for interpretation instead of as argv.
        executable(str):
            Path to the binary to execute.  If :const:`None`, uses ``argv[0]``.
            Cannot be used with ``shell``.
        cwd(str):
            Working directory.  Uses the current working directory by default.
        env(dict):
            Environment variables.  By default, inherits from Python's environment.
        stdin(int):
            File object or file descriptor number to use for ``stdin``.
            By default, a pipe is used.  A pty can be used instead by setting
            this to ``PTY``.  This will cause programs to behave in an
            interactive manner (e.g.., ``python`` will show a ``>>>`` prompt).
            If the application reads from ``/dev/tty`` directly, use a pty.
        stdout(int):
            File object or file descriptor number to use for ``stdout``.
            By default, a pty is used so that any stdout buffering by libc
            routines is disabled.
            May also be ``PIPE`` to use a normal pipe.
        stderr(int):
            File object or file descriptor number to use for ``stderr``.
            By default, ``STDOUT`` is used.
            May also be ``PIPE`` to use a separate pipe,
            although the :class:`pwnlib.tubes.tube.tube` wrapper will not be able to read this data.
        close_fds(bool):
            Close all open file descriptors except stdin, stdout, stderr.
            By default, :const:`True` is used.
        preexec_fn(callable):
            Callable to invoke immediately before calling ``execve``.
        raw(bool):
            Set the created pty to raw mode (i.e. disable echo and control
            characters).  :const:`True` by default.  If no pty is created, this
            has no effect.
        aslr(bool):
            If set to :const:`False`, disable ASLR via ``personality`` (``setarch -R``)
            and ``setrlimit`` (``ulimit -s unlimited``).

            This disables ASLR for the target process.  However, the ``setarch``
            changes are lost if a ``setuid`` binary is executed.

            The default value is inherited from ``context.aslr``.
            See ``setuid`` below for additional options and information.
        setuid(bool):
            Used to control `setuid` status of the target binary, and the
            corresponding actions taken.

            By default, this value is :const:`None`, so no assumptions are made.

            If :const:`True`, treat the target binary as ``setuid``.
            This modifies the mechanisms used to disable ASLR on the process if
            ``aslr=False``.
            This is useful for debugging locally, when the exploit is a
            ``setuid`` binary.

            If :const:`False`, prevent ``setuid`` bits from taking effect on the
            target binary.  This is only supported on Linux, with kernels v3.5
            or greater.
        where(str):
            Where the process is running, used for logging purposes.
        display(list):
            List of arguments to display, instead of the main executable name.
        alarm(int):
            Set a SIGALRM alarm timeout on the process.

    Examples:

        >>> p = process('python2')
        >>> p.sendline(b"print 'Hello world'")
        >>> p.sendline(b"print 'Wow, such data'");
        >>> b'' == p.recv(timeout=0.01)
        True
        >>> p.shutdown('send')
        >>> p.proc.stdin.closed
        True
        >>> p.connected('send')
        False
        >>> p.recvline()
        b'Hello world\n'
        >>> p.recvuntil(b',')
        b'Wow,'
        >>> p.recvregex(b'.*data')
        b' such data'
        >>> p.recv()
        b'\n'
        >>> p.recv() # doctest: +ELLIPSIS
        Traceback (most recent call last):
        ...
        EOFError

        >>> p = process('cat')
        >>> d = open('/dev/urandom', 'rb').read(4096)
        >>> p.recv(timeout=0.1)
        b''
        >>> p.write(d)
        >>> p.recvrepeat(0.1) == d
        True
        >>> p.recv(timeout=0.1)
        b''
        >>> p.shutdown('send')
        >>> p.wait_for_close()
        >>> p.poll()
        0

        >>> p = process('cat /dev/zero | head -c8', shell=True, stderr=open('/dev/null', 'w+b'))
        >>> p.recv()
        b'\x00\x00\x00\x00\x00\x00\x00\x00'

        >>> p = process(['python','-c','import os; print(os.read(2,1024).decode())'],
        ...             preexec_fn = lambda: os.dup2(0,2))
        >>> p.sendline(b'hello')
        >>> p.recvline()
        b'hello\n'

        >>> stack_smashing = ['python','-c','open("/dev/tty","wb").write(b"stack smashing detected")']
        >>> process(stack_smashing).recvall()
        b'stack smashing detected'

        >>> process(stack_smashing, stdout=PIPE).recvall()
        b''

        >>> getpass = ['python','-c','import getpass; print(getpass.getpass("XXX"))']
        >>> p = process(getpass, stdin=PTY)
        >>> p.recv()
        b'XXX'
        >>> p.sendline(b'hunter2')
        >>> p.recvall()
        b'\nhunter2\n'

        >>> process('echo hello 1>&2', shell=True).recvall()
        b'hello\n'

        >>> process('echo hello 1>&2', shell=True, stderr=PIPE).recvall()
        b''

        >>> a = process(['cat', '/proc/self/maps']).recvall()
        >>> b = process(['cat', '/proc/self/maps'], aslr=False).recvall()
        >>> with context.local(aslr=False):
        ...    c = process(['cat', '/proc/self/maps']).recvall()
        >>> a == b
        False
        >>> b == c
        True

        >>> process(['sh','-c','ulimit -s'], aslr=0).recvline()
        b'unlimited\n'

        >>> io = process(['sh','-c','sleep 10; exit 7'], alarm=2)
        >>> io.poll(block=True) == -signal.SIGALRM
        True

        >>> binary = ELF.from_assembly('nop', arch='mips')
        >>> p = process(binary.path)
    """
    def __enter__(self):
        r"""
        Permit use of 'with' to control scoping and closing sessions.

        Examples:

            >>> t = tube()
            >>> def p(x): print(x)
            >>> t.close = lambda: p("Closed!")
            >>> with t: pass
            Closed!
        """
        ...

    def __exit__(self, type, value, traceback):
        r"""
        Handles closing for 'with' statement

        See :meth:`__enter__`
        """
        ...

    def __getattr__(self, attr):
        r"""
        Permit pass-through access to the underlying process object for
        fields like ``pid`` and ``stdin``.
        """
        ...

    def __init__(self, argv=None, shell=False, executable=None, cwd=None, env=None, stdin=-1, stdout: pwnlib.tubes.process.PTY = None, stderr=-2, close_fds=True, preexec_fn: Callable = None, raw=True, aslr=None, setuid=None, where='local', display=None, alarm=None, *args, **kwargs):
        r"""
        Initialize self.  See help(type(self)) for accurate signature.
        """
        ...

    def __lshift__(self, other):
        r"""
        Shorthand for connecting multiple tubes.

        See :meth:`connect_input` for more information.

        Examples:

            The following are equivalent ::

                tube_a >> tube.b
                tube_a.connect_input(tube_b)

            This is useful when chaining multiple tubes ::

                tube_a >> tube_b >> tube_a
                tube_a.connect_input(tube_b)
                tube_b.connect_input(tube_a)
        """
        ...

    def __ne__(self, other):
        r"""
        Shorthand for connecting tubes to eachother.

        The following are equivalent ::

            a >> b >> a
            a <> b

        See :meth:`connect_input` for more information.
        """
        ...

    def __rshift__(self, other):
        r"""
        Inverse of the ``<<`` operator.  See :meth:`__lshift__`.

        See :meth:`connect_input` for more information.
        """
        ...

    def _fillbuffer(self, timeout=pwnlib.timeout.Timeout.default):
        r"""
        _fillbuffer(timeout = default)

        Fills the internal buffer from the pipe, by calling
        :meth:`recv_raw` exactly once.

        Returns:

            The bytes of data received, or ``''`` if no data was received.

        Examples:

            >>> t = tube()
            >>> t.recv_raw = lambda *a: b'abc'
            >>> len(t.buffer)
            0
            >>> t._fillbuffer()
            b'abc'
            >>> len(t.buffer)
            3
        """
        ...

    def _get_timeout_seconds(self, value):

        ...

    def _getlevel(self, levelString):

        ...

    def _handles(self, stdin, stdout, stderr):

        ...

    def _log(self, level, msg, args, kwargs, msgtype, progress=None):

        ...

    def _process__on_enoexec(self, exception):
        r"""
        We received an 'exec format' error (ENOEXEC)

        This implies that the user tried to execute e.g.
        an ARM binary on a non-ARM system, and does not have
        binfmt helpers installed for QEMU.
        """
        ...

    def _process__preexec_fn(self):
        r"""
        Routine executed in the child process before invoking execve().

        Handles setting the controlling TTY as well as invoking the user-
        supplied preexec_fn.
        """
        ...

    def _process__pty_make_controlling_tty(self, tty_fd):
        r"""
        This makes the pseudo-terminal the controlling tty. This should be
        more portable than the pty.fork() function. Specifically, this should
        work on Solaris. 
        """
        ...

    def _read(self, *a, **kw):
        r"""
        Alias for :meth:`_recv`
        """
        ...

    def _recv(self, numb=None, timeout=pwnlib.timeout.Timeout.default):
        r"""
        _recv(numb = 4096, timeout = default) -> str

        Receives one chunk of from the internal buffer or from the OS if the
        buffer is empty.
        """
        ...

    def _validate(self, cwd, executable, argv, env):
        r"""
        Perform extended validation on the executable path, argv, and envp.

        Mostly to make Python happy, but also to prevent common pitfalls.
        """
        ...

    def addHandler(self, handler):
        r"""
        addHandler(handler)

        Add the specified handler to the underlying logger.
        """
        ...

    def can_read(self, *a, **kw):
        r"""
        Alias for :meth:`can_recv`
        """
        ...

    def can_read_raw(self, *a, **kw):
        r"""
        Alias for :meth:`can_recv_raw`
        """
        ...

    def can_recv(self, timeout=0):
        r"""
        can_recv(timeout = 0) -> bool

        Returns True, if there is data available within `timeout` seconds.

        Examples:

            >>> import time
            >>> t = tube()
            >>> t.can_recv_raw = lambda *a: False
            >>> t.can_recv()
            False
            >>> _=t.unrecv(b'data')
            >>> t.can_recv()
            True
            >>> _=t.recv()
            >>> t.can_recv()
            False
        """
        ...

    def can_recv_raw(self, timeout):
        r"""
        can_recv_raw(timeout) -> bool

        Should not be called directly. Returns True, if
        there is data available within the timeout, but
        ignores the buffer on the object.
        """
        ...

    def clean(self, timeout=0.05):
        r"""
        clean(timeout = 0.05)

        Removes all the buffered data from a tube by calling
        :meth:`pwnlib.tubes.tube.tube.recv` with a low timeout until it fails.

        If ``timeout`` is zero, only cached data will be cleared.

        Note: If timeout is set to zero, the underlying network is
        not actually polled; only the internal buffer is cleared.

        Returns:

            All data received

        Examples:

            >>> t = tube()
            >>> t.unrecv(b'clean me up')
            >>> t.clean(0)
            b'clean me up'
            >>> len(t.buffer)
            0
        """
        ...

    def clean_and_log(self, timeout=0.05):
        r"""
        clean_and_log(timeout = 0.05)

        Works exactly as :meth:`pwnlib.tubes.tube.tube.clean`, but logs received
        data with :meth:`pwnlib.self.info`.

        Returns:

            All data received

        Examples:

            >>> def recv(n, data=[b'', b'hooray_data']):
            ...     while data: return data.pop()
            >>> t = tube()
            >>> t.recv_raw      = recv
            >>> t.connected_raw = lambda d: True
            >>> t.fileno        = lambda: 1234
            >>> with context.local(log_level='info'):
            ...     data = t.clean_and_log() #doctest: +ELLIPSIS
            [DEBUG] Received 0xb bytes:
                b'hooray_data'
            >>> data
            b'hooray_data'
            >>> context.clear()
        """
        ...

    def close(self):
        r"""
        close()

        Closes the tube.
        """
        ...

    def communicate(self, stdin=None):
        r"""
        communicate(stdin = None) -> str

        Calls :meth:`subprocess.Popen.communicate` method on the process.
        """
        ...

    def connect_both(self, other):
        r"""
        connect_both(other)

        Connects the both ends of this tube object with another tube object.
        """
        ...

    def connect_input(self, other):
        r"""
        connect_input(other)

        Connects the input of this tube to the output of another tube object.


        Examples:

            >>> def p(x): print(x.decode())
            >>> def recvone(n, data=[b'data']):
            ...     while data: return data.pop()
            ...     raise EOFError
            >>> a = tube()
            >>> b = tube()
            >>> a.recv_raw = recvone
            >>> b.send_raw = p
            >>> a.connected_raw = lambda d: True
            >>> b.connected_raw = lambda d: True
            >>> a.shutdown      = lambda d: True
            >>> b.shutdown      = lambda d: True
            >>> import time
            >>> _=(b.connect_input(a), time.sleep(0.1))
            data
        """
        ...

    def connect_output(self, other):
        r"""
        connect_output(other)

        Connects the output of this tube to the input of another tube object.

        Examples:

            >>> def p(x): print(repr(x))
            >>> def recvone(n, data=[b'data']):
            ...     while data: return data.pop()
            ...     raise EOFError
            >>> a = tube()
            >>> b = tube()
            >>> a.recv_raw = recvone
            >>> b.send_raw = p
            >>> a.connected_raw = lambda d: True
            >>> b.connected_raw = lambda d: True
            >>> a.shutdown      = lambda d: True
            >>> b.shutdown      = lambda d: True
            >>> _=(a.connect_output(b), time.sleep(0.1))
            b'data'
        """
        ...

    def connected(self, direction='any'):
        r"""
        connected(direction = 'any') -> bool

        Returns True if the tube is connected in the specified direction.

        Arguments:
          direction(str): Can be the string 'any', 'in', 'read', 'recv',
                          'out', 'write', 'send'.

        Doctest:

            >>> def p(x): print(x)
            >>> t = tube()
            >>> t.connected_raw = p
            >>> _=list(map(t.connected, ('any', 'in', 'read', 'recv', 'out', 'write', 'send')))
            any
            recv
            recv
            recv
            send
            send
            send
            >>> t.connected('bad_value') #doctest: +ELLIPSIS
            Traceback (most recent call last):
            ...
            KeyError: "direction must be in ['any', 'in', 'out', 'read', 'recv', 'send', 'write']"
        """
        ...

    def connected_raw(self, direction):
        r"""
        connected(direction = 'any') -> bool

        Should not be called directly.  Returns True iff the
        tube is connected in the given direction.
        """
        ...

    def countdown(self, timeout=pwnlib.timeout.Timeout.default):
        r"""
        Scoped timeout setter.  Sets the timeout within the scope,
        and restores it when leaving the scope.

        When accessing :attr:`timeout` within the scope, it will be
        calculated against the time when the scope was entered, in a
        countdown fashion.

        If :const:`None` is specified for ``timeout``, then the current
        timeout is used is made.  This allows :const:`None` to be specified
        as a default argument with less complexity.
        """
        ...

    def countdown_active(self):

        ...

    def critical(self, message, *args, **kwargs):
        r"""
        critical(message, *args, **kwargs)

        Logs a critical message.
        """
        ...

    def debug(self, message, *args, **kwargs):
        r"""
        debug(message, *args, **kwargs)

        Logs a debug message.
        """
        ...

    def error(self, message, *args, **kwargs):
        r"""
        error(message, *args, **kwargs)

        To be called outside an exception handler.

        Logs an error message, then raises a ``PwnlibException``.
        """
        ...

    def exception(self, message, *args, **kwargs):
        r"""
        exception(message, *args, **kwargs)

        To be called from an exception handler.

        Logs a error message, then re-raises the current exception.
        """
        ...

    def failure(self, message, *args, **kwargs):
        r"""
        failure(message, *args, **kwargs)

        Logs a failure message.
        """
        ...

    def fileno(self):
        r"""
        fileno() -> int

        Returns the file number used for reading.
        """
        ...

    def fit(self, *a, **kw):

        ...

    def flat(self, *a, **kw):

        ...

    def hexdump(self, message, *args, **kwargs):

        ...

    def indented(self, message, *args, **kwargs):
        r"""
        indented(message, *args, level = logging.INFO, **kwargs)

        Log a message but don't put a line prefix on it.

        Arguments:
            level(int): Alternate log level at which to set the indented
                        message.  Defaults to :const:`logging.INFO`.
        """
        ...

    def info(self, message, *args, **kwargs):
        r"""
        info(message, *args, **kwargs)

        Logs an info message.
        """
        ...

    def info_once(self, message, *args, **kwargs):
        r"""
        info_once(message, *args, **kwargs)

        Logs an info message.  The same message is never printed again.
        """
        ...

    def interactive(self, prompt='\x1b[1m\x1b[31m$\x1b[m '):
        r"""
        interactive(prompt = pwnlib.term.text.bold_red('$') + ' ')

        Does simultaneous reading and writing to the tube. In principle this just
        connects the tube to standard in and standard out, but in practice this
        is much more usable, since we are using :mod:`pwnlib.term` to print a
        floating prompt.

        Thus it only works in while in :data:`pwnlib.term.term_mode`.
        """
        ...

    def isEnabledFor(self, level):
        r"""
        isEnabledFor(level) -> bool

        See if the underlying logger is enabled for the specified level.
        """
        ...

    def kill(self):
        r"""
        kill()

        Kills the process.
        """
        ...

    def leak(self, address, count=1):
        r"""
        Leaks memory within the process at the specified address.

        Arguments:
            address(int): Address to leak memory at
            count(int): Number of bytes to leak at that address.

        Example:

            >>> e = ELF('/bin/bash-static')
            >>> p = process(e.path)

            In order to make sure there's not a race condition against
            the process getting set up...

            >>> p.sendline(b'echo hello')
            >>> p.recvuntil(b'hello')
            b'hello'

            Now we can leak some data!

            >>> p.leak(e.address, 4)
            b'\x7fELF'
        """
        ...

    def libs(self):
        r"""
        libs() -> dict

        Return a dictionary mapping the path of each shared library loaded
        by the process to the address it is loaded at in the process' address
        space.
        """
        ...

    def local(self, timeout):
        r"""
        Scoped timeout setter.  Sets the timeout within the scope,
        and restores it when leaving the scope.
        """
        ...

    def log(self, level, message, *args, **kwargs):
        r"""
        log(level, message, *args, **kwargs)

        Logs a message with log level `level`.  The ``pwnlib`` formatter will
        use the default :mod:`logging` formater to format this message.
        """
        ...

    def p16(self, *a, **kw):

        ...

    def p32(self, *a, **kw):

        ...

    def p64(self, *a, **kw):

        ...

    def p8(self, *a, **kw):

        ...

    def pack(self, *a, **kw):

        ...

    def poll(self, block=False):
        r"""
        poll(block = False) -> int

        Arguments:
            block(bool): Wait for the process to exit

        Poll the exit code of the process. Will return None, if the
        process has not yet finished and the exit code otherwise.
        """
        ...

    def progress(self, message, status='', *args, **kwargs):
        r"""
        progress(message, status = '', *args, level = logging.INFO, **kwargs) -> Progress

        Creates a new progress logger which creates log records with log level
        `level`.

        Progress status can be updated using :meth:`Progress.status` and stopped
        using :meth:`Progress.success` or :meth:`Progress.failure`.

        If `term.term_mode` is enabled the progress logger will be animated.

        The progress manager also functions as a context manager.  Using context
        managers ensures that animations stop even if an exception is raised.

        .. code-block:: python

           with log.progress('Trying something...') as p:
               for i in range(10):
                   p.status("At %i" % i)
                   time.sleep(0.5)
               x = 1/0
        """
        ...

    def read(self, *a, **kw):
        r"""
        Alias for :meth:`recv`
        """
        ...

    def readS(self, *a, **kw):
        r"""
        Alias for :meth:`recvS`
        """
        ...

    def read_raw(self, *a, **kw):
        r"""
        Alias for :meth:`recv_raw`
        """
        ...

    def readall(self, *a, **kw):
        r"""
        Alias for :meth:`recvall`
        """
        ...

    def readallS(self, *a, **kw):
        r"""
        Alias for :meth:`recvallS`
        """
        ...

    def readallb(self, *a, **kw):
        r"""
        Alias for :meth:`recvallb`
        """
        ...

    def readb(self, *a, **kw):
        r"""
        Alias for :meth:`recvb`
        """
        ...

    def readline(self, *a, **kw):
        r"""
        Alias for :meth:`recvline`
        """
        ...

    def readlineS(self, *a, **kw):
        r"""
        Alias for :meth:`recvlineS`
        """
        ...

    def readline_contains(self, *a, **kw):
        r"""
        Alias for :meth:`recvline_contains`
        """
        ...

    def readline_containsS(self, *a, **kw):
        r"""
        Alias for :meth:`recvline_containsS`
        """
        ...

    def readline_containsb(self, *a, **kw):
        r"""
        Alias for :meth:`recvline_containsb`
        """
        ...

    def readline_endswith(self, *a, **kw):
        r"""
        Alias for :meth:`recvline_endswith`
        """
        ...

    def readline_endswithS(self, *a, **kw):
        r"""
        Alias for :meth:`recvline_endswithS`
        """
        ...

    def readline_endswithb(self, *a, **kw):
        r"""
        Alias for :meth:`recvline_endswithb`
        """
        ...

    def readline_pred(self, *a, **kw):
        r"""
        Alias for :meth:`recvline_pred`
        """
        ...

    def readline_regex(self, *a, **kw):
        r"""
        Alias for :meth:`recvline_regex`
        """
        ...

    def readline_regexS(self, *a, **kw):
        r"""
        Alias for :meth:`recvline_regexS`
        """
        ...

    def readline_regexb(self, *a, **kw):
        r"""
        Alias for :meth:`recvline_regexb`
        """
        ...

    def readline_startswith(self, *a, **kw):
        r"""
        Alias for :meth:`recvline_startswith`
        """
        ...

    def readline_startswithS(self, *a, **kw):
        r"""
        Alias for :meth:`recvline_startswithS`
        """
        ...

    def readline_startswithb(self, *a, **kw):
        r"""
        Alias for :meth:`recvline_startswithb`
        """
        ...

    def readlineb(self, *a, **kw):
        r"""
        Alias for :meth:`recvlineb`
        """
        ...

    def readlines(self, *a, **kw):
        r"""
        Alias for :meth:`recvlines`
        """
        ...

    def readlinesS(self, *a, **kw):
        r"""
        Alias for :meth:`recvlinesS`
        """
        ...

    def readlinesb(self, *a, **kw):
        r"""
        Alias for :meth:`recvlinesb`
        """
        ...

    def readn(self, *a, **kw):
        r"""
        Alias for :meth:`recvn`
        """
        ...

    def readnS(self, *a, **kw):
        r"""
        Alias for :meth:`recvnS`
        """
        ...

    def readnb(self, *a, **kw):
        r"""
        Alias for :meth:`recvnb`
        """
        ...

    def readpred(self, *a, **kw):
        r"""
        Alias for :meth:`recvpred`
        """
        ...

    def readpredS(self, *a, **kw):
        r"""
        Alias for :meth:`recvpredS`
        """
        ...

    def readpredb(self, *a, **kw):
        r"""
        Alias for :meth:`recvpredb`
        """
        ...

    def readregex(self, *a, **kw):
        r"""
        Alias for :meth:`recvregex`
        """
        ...

    def readregexS(self, *a, **kw):
        r"""
        Alias for :meth:`recvregexS`
        """
        ...

    def readregexb(self, *a, **kw):
        r"""
        Alias for :meth:`recvregexb`
        """
        ...

    def readrepeat(self, *a, **kw):
        r"""
        Alias for :meth:`recvrepeat`
        """
        ...

    def readrepeatS(self, *a, **kw):
        r"""
        Alias for :meth:`recvrepeatS`
        """
        ...

    def readrepeatb(self, *a, **kw):
        r"""
        Alias for :meth:`recvrepeatb`
        """
        ...

    def readuntil(self, *a, **kw):
        r"""
        Alias for :meth:`recvuntil`
        """
        ...

    def readuntilS(self, *a, **kw):
        r"""
        Alias for :meth:`recvuntilS`
        """
        ...

    def readuntilb(self, *a, **kw):
        r"""
        Alias for :meth:`recvuntilb`
        """
        ...

    def recv(self, numb=None, timeout=pwnlib.timeout.Timeout.default):
        r"""
        recv(numb = 4096, timeout = default) -> bytes

        Receives up to `numb` bytes of data from the tube, and returns
        as soon as any quantity of data is available.

        If the request is not satisfied before ``timeout`` seconds pass,
        all data is buffered and an empty string (``''``) is returned.

        Raises:
            exceptions.EOFError: The connection is closed

        Returns:
            A bytes object containing bytes received from the socket,
            or ``''`` if a timeout occurred while waiting.

        Examples:

            >>> t = tube()
            >>> # Fake a data source
            >>> t.recv_raw = lambda n: b'Hello, world'
            >>> t.recv() == b'Hello, world'
            True
            >>> t.unrecv(b'Woohoo')
            >>> t.recv() == b'Woohoo'
            True
            >>> with context.local(log_level='debug'):
            ...    _ = t.recv() # doctest: +ELLIPSIS
            [...] Received 0xc bytes:
                b'Hello, world'
        """
        ...

    def recvS(self, *a, **kw):
        r"""
        Same as :meth:`recv`, but returns a str, decoding the result using `context.encoding`. (note that the binary versions are way faster)
        """
        ...

    def recv_raw(self, numb):
        r"""
        recv_raw(numb) -> str

        Should not be called directly. Receives data without using the buffer
        on the object.

        Unless there is a timeout or closed connection, this should always
        return data. In case of a timeout, it should return None, in case
        of a closed connection it should raise an ``exceptions.EOFError``.
        """
        ...

    def recvall(self, timeout=None):
        r"""
        recvall() -> bytes

        Receives data until EOF is reached.
        """
        ...

    def recvallS(self, *a, **kw):
        r"""
        Same as :meth:`recvall`, but returns a str, decoding the result using `context.encoding`. (note that the binary versions are way faster)
        """
        ...

    def recvallb(self, *a, **kw):
        r"""
        Same as :meth:`recvall`, but returns a bytearray
        """
        ...

    def recvb(self, *a, **kw):
        r"""
        Same as :meth:`recv`, but returns a bytearray
        """
        ...

    def recvline(self, keepends=True, timeout=pwnlib.timeout.Timeout.default):
        r"""
        recvline(keepends=True, timeout=default) -> bytes

        Receive a single line from the tube.

        A "line" is any sequence of bytes terminated by the byte sequence
        set in :attr:`newline`, which defaults to ``'\n'``.

        If the request is not satisfied before ``timeout`` seconds pass,
        all data is buffered and an empty string (``''``) is returned.

        Arguments:
            keepends(bool): Keep the line ending (:const:`True`).
            timeout(int): Timeout

        Return:
            All bytes received over the tube until the first
            newline ``'\n'`` is received.  Optionally retains
            the ending.

        Examples:

            >>> t = tube()
            >>> t.recv_raw = lambda n: b'Foo\nBar\r\nBaz\n'
            >>> t.recvline()
            b'Foo\n'
            >>> t.recvline()
            b'Bar\r\n'
            >>> t.recvline(keepends = False)
            b'Baz'
            >>> t.newline = b'\r\n'
            >>> t.recvline(keepends = False)
            b'Foo\nBar'
        """
        ...

    def recvlineS(self, *a, **kw):
        r"""
        Same as :meth:`recvline`, but returns a str, decoding the result using `context.encoding`. (note that the binary versions are way faster)
        """
        ...

    def recvline_contains(self, items, keepends=False, timeout=pwnlib.timeout.Timeout.default):
        r"""
        Receive lines until one line is found which contains at least
        one of `items`.

        Arguments:
            items(str,tuple): List of strings to search for, or a single string.
            keepends(bool): Return lines with newlines if :const:`True`
            timeout(int): Timeout, in seconds

        Examples:

            >>> t = tube()
            >>> t.recv_raw = lambda n: b"Hello\nWorld\nXylophone\n"
            >>> t.recvline_contains(b'r')
            b'World'
            >>> f = lambda n: b"cat dog bird\napple pear orange\nbicycle car train\n"
            >>> t = tube()
            >>> t.recv_raw = f
            >>> t.recvline_contains(b'pear')
            b'apple pear orange'
            >>> t = tube()
            >>> t.recv_raw = f
            >>> t.recvline_contains((b'car', b'train'))
            b'bicycle car train'
        """
        ...

    def recvline_containsS(self, *a, **kw):
        r"""
        Same as :meth:`recvline_contains`, but returns a str, decoding the result using `context.encoding`. (note that the binary versions are way faster)
        """
        ...

    def recvline_containsb(self, *a, **kw):
        r"""
        Same as :meth:`recvline_contains`, but returns a bytearray
        """
        ...

    def recvline_endswith(self, delims, keepends=False, timeout=pwnlib.timeout.Timeout.default):
        r"""
        recvline_endswith(delims, keepends=False, timeout=default) -> bytes

        Keep receiving lines until one is found that ends with one of
        `delims`.  Returns the last line received.

        If the request is not satisfied before ``timeout`` seconds pass,
        all data is buffered and an empty string (``''``) is returned.

        See :meth:`recvline_startswith` for more details.

        Examples:

            >>> t = tube()
            >>> t.recv_raw = lambda n: b'Foo\nBar\nBaz\nKaboodle\n'
            >>> t.recvline_endswith(b'r')
            b'Bar'
            >>> t.recvline_endswith((b'a',b'b',b'c',b'd',b'e'), True)
            b'Kaboodle\n'
            >>> t.recvline_endswith(b'oodle')
            b'Kaboodle'
        """
        ...

    def recvline_endswithS(self, *a, **kw):
        r"""
        Same as :meth:`recvline_endswith`, but returns a str, decoding the result using `context.encoding`. (note that the binary versions are way faster)
        """
        ...

    def recvline_endswithb(self, *a, **kw):
        r"""
        Same as :meth:`recvline_endswith`, but returns a bytearray
        """
        ...

    def recvline_pred(self, pred, keepends=False, timeout=pwnlib.timeout.Timeout.default):
        r"""
        recvline_pred(pred, keepends=False) -> bytes

        Receive data until ``pred(line)`` returns a truthy value.
        Drop all other data.

        If the request is not satisfied before ``timeout`` seconds pass,
        all data is buffered and an empty string (``''``) is returned.

        Arguments:
            pred(callable): Function to call.  Returns the line for which
                this function returns :const:`True`.

        Examples:

            >>> t = tube()
            >>> t.recv_raw = lambda n: b"Foo\nBar\nBaz\n"
            >>> t.recvline_pred(lambda line: line == b"Bar\n")
            b'Bar'
            >>> t.recvline_pred(lambda line: line == b"Bar\n", keepends=True)
            b'Bar\n'
            >>> t.recvline_pred(lambda line: line == b'Nope!', timeout=0.1)
            b''
        """
        ...

    def recvline_regex(self, regex, exact=False, keepends=False, timeout=pwnlib.timeout.Timeout.default):
        r"""
        recvline_regex(regex, exact=False, keepends=False, timeout=default) -> bytes

        Wrapper around :func:`recvline_pred`, which will return when a regex
        matches a line.

        By default :func:`re.RegexObject.search` is used, but if `exact` is
        set to True, then :func:`re.RegexObject.match` will be used instead.

        If the request is not satisfied before ``timeout`` seconds pass,
        all data is buffered and an empty string (``''``) is returned.
        """
        ...

    def recvline_regexS(self, *a, **kw):
        r"""
        Same as :meth:`recvline_regex`, but returns a str, decoding the result using `context.encoding`. (note that the binary versions are way faster)
        """
        ...

    def recvline_regexb(self, *a, **kw):
        r"""
        Same as :meth:`recvline_regex`, but returns a bytearray
        """
        ...

    def recvline_startswith(self, delims, keepends=False, timeout=pwnlib.timeout.Timeout.default):
        r"""
        recvline_startswith(delims, keepends=False, timeout=default) -> bytes

        Keep receiving lines until one is found that starts with one of
        `delims`.  Returns the last line received.

        If the request is not satisfied before ``timeout`` seconds pass,
        all data is buffered and an empty string (``''``) is returned.

        Arguments:
            delims(str,tuple): List of strings to search for, or string of single characters
            keepends(bool): Return lines with newlines if :const:`True`
            timeout(int): Timeout, in seconds

        Returns:
            The first line received which starts with a delimiter in ``delims``.

        Examples:

            >>> t = tube()
            >>> t.recv_raw = lambda n: b"Hello\nWorld\nXylophone\n"
            >>> t.recvline_startswith((b'W',b'X',b'Y',b'Z'))
            b'World'
            >>> t.recvline_startswith((b'W',b'X',b'Y',b'Z'), True)
            b'Xylophone\n'
            >>> t.recvline_startswith(b'Wo')
            b'World'
        """
        ...

    def recvline_startswithS(self, *a, **kw):
        r"""
        Same as :meth:`recvline_startswith`, but returns a str, decoding the result using `context.encoding`. (note that the binary versions are way faster)
        """
        ...

    def recvline_startswithb(self, *a, **kw):
        r"""
        Same as :meth:`recvline_startswith`, but returns a bytearray
        """
        ...

    def recvlineb(self, *a, **kw):
        r"""
        Same as :meth:`recvline`, but returns a bytearray
        """
        ...

    def recvlines(self, numlines=1048576, keepends=False, timeout=pwnlib.timeout.Timeout.default):
        r"""
        recvlines(numlines, keepends=False, timeout=default) -> list of bytes objects

        Receive up to ``numlines`` lines.

        A "line" is any sequence of bytes terminated by the byte sequence
        set by :attr:`newline`, which defaults to ``'\n'``.

        If the request is not satisfied before ``timeout`` seconds pass,
        all data is buffered and an empty string (``''``) is returned.

        Arguments:
            numlines(int): Maximum number of lines to receive
            keepends(bool): Keep newlines at the end of each line (:const:`False`).
            timeout(int): Maximum timeout

        Raises:
            exceptions.EOFError: The connection closed before the request could be satisfied

        Returns:
            A string containing bytes received from the socket,
            or ``''`` if a timeout occurred while waiting.

        Examples:

            >>> t = tube()
            >>> t.recv_raw = lambda n: b'\n'
            >>> t.recvlines(3)
            [b'', b'', b'']
            >>> t.recv_raw = lambda n: b'Foo\nBar\nBaz\n'
            >>> t.recvlines(3)
            [b'Foo', b'Bar', b'Baz']
            >>> t.recvlines(3, True)
            [b'Foo\n', b'Bar\n', b'Baz\n']
        """
        ...

    def recvlinesS(self, numlines=1048576, keepends=False, timeout=pwnlib.timeout.Timeout.default):
        r"""
        recvlinesS(numlines, keepends=False, timeout=default) -> str list

        This function is identical to :meth:`recvlines`, but decodes
        the received bytes into string using :func:`context.encoding`.
        You should use :meth:`recvlines` whenever possible for better performance.

        Examples:

            >>> t = tube()
            >>> t.recv_raw = lambda n: b'\n'
            >>> t.recvlinesS(3)
            ['', '', '']
            >>> t.recv_raw = lambda n: b'Foo\nBar\nBaz\n'
            >>> t.recvlinesS(3)
            ['Foo', 'Bar', 'Baz']
        """
        ...

    def recvlinesb(self, numlines=1048576, keepends=False, timeout=pwnlib.timeout.Timeout.default):
        r"""
        recvlinesb(numlines, keepends=False, timeout=default) -> bytearray list

        This function is identical to :meth:`recvlines`, but returns a bytearray.

        Examples:

            >>> t = tube()
            >>> t.recv_raw = lambda n: b'\n'
            >>> t.recvlinesb(3)
            [bytearray(b''), bytearray(b''), bytearray(b'')]
            >>> t.recv_raw = lambda n: b'Foo\nBar\nBaz\n'
            >>> t.recvlinesb(3)
            [bytearray(b'Foo'), bytearray(b'Bar'), bytearray(b'Baz')]
        """
        ...

    def recvn(self, numb, timeout=pwnlib.timeout.Timeout.default):
        r"""
        recvn(numb, timeout = default) -> str

        Receives exactly `n` bytes.

        If the request is not satisfied before ``timeout`` seconds pass,
        all data is buffered and an empty string (``''``) is returned.

        Raises:
            exceptions.EOFError: The connection closed before the request could be satisfied

        Returns:
            A string containing bytes received from the socket,
            or ``''`` if a timeout occurred while waiting.

        Examples:

            >>> t = tube()
            >>> data = b'hello world'
            >>> t.recv_raw = lambda *a: data
            >>> t.recvn(len(data)) == data
            True
            >>> t.recvn(len(data)+1) == data + data[:1]
            True
            >>> t.recv_raw = lambda *a: None
            >>> # The remaining data is buffered
            >>> t.recv() == data[1:]
            True
            >>> t.recv_raw = lambda *a: time.sleep(0.01) or b'a'
            >>> t.recvn(10, timeout=0.05)
            b''
            >>> t.recvn(10, timeout=0.06) # doctest: +ELLIPSIS
            b'aaaaaa...'
        """
        ...

    def recvnS(self, *a, **kw):
        r"""
        Same as :meth:`recvn`, but returns a str, decoding the result using `context.encoding`. (note that the binary versions are way faster)
        """
        ...

    def recvnb(self, *a, **kw):
        r"""
        Same as :meth:`recvn`, but returns a bytearray
        """
        ...

    def recvpred(self, pred, timeout=pwnlib.timeout.Timeout.default):
        r"""
        recvpred(pred, timeout = default) -> bytes

        Receives one byte at a time from the tube, until ``pred(all_bytes)``
        evaluates to True.

        If the request is not satisfied before ``timeout`` seconds pass,
        all data is buffered and an empty string (``''``) is returned.

        Arguments:
            pred(callable): Function to call, with the currently-accumulated data.
            timeout(int): Timeout for the operation

        Raises:
            exceptions.EOFError: The connection is closed

        Returns:
            A bytes object containing bytes received from the socket,
            or ``''`` if a timeout occurred while waiting.
        """
        ...

    def recvpredS(self, *a, **kw):
        r"""
        Same as :meth:`recvpred`, but returns a str, decoding the result using `context.encoding`. (note that the binary versions are way faster)
        """
        ...

    def recvpredb(self, *a, **kw):
        r"""
        Same as :meth:`recvpred`, but returns a bytearray
        """
        ...

    def recvregex(self, regex, exact=False, timeout=pwnlib.timeout.Timeout.default):
        r"""
        recvregex(regex, exact=False, timeout=default) -> bytes

        Wrapper around :func:`recvpred`, which will return when a regex
        matches the string in the buffer.

        By default :func:`re.RegexObject.search` is used, but if `exact` is
        set to True, then :func:`re.RegexObject.match` will be used instead.

        If the request is not satisfied before ``timeout`` seconds pass,
        all data is buffered and an empty string (``''``) is returned.
        """
        ...

    def recvregexS(self, *a, **kw):
        r"""
        Same as :meth:`recvregex`, but returns a str, decoding the result using `context.encoding`. (note that the binary versions are way faster)
        """
        ...

    def recvregexb(self, *a, **kw):
        r"""
        Same as :meth:`recvregex`, but returns a bytearray
        """
        ...

    def recvrepeat(self, timeout=pwnlib.timeout.Timeout.default):
        r"""
        recvrepeat(timeout=default) -> bytes

        Receives data until a timeout or EOF is reached.

        Examples:

            >>> data = [
            ... b'd',
            ... b'', # simulate timeout
            ... b'c',
            ... b'b',
            ... b'a',
            ... ]
            >>> def delayrecv(n, data=data):
            ...     return data.pop()
            >>> t = tube()
            >>> t.recv_raw = delayrecv
            >>> t.recvrepeat(0.2)
            b'abc'
            >>> t.recv()
            b'd'
        """
        ...

    def recvrepeatS(self, *a, **kw):
        r"""
        Same as :meth:`recvrepeat`, but returns a str, decoding the result using `context.encoding`. (note that the binary versions are way faster)
        """
        ...

    def recvrepeatb(self, *a, **kw):
        r"""
        Same as :meth:`recvrepeat`, but returns a bytearray
        """
        ...

    def recvuntil(self, delims, drop=False, timeout=pwnlib.timeout.Timeout.default):
        r"""
        recvuntil(delims, drop=False, timeout=default) -> bytes

        Receive data until one of `delims` is encountered.

        If the request is not satisfied before ``timeout`` seconds pass,
        all data is buffered and an empty string (``''``) is returned.

        arguments:
            delims(bytes,tuple): Byte-string of delimiters characters, or list of delimiter byte-strings.
            drop(bool): Drop the ending.  If :const:`True` it is removed from the end of the return value.

        Raises:
            exceptions.EOFError: The connection closed before the request could be satisfied

        Returns:
            A string containing bytes received from the socket,
            or ``''`` if a timeout occurred while waiting.

        Examples:

            >>> t = tube()
            >>> t.recv_raw = lambda n: b"Hello World!"
            >>> t.recvuntil(b' ')
            b'Hello '
            >>> _=t.clean(0)
            >>> # Matches on 'o' in 'Hello'
            >>> t.recvuntil((b' ',b'W',b'o',b'r'))
            b'Hello'
            >>> _=t.clean(0)
            >>> # Matches expressly full string
            >>> t.recvuntil(b' Wor')
            b'Hello Wor'
            >>> _=t.clean(0)
            >>> # Matches on full string, drops match
            >>> t.recvuntil(b' Wor', drop=True)
            b'Hello'

            >>> # Try with regex special characters
            >>> t = tube()
            >>> t.recv_raw = lambda n: b"Hello|World"
            >>> t.recvuntil(b'|', drop=True)
            b'Hello'
        """
        ...

    def recvuntilS(self, *a, **kw):
        r"""
        Same as :meth:`recvuntil`, but returns a str, decoding the result using `context.encoding`. (note that the binary versions are way faster)
        """
        ...

    def recvuntilb(self, *a, **kw):
        r"""
        Same as :meth:`recvuntil`, but returns a bytearray
        """
        ...

    def removeHandler(self, handler):
        r"""
        removeHandler(handler)

        Remove the specified handler from the underlying logger.
        """
        ...

    def send(self, data):
        r"""
        send(data)

        Sends data.

        If log level ``DEBUG`` is enabled, also prints out the data
        received.

        If it is not possible to send anymore because of a closed
        connection, it raises ``exceptions.EOFError``

        Examples:

            >>> def p(x): print(repr(x))
            >>> t = tube()
            >>> t.send_raw = p
            >>> t.send(b'hello')
            b'hello'
        """
        ...

    def send_raw(self, data):
        r"""
        send_raw(data)

        Should not be called directly. Sends data to the tube.

        Should return ``exceptions.EOFError``, if it is unable to send any
        more, because of a close tube.
        """
        ...

    def sendafter(self, delim, data, timeout=pwnlib.timeout.Timeout.default):
        r"""
        sendafter(delim, data, timeout = default) -> str

        A combination of ``recvuntil(delim, timeout=timeout)`` and ``send(data)``.
        """
        ...

    def sendline(self, line=b''):
        r"""
        sendline(data)

        Shorthand for ``t.send(data + t.newline)``.

        Examples:

            >>> def p(x): print(repr(x))
            >>> t = tube()
            >>> t.send_raw = p
            >>> t.sendline(b'hello')
            b'hello\n'
            >>> t.newline = b'\r\n'
            >>> t.sendline(b'hello')
            b'hello\r\n'
        """
        ...

    def sendlineafter(self, delim, data, timeout=pwnlib.timeout.Timeout.default):
        r"""
        sendlineafter(delim, data, timeout = default) -> str

        A combination of ``recvuntil(delim, timeout=timeout)`` and ``sendline(data)``.
        """
        ...

    def sendlines(self, lines=[]):

        ...

    def sendlinethen(self, delim, data, timeout=pwnlib.timeout.Timeout.default):
        r"""
        sendlinethen(delim, data, timeout = default) -> str

        A combination of ``sendline(data)`` and ``recvuntil(delim, timeout=timeout)``.
        """
        ...

    def sendthen(self, delim, data, timeout=pwnlib.timeout.Timeout.default):
        r"""
        sendthen(delim, data, timeout = default) -> str

        A combination of ``send(data)`` and ``recvuntil(delim, timeout=timeout)``.
        """
        ...

    def setLevel(self, level):
        r"""
        setLevel(level)

        Set the logging level for the underlying logger.
        """
        ...

    def settimeout(self, timeout):
        r"""
        settimeout(timeout)

        Set the timeout for receiving operations. If the string "default"
        is given, then :data:`context.timeout` will be used. If None is given,
        then there will be no timeout.

        Examples:

            >>> t = tube()
            >>> t.settimeout_raw = lambda t: None
            >>> t.settimeout(3)
            >>> t.timeout == 3
            True
        """
        ...

    def settimeout_raw(self, timeout):
        r"""
        settimeout_raw(timeout)

        Should not be called directly. Sets the timeout for
        the tube.
        """
        ...

    def shutdown(self, direction='send'):
        r"""
        shutdown(direction = "send")

        Closes the tube for futher reading or writing depending on `direction`.

        Arguments:
          direction(str): Which direction to close; "in", "read" or "recv"
            closes the tube in the ingoing direction, "out", "write" or "send"
            closes it in the outgoing direction.

        Returns:
          :const:`None`

        Examples:

            >>> def p(x): print(x)
            >>> t = tube()
            >>> t.shutdown_raw = p
            >>> _=list(map(t.shutdown, ('in', 'read', 'recv', 'out', 'write', 'send')))
            recv
            recv
            recv
            send
            send
            send
            >>> t.shutdown('bad_value') #doctest: +ELLIPSIS
            Traceback (most recent call last):
            ...
            KeyError: "direction must be in ['in', 'out', 'read', 'recv', 'send', 'write']"
        """
        ...

    def shutdown_raw(self, direction):
        r"""
        shutdown_raw(direction)

        Should not be called directly.  Closes the tube for further reading or
        writing.
        """
        ...

    def spawn_process(self, *args, **kwargs):
        r"""
        Spawns a new process having this tube as stdin, stdout and stderr.

        Takes the same arguments as :class:`subprocess.Popen`.
        """
        ...

    def stream(self, line_mode=True):
        r"""
        stream()

        Receive data until the tube exits, and print it to stdout.

        Similar to :func:`interactive`, except that no input is sent.

        Similar to ``print(tube.recvall())`` except that data is printed
        as it is received, rather than after all data is received.

        Arguments:
            line_mode(bool): Whether to receive line-by-line or raw data.

        Returns:
            All data printed.
        """
        ...

    def success(self, message, *args, **kwargs):
        r"""
        success(message, *args, **kwargs)

        Logs a success message.
        """
        ...

    def timeout_change(self):
        r"""
        Informs the raw layer of the tube that the timeout has changed.

        Should not be called directly.

        Inherited from :class:`Timeout`.
        """
        ...

    def u16(self, *a, **kw):

        ...

    def u32(self, *a, **kw):

        ...

    def u64(self, *a, **kw):

        ...

    def u8(self, *a, **kw):

        ...

    def unpack(self, *a, **kw):

        ...

    def unread(self, *a, **kw):
        r"""
        Alias for :meth:`unrecv`
        """
        ...

    def unrecv(self, data):
        r"""
        unrecv(data)

        Puts the specified data back at the beginning of the receive
        buffer.

        Examples:

            >>> t = tube()
            >>> t.recv_raw = lambda n: b'hello'
            >>> t.recv()
            b'hello'
            >>> t.recv()
            b'hello'
            >>> t.unrecv(b'world')
            >>> t.recv()
            b'world'
            >>> t.recv()
            b'hello'
        """
        ...

    def wait(self, timeout=pwnlib.timeout.Timeout.default):
        r"""
        Waits until the tube is closed.
        """
        ...

    def wait_for_close(self, timeout=pwnlib.timeout.Timeout.default):
        r"""
        Waits until the tube is closed.
        """
        ...

    def waitfor(self, *args, **kwargs):
        r"""
        Alias for :meth:`progress`.
        """
        ...

    def warn(self, *args, **kwargs):
        r"""
        Alias for :meth:`warning`.
        """
        ...

    def warn_once(self, *args, **kwargs):
        r"""
        Alias for :meth:`warning_once`.
        """
        ...

    def warning(self, message, *args, **kwargs):
        r"""
        warning(message, *args, **kwargs)

        Logs a warning message.
        """
        ...

    def warning_once(self, message, *args, **kwargs):
        r"""
        warning_once(message, *args, **kwargs)

        Logs a warning message.  The same message is never printed again.
        """
        ...

    def write(self, *a, **kw):
        r"""
        Alias for :meth:`send`
        """
        ...

    def write_raw(self, *a, **kw):
        r"""
        Alias for :meth:`send_raw`
        """
        ...

    def writeafter(self, *a, **kw):
        r"""
        Alias for :meth:`sendafter`
        """
        ...

    def writeline(self, *a, **kw):
        r"""
        Alias for :meth:`sendline`
        """
        ...

    def writelineafter(self, *a, **kw):
        r"""
        Alias for :meth:`sendlineafter`
        """
        ...

    def writelines(self, *a, **kw):
        r"""
        Alias for :meth:`sendlines`
        """
        ...

    def writelinethen(self, *a, **kw):
        r"""
        Alias for :meth:`sendlinethen`
        """
        ...

    def writethen(self, *a, **kw):
        r"""
        Alias for :meth:`sendthen`
        """
        ...


import pwnlib.tubes.remote

class connect (pwnlib.tubes.remote.remote):
    r"""
    Creates a TCP or UDP-connection to a remote host. It supports
    both IPv4 and IPv6.

    The returned object supports all the methods from
    :class:`pwnlib.tubes.sock` and :class:`pwnlib.tubes.tube`.

    Arguments:
        host(str): The host to connect to.
        port(int): The port to connect to.
        fam: The string "any", "ipv4" or "ipv6" or an integer to pass to :func:`socket.getaddrinfo`.
        typ: The string "tcp" or "udp" or an integer to pass to :func:`socket.getaddrinfo`.
        timeout: A positive number, None or the string "default".
        ssl(bool): Wrap the socket with SSL
        ssl_context(ssl.SSLContext): Specify SSLContext used to wrap the socket.
        sni: Set 'server_hostname' in ssl_args based on the host parameter.
        sock(socket.socket): Socket to inherit, rather than connecting
        ssl_args(dict): Pass ssl.wrap_socket named arguments in a dictionary.

    Examples:

        >>> r = remote('google.com', 443, ssl=True)
        >>> r.send(b'GET /\r\n\r\n')
        >>> r.recvn(4)
        b'HTTP'

        If a connection cannot be made, an exception is raised.

        >>> r = remote('127.0.0.1', 1)
        Traceback (most recent call last):
        ...
        PwnlibException: Could not connect to 127.0.0.1 on port 1

        You can also use :meth:`.remote.fromsocket` to wrap an existing socket.

        >>> import socket
        >>> s = socket.socket()
        >>> s.connect(('google.com', 80))
        >>> s.send(b'GET /' + b'\r\n'*2)
        9
        >>> r = remote.fromsocket(s)
        >>> r.recvn(4)
        b'HTTP'
    """
    def __enter__(self):
        r"""
        Permit use of 'with' to control scoping and closing sessions.

        Examples:

            >>> t = tube()
            >>> def p(x): print(x)
            >>> t.close = lambda: p("Closed!")
            >>> with t: pass
            Closed!
        """
        ...

    def __exit__(self, type, value, traceback):
        r"""
        Handles closing for 'with' statement

        See :meth:`__enter__`
        """
        ...

    def __init__(self, host, port, fam='any', typ='tcp', ssl=False, sock=None, ssl_context=None, ssl_args=None, sni=True, *args, **kwargs):
        r"""
        Initialize self.  See help(type(self)) for accurate signature.
        """
        ...

    def __lshift__(self, other):
        r"""
        Shorthand for connecting multiple tubes.

        See :meth:`connect_input` for more information.

        Examples:

            The following are equivalent ::

                tube_a >> tube.b
                tube_a.connect_input(tube_b)

            This is useful when chaining multiple tubes ::

                tube_a >> tube_b >> tube_a
                tube_a.connect_input(tube_b)
                tube_b.connect_input(tube_a)
        """
        ...

    def __ne__(self, other):
        r"""
        Shorthand for connecting tubes to eachother.

        The following are equivalent ::

            a >> b >> a
            a <> b

        See :meth:`connect_input` for more information.
        """
        ...

    def __rshift__(self, other):
        r"""
        Inverse of the ``<<`` operator.  See :meth:`__lshift__`.

        See :meth:`connect_input` for more information.
        """
        ...

    def _close_msg(self):

        ...

    def _connect(self, fam, typ):

        ...

    def _fillbuffer(self, timeout=pwnlib.timeout.Timeout.default):
        r"""
        _fillbuffer(timeout = default)

        Fills the internal buffer from the pipe, by calling
        :meth:`recv_raw` exactly once.

        Returns:

            The bytes of data received, or ``''`` if no data was received.

        Examples:

            >>> t = tube()
            >>> t.recv_raw = lambda *a: b'abc'
            >>> len(t.buffer)
            0
            >>> t._fillbuffer()
            b'abc'
            >>> len(t.buffer)
            3
        """
        ...

    def _get_timeout_seconds(self, value):

        ...

    def _getlevel(self, levelString):

        ...

    def _log(self, level, msg, args, kwargs, msgtype, progress=None):

        ...

    def _read(self, *a, **kw):
        r"""
        Alias for :meth:`_recv`
        """
        ...

    def _recv(self, numb=None, timeout=pwnlib.timeout.Timeout.default):
        r"""
        _recv(numb = 4096, timeout = default) -> str

        Receives one chunk of from the internal buffer or from the OS if the
        buffer is empty.
        """
        ...

    def addHandler(self, handler):
        r"""
        addHandler(handler)

        Add the specified handler to the underlying logger.
        """
        ...

    def can_read(self, *a, **kw):
        r"""
        Alias for :meth:`can_recv`
        """
        ...

    def can_read_raw(self, *a, **kw):
        r"""
        Alias for :meth:`can_recv_raw`
        """
        ...

    def can_recv(self, timeout=0):
        r"""
        can_recv(timeout = 0) -> bool

        Returns True, if there is data available within `timeout` seconds.

        Examples:

            >>> import time
            >>> t = tube()
            >>> t.can_recv_raw = lambda *a: False
            >>> t.can_recv()
            False
            >>> _=t.unrecv(b'data')
            >>> t.can_recv()
            True
            >>> _=t.recv()
            >>> t.can_recv()
            False
        """
        ...

    def can_recv_raw(self, timeout):
        r"""
        Tests:

            >>> l = listen()
            >>> r = remote('localhost', l.lport)
            >>> r.can_recv_raw(timeout=0)
            False
            >>> l.send(b'a')
            >>> r.can_recv_raw(timeout=1)
            True
            >>> r.recv()
            b'a'
            >>> r.can_recv_raw(timeout=0)
            False
            >>> l.close()
            >>> r.can_recv_raw(timeout=1)
            False
            >>> r.closed['recv']
            True
        """
        ...

    def clean(self, timeout=0.05):
        r"""
        clean(timeout = 0.05)

        Removes all the buffered data from a tube by calling
        :meth:`pwnlib.tubes.tube.tube.recv` with a low timeout until it fails.

        If ``timeout`` is zero, only cached data will be cleared.

        Note: If timeout is set to zero, the underlying network is
        not actually polled; only the internal buffer is cleared.

        Returns:

            All data received

        Examples:

            >>> t = tube()
            >>> t.unrecv(b'clean me up')
            >>> t.clean(0)
            b'clean me up'
            >>> len(t.buffer)
            0
        """
        ...

    def clean_and_log(self, timeout=0.05):
        r"""
        clean_and_log(timeout = 0.05)

        Works exactly as :meth:`pwnlib.tubes.tube.tube.clean`, but logs received
        data with :meth:`pwnlib.self.info`.

        Returns:

            All data received

        Examples:

            >>> def recv(n, data=[b'', b'hooray_data']):
            ...     while data: return data.pop()
            >>> t = tube()
            >>> t.recv_raw      = recv
            >>> t.connected_raw = lambda d: True
            >>> t.fileno        = lambda: 1234
            >>> with context.local(log_level='info'):
            ...     data = t.clean_and_log() #doctest: +ELLIPSIS
            [DEBUG] Received 0xb bytes:
                b'hooray_data'
            >>> data
            b'hooray_data'
            >>> context.clear()
        """
        ...

    def close(self):
        r"""
        close()

        Closes the tube.
        """
        ...

    def connect_both(self, other):
        r"""
        connect_both(other)

        Connects the both ends of this tube object with another tube object.
        """
        ...

    def connect_input(self, other):
        r"""
        connect_input(other)

        Connects the input of this tube to the output of another tube object.


        Examples:

            >>> def p(x): print(x.decode())
            >>> def recvone(n, data=[b'data']):
            ...     while data: return data.pop()
            ...     raise EOFError
            >>> a = tube()
            >>> b = tube()
            >>> a.recv_raw = recvone
            >>> b.send_raw = p
            >>> a.connected_raw = lambda d: True
            >>> b.connected_raw = lambda d: True
            >>> a.shutdown      = lambda d: True
            >>> b.shutdown      = lambda d: True
            >>> import time
            >>> _=(b.connect_input(a), time.sleep(0.1))
            data
        """
        ...

    def connect_output(self, other):
        r"""
        connect_output(other)

        Connects the output of this tube to the input of another tube object.

        Examples:

            >>> def p(x): print(repr(x))
            >>> def recvone(n, data=[b'data']):
            ...     while data: return data.pop()
            ...     raise EOFError
            >>> a = tube()
            >>> b = tube()
            >>> a.recv_raw = recvone
            >>> b.send_raw = p
            >>> a.connected_raw = lambda d: True
            >>> b.connected_raw = lambda d: True
            >>> a.shutdown      = lambda d: True
            >>> b.shutdown      = lambda d: True
            >>> _=(a.connect_output(b), time.sleep(0.1))
            b'data'
        """
        ...

    def connected(self, direction='any'):
        r"""
        connected(direction = 'any') -> bool

        Returns True if the tube is connected in the specified direction.

        Arguments:
          direction(str): Can be the string 'any', 'in', 'read', 'recv',
                          'out', 'write', 'send'.

        Doctest:

            >>> def p(x): print(x)
            >>> t = tube()
            >>> t.connected_raw = p
            >>> _=list(map(t.connected, ('any', 'in', 'read', 'recv', 'out', 'write', 'send')))
            any
            recv
            recv
            recv
            send
            send
            send
            >>> t.connected('bad_value') #doctest: +ELLIPSIS
            Traceback (most recent call last):
            ...
            KeyError: "direction must be in ['any', 'in', 'out', 'read', 'recv', 'send', 'write']"
        """
        ...

    def connected_raw(self, direction):
        r"""
        Tests:

            >>> l = listen()
            >>> r = remote('localhost', l.lport)
            >>> r.connected()
            True
            >>> l.close()
            >>> time.sleep(0.1) # Avoid race condition
            >>> r.connected()
            False
        """
        ...

    def countdown(self, timeout=pwnlib.timeout.Timeout.default):
        r"""
        Scoped timeout setter.  Sets the timeout within the scope,
        and restores it when leaving the scope.

        When accessing :attr:`timeout` within the scope, it will be
        calculated against the time when the scope was entered, in a
        countdown fashion.

        If :const:`None` is specified for ``timeout``, then the current
        timeout is used is made.  This allows :const:`None` to be specified
        as a default argument with less complexity.
        """
        ...

    def countdown_active(self):

        ...

    def critical(self, message, *args, **kwargs):
        r"""
        critical(message, *args, **kwargs)

        Logs a critical message.
        """
        ...

    def debug(self, message, *args, **kwargs):
        r"""
        debug(message, *args, **kwargs)

        Logs a debug message.
        """
        ...

    def error(self, message, *args, **kwargs):
        r"""
        error(message, *args, **kwargs)

        To be called outside an exception handler.

        Logs an error message, then raises a ``PwnlibException``.
        """
        ...

    def exception(self, message, *args, **kwargs):
        r"""
        exception(message, *args, **kwargs)

        To be called from an exception handler.

        Logs a error message, then re-raises the current exception.
        """
        ...

    def failure(self, message, *args, **kwargs):
        r"""
        failure(message, *args, **kwargs)

        Logs a failure message.
        """
        ...

    def fileno(self):
        r"""
        fileno() -> int

        Returns the file number used for reading.
        """
        ...

    def fit(self, *a, **kw):

        ...

    def flat(self, *a, **kw):

        ...

    def hexdump(self, message, *args, **kwargs):

        ...

    def indented(self, message, *args, **kwargs):
        r"""
        indented(message, *args, level = logging.INFO, **kwargs)

        Log a message but don't put a line prefix on it.

        Arguments:
            level(int): Alternate log level at which to set the indented
                        message.  Defaults to :const:`logging.INFO`.
        """
        ...

    def info(self, message, *args, **kwargs):
        r"""
        info(message, *args, **kwargs)

        Logs an info message.
        """
        ...

    def info_once(self, message, *args, **kwargs):
        r"""
        info_once(message, *args, **kwargs)

        Logs an info message.  The same message is never printed again.
        """
        ...

    def interactive(self, prompt='\x1b[1m\x1b[31m$\x1b[m '):
        r"""
        interactive(prompt = pwnlib.term.text.bold_red('$') + ' ')

        Does simultaneous reading and writing to the tube. In principle this just
        connects the tube to standard in and standard out, but in practice this
        is much more usable, since we are using :mod:`pwnlib.term` to print a
        floating prompt.

        Thus it only works in while in :data:`pwnlib.term.term_mode`.
        """
        ...

    def isEnabledFor(self, level):
        r"""
        isEnabledFor(level) -> bool

        See if the underlying logger is enabled for the specified level.
        """
        ...

    def local(self, timeout):
        r"""
        Scoped timeout setter.  Sets the timeout within the scope,
        and restores it when leaving the scope.
        """
        ...

    def log(self, level, message, *args, **kwargs):
        r"""
        log(level, message, *args, **kwargs)

        Logs a message with log level `level`.  The ``pwnlib`` formatter will
        use the default :mod:`logging` formater to format this message.
        """
        ...

    def p16(self, *a, **kw):

        ...

    def p32(self, *a, **kw):

        ...

    def p64(self, *a, **kw):

        ...

    def p8(self, *a, **kw):

        ...

    def pack(self, *a, **kw):

        ...

    def progress(self, message, status='', *args, **kwargs):
        r"""
        progress(message, status = '', *args, level = logging.INFO, **kwargs) -> Progress

        Creates a new progress logger which creates log records with log level
        `level`.

        Progress status can be updated using :meth:`Progress.status` and stopped
        using :meth:`Progress.success` or :meth:`Progress.failure`.

        If `term.term_mode` is enabled the progress logger will be animated.

        The progress manager also functions as a context manager.  Using context
        managers ensures that animations stop even if an exception is raised.

        .. code-block:: python

           with log.progress('Trying something...') as p:
               for i in range(10):
                   p.status("At %i" % i)
                   time.sleep(0.5)
               x = 1/0
        """
        ...

    def read(self, *a, **kw):
        r"""
        Alias for :meth:`recv`
        """
        ...

    def readS(self, *a, **kw):
        r"""
        Alias for :meth:`recvS`
        """
        ...

    def read_raw(self, *a, **kw):
        r"""
        Alias for :meth:`recv_raw`
        """
        ...

    def readall(self, *a, **kw):
        r"""
        Alias for :meth:`recvall`
        """
        ...

    def readallS(self, *a, **kw):
        r"""
        Alias for :meth:`recvallS`
        """
        ...

    def readallb(self, *a, **kw):
        r"""
        Alias for :meth:`recvallb`
        """
        ...

    def readb(self, *a, **kw):
        r"""
        Alias for :meth:`recvb`
        """
        ...

    def readline(self, *a, **kw):
        r"""
        Alias for :meth:`recvline`
        """
        ...

    def readlineS(self, *a, **kw):
        r"""
        Alias for :meth:`recvlineS`
        """
        ...

    def readline_contains(self, *a, **kw):
        r"""
        Alias for :meth:`recvline_contains`
        """
        ...

    def readline_containsS(self, *a, **kw):
        r"""
        Alias for :meth:`recvline_containsS`
        """
        ...

    def readline_containsb(self, *a, **kw):
        r"""
        Alias for :meth:`recvline_containsb`
        """
        ...

    def readline_endswith(self, *a, **kw):
        r"""
        Alias for :meth:`recvline_endswith`
        """
        ...

    def readline_endswithS(self, *a, **kw):
        r"""
        Alias for :meth:`recvline_endswithS`
        """
        ...

    def readline_endswithb(self, *a, **kw):
        r"""
        Alias for :meth:`recvline_endswithb`
        """
        ...

    def readline_pred(self, *a, **kw):
        r"""
        Alias for :meth:`recvline_pred`
        """
        ...

    def readline_regex(self, *a, **kw):
        r"""
        Alias for :meth:`recvline_regex`
        """
        ...

    def readline_regexS(self, *a, **kw):
        r"""
        Alias for :meth:`recvline_regexS`
        """
        ...

    def readline_regexb(self, *a, **kw):
        r"""
        Alias for :meth:`recvline_regexb`
        """
        ...

    def readline_startswith(self, *a, **kw):
        r"""
        Alias for :meth:`recvline_startswith`
        """
        ...

    def readline_startswithS(self, *a, **kw):
        r"""
        Alias for :meth:`recvline_startswithS`
        """
        ...

    def readline_startswithb(self, *a, **kw):
        r"""
        Alias for :meth:`recvline_startswithb`
        """
        ...

    def readlineb(self, *a, **kw):
        r"""
        Alias for :meth:`recvlineb`
        """
        ...

    def readlines(self, *a, **kw):
        r"""
        Alias for :meth:`recvlines`
        """
        ...

    def readlinesS(self, *a, **kw):
        r"""
        Alias for :meth:`recvlinesS`
        """
        ...

    def readlinesb(self, *a, **kw):
        r"""
        Alias for :meth:`recvlinesb`
        """
        ...

    def readn(self, *a, **kw):
        r"""
        Alias for :meth:`recvn`
        """
        ...

    def readnS(self, *a, **kw):
        r"""
        Alias for :meth:`recvnS`
        """
        ...

    def readnb(self, *a, **kw):
        r"""
        Alias for :meth:`recvnb`
        """
        ...

    def readpred(self, *a, **kw):
        r"""
        Alias for :meth:`recvpred`
        """
        ...

    def readpredS(self, *a, **kw):
        r"""
        Alias for :meth:`recvpredS`
        """
        ...

    def readpredb(self, *a, **kw):
        r"""
        Alias for :meth:`recvpredb`
        """
        ...

    def readregex(self, *a, **kw):
        r"""
        Alias for :meth:`recvregex`
        """
        ...

    def readregexS(self, *a, **kw):
        r"""
        Alias for :meth:`recvregexS`
        """
        ...

    def readregexb(self, *a, **kw):
        r"""
        Alias for :meth:`recvregexb`
        """
        ...

    def readrepeat(self, *a, **kw):
        r"""
        Alias for :meth:`recvrepeat`
        """
        ...

    def readrepeatS(self, *a, **kw):
        r"""
        Alias for :meth:`recvrepeatS`
        """
        ...

    def readrepeatb(self, *a, **kw):
        r"""
        Alias for :meth:`recvrepeatb`
        """
        ...

    def readuntil(self, *a, **kw):
        r"""
        Alias for :meth:`recvuntil`
        """
        ...

    def readuntilS(self, *a, **kw):
        r"""
        Alias for :meth:`recvuntilS`
        """
        ...

    def readuntilb(self, *a, **kw):
        r"""
        Alias for :meth:`recvuntilb`
        """
        ...

    def recv(self, numb=None, timeout=pwnlib.timeout.Timeout.default):
        r"""
        recv(numb = 4096, timeout = default) -> bytes

        Receives up to `numb` bytes of data from the tube, and returns
        as soon as any quantity of data is available.

        If the request is not satisfied before ``timeout`` seconds pass,
        all data is buffered and an empty string (``''``) is returned.

        Raises:
            exceptions.EOFError: The connection is closed

        Returns:
            A bytes object containing bytes received from the socket,
            or ``''`` if a timeout occurred while waiting.

        Examples:

            >>> t = tube()
            >>> # Fake a data source
            >>> t.recv_raw = lambda n: b'Hello, world'
            >>> t.recv() == b'Hello, world'
            True
            >>> t.unrecv(b'Woohoo')
            >>> t.recv() == b'Woohoo'
            True
            >>> with context.local(log_level='debug'):
            ...    _ = t.recv() # doctest: +ELLIPSIS
            [...] Received 0xc bytes:
                b'Hello, world'
        """
        ...

    def recvS(self, *a, **kw):
        r"""
        Same as :meth:`recv`, but returns a str, decoding the result using `context.encoding`. (note that the binary versions are way faster)
        """
        ...

    def recv_raw(self, numb, *a):
        r"""
        recv_raw(numb) -> str

        Should not be called directly. Receives data without using the buffer
        on the object.

        Unless there is a timeout or closed connection, this should always
        return data. In case of a timeout, it should return None, in case
        of a closed connection it should raise an ``exceptions.EOFError``.
        """
        ...

    def recvall(self, timeout=None):
        r"""
        recvall() -> str

        Receives data until the socket is closed.
        """
        ...

    def recvallS(self, *a, **kw):
        r"""
        Same as :meth:`recvall`, but returns a str, decoding the result using `context.encoding`. (note that the binary versions are way faster)
        """
        ...

    def recvallb(self, *a, **kw):
        r"""
        Same as :meth:`recvall`, but returns a bytearray
        """
        ...

    def recvb(self, *a, **kw):
        r"""
        Same as :meth:`recv`, but returns a bytearray
        """
        ...

    def recvline(self, keepends=True, timeout=pwnlib.timeout.Timeout.default):
        r"""
        recvline(keepends=True, timeout=default) -> bytes

        Receive a single line from the tube.

        A "line" is any sequence of bytes terminated by the byte sequence
        set in :attr:`newline`, which defaults to ``'\n'``.

        If the request is not satisfied before ``timeout`` seconds pass,
        all data is buffered and an empty string (``''``) is returned.

        Arguments:
            keepends(bool): Keep the line ending (:const:`True`).
            timeout(int): Timeout

        Return:
            All bytes received over the tube until the first
            newline ``'\n'`` is received.  Optionally retains
            the ending.

        Examples:

            >>> t = tube()
            >>> t.recv_raw = lambda n: b'Foo\nBar\r\nBaz\n'
            >>> t.recvline()
            b'Foo\n'
            >>> t.recvline()
            b'Bar\r\n'
            >>> t.recvline(keepends = False)
            b'Baz'
            >>> t.newline = b'\r\n'
            >>> t.recvline(keepends = False)
            b'Foo\nBar'
        """
        ...

    def recvlineS(self, *a, **kw):
        r"""
        Same as :meth:`recvline`, but returns a str, decoding the result using `context.encoding`. (note that the binary versions are way faster)
        """
        ...

    def recvline_contains(self, items, keepends=False, timeout=pwnlib.timeout.Timeout.default):
        r"""
        Receive lines until one line is found which contains at least
        one of `items`.

        Arguments:
            items(str,tuple): List of strings to search for, or a single string.
            keepends(bool): Return lines with newlines if :const:`True`
            timeout(int): Timeout, in seconds

        Examples:

            >>> t = tube()
            >>> t.recv_raw = lambda n: b"Hello\nWorld\nXylophone\n"
            >>> t.recvline_contains(b'r')
            b'World'
            >>> f = lambda n: b"cat dog bird\napple pear orange\nbicycle car train\n"
            >>> t = tube()
            >>> t.recv_raw = f
            >>> t.recvline_contains(b'pear')
            b'apple pear orange'
            >>> t = tube()
            >>> t.recv_raw = f
            >>> t.recvline_contains((b'car', b'train'))
            b'bicycle car train'
        """
        ...

    def recvline_containsS(self, *a, **kw):
        r"""
        Same as :meth:`recvline_contains`, but returns a str, decoding the result using `context.encoding`. (note that the binary versions are way faster)
        """
        ...

    def recvline_containsb(self, *a, **kw):
        r"""
        Same as :meth:`recvline_contains`, but returns a bytearray
        """
        ...

    def recvline_endswith(self, delims, keepends=False, timeout=pwnlib.timeout.Timeout.default):
        r"""
        recvline_endswith(delims, keepends=False, timeout=default) -> bytes

        Keep receiving lines until one is found that ends with one of
        `delims`.  Returns the last line received.

        If the request is not satisfied before ``timeout`` seconds pass,
        all data is buffered and an empty string (``''``) is returned.

        See :meth:`recvline_startswith` for more details.

        Examples:

            >>> t = tube()
            >>> t.recv_raw = lambda n: b'Foo\nBar\nBaz\nKaboodle\n'
            >>> t.recvline_endswith(b'r')
            b'Bar'
            >>> t.recvline_endswith((b'a',b'b',b'c',b'd',b'e'), True)
            b'Kaboodle\n'
            >>> t.recvline_endswith(b'oodle')
            b'Kaboodle'
        """
        ...

    def recvline_endswithS(self, *a, **kw):
        r"""
        Same as :meth:`recvline_endswith`, but returns a str, decoding the result using `context.encoding`. (note that the binary versions are way faster)
        """
        ...

    def recvline_endswithb(self, *a, **kw):
        r"""
        Same as :meth:`recvline_endswith`, but returns a bytearray
        """
        ...

    def recvline_pred(self, pred, keepends=False, timeout=pwnlib.timeout.Timeout.default):
        r"""
        recvline_pred(pred, keepends=False) -> bytes

        Receive data until ``pred(line)`` returns a truthy value.
        Drop all other data.

        If the request is not satisfied before ``timeout`` seconds pass,
        all data is buffered and an empty string (``''``) is returned.

        Arguments:
            pred(callable): Function to call.  Returns the line for which
                this function returns :const:`True`.

        Examples:

            >>> t = tube()
            >>> t.recv_raw = lambda n: b"Foo\nBar\nBaz\n"
            >>> t.recvline_pred(lambda line: line == b"Bar\n")
            b'Bar'
            >>> t.recvline_pred(lambda line: line == b"Bar\n", keepends=True)
            b'Bar\n'
            >>> t.recvline_pred(lambda line: line == b'Nope!', timeout=0.1)
            b''
        """
        ...

    def recvline_regex(self, regex, exact=False, keepends=False, timeout=pwnlib.timeout.Timeout.default):
        r"""
        recvline_regex(regex, exact=False, keepends=False, timeout=default) -> bytes

        Wrapper around :func:`recvline_pred`, which will return when a regex
        matches a line.

        By default :func:`re.RegexObject.search` is used, but if `exact` is
        set to True, then :func:`re.RegexObject.match` will be used instead.

        If the request is not satisfied before ``timeout`` seconds pass,
        all data is buffered and an empty string (``''``) is returned.
        """
        ...

    def recvline_regexS(self, *a, **kw):
        r"""
        Same as :meth:`recvline_regex`, but returns a str, decoding the result using `context.encoding`. (note that the binary versions are way faster)
        """
        ...

    def recvline_regexb(self, *a, **kw):
        r"""
        Same as :meth:`recvline_regex`, but returns a bytearray
        """
        ...

    def recvline_startswith(self, delims, keepends=False, timeout=pwnlib.timeout.Timeout.default):
        r"""
        recvline_startswith(delims, keepends=False, timeout=default) -> bytes

        Keep receiving lines until one is found that starts with one of
        `delims`.  Returns the last line received.

        If the request is not satisfied before ``timeout`` seconds pass,
        all data is buffered and an empty string (``''``) is returned.

        Arguments:
            delims(str,tuple): List of strings to search for, or string of single characters
            keepends(bool): Return lines with newlines if :const:`True`
            timeout(int): Timeout, in seconds

        Returns:
            The first line received which starts with a delimiter in ``delims``.

        Examples:

            >>> t = tube()
            >>> t.recv_raw = lambda n: b"Hello\nWorld\nXylophone\n"
            >>> t.recvline_startswith((b'W',b'X',b'Y',b'Z'))
            b'World'
            >>> t.recvline_startswith((b'W',b'X',b'Y',b'Z'), True)
            b'Xylophone\n'
            >>> t.recvline_startswith(b'Wo')
            b'World'
        """
        ...

    def recvline_startswithS(self, *a, **kw):
        r"""
        Same as :meth:`recvline_startswith`, but returns a str, decoding the result using `context.encoding`. (note that the binary versions are way faster)
        """
        ...

    def recvline_startswithb(self, *a, **kw):
        r"""
        Same as :meth:`recvline_startswith`, but returns a bytearray
        """
        ...

    def recvlineb(self, *a, **kw):
        r"""
        Same as :meth:`recvline`, but returns a bytearray
        """
        ...

    def recvlines(self, numlines=1048576, keepends=False, timeout=pwnlib.timeout.Timeout.default):
        r"""
        recvlines(numlines, keepends=False, timeout=default) -> list of bytes objects

        Receive up to ``numlines`` lines.

        A "line" is any sequence of bytes terminated by the byte sequence
        set by :attr:`newline`, which defaults to ``'\n'``.

        If the request is not satisfied before ``timeout`` seconds pass,
        all data is buffered and an empty string (``''``) is returned.

        Arguments:
            numlines(int): Maximum number of lines to receive
            keepends(bool): Keep newlines at the end of each line (:const:`False`).
            timeout(int): Maximum timeout

        Raises:
            exceptions.EOFError: The connection closed before the request could be satisfied

        Returns:
            A string containing bytes received from the socket,
            or ``''`` if a timeout occurred while waiting.

        Examples:

            >>> t = tube()
            >>> t.recv_raw = lambda n: b'\n'
            >>> t.recvlines(3)
            [b'', b'', b'']
            >>> t.recv_raw = lambda n: b'Foo\nBar\nBaz\n'
            >>> t.recvlines(3)
            [b'Foo', b'Bar', b'Baz']
            >>> t.recvlines(3, True)
            [b'Foo\n', b'Bar\n', b'Baz\n']
        """
        ...

    def recvlinesS(self, numlines=1048576, keepends=False, timeout=pwnlib.timeout.Timeout.default):
        r"""
        recvlinesS(numlines, keepends=False, timeout=default) -> str list

        This function is identical to :meth:`recvlines`, but decodes
        the received bytes into string using :func:`context.encoding`.
        You should use :meth:`recvlines` whenever possible for better performance.

        Examples:

            >>> t = tube()
            >>> t.recv_raw = lambda n: b'\n'
            >>> t.recvlinesS(3)
            ['', '', '']
            >>> t.recv_raw = lambda n: b'Foo\nBar\nBaz\n'
            >>> t.recvlinesS(3)
            ['Foo', 'Bar', 'Baz']
        """
        ...

    def recvlinesb(self, numlines=1048576, keepends=False, timeout=pwnlib.timeout.Timeout.default):
        r"""
        recvlinesb(numlines, keepends=False, timeout=default) -> bytearray list

        This function is identical to :meth:`recvlines`, but returns a bytearray.

        Examples:

            >>> t = tube()
            >>> t.recv_raw = lambda n: b'\n'
            >>> t.recvlinesb(3)
            [bytearray(b''), bytearray(b''), bytearray(b'')]
            >>> t.recv_raw = lambda n: b'Foo\nBar\nBaz\n'
            >>> t.recvlinesb(3)
            [bytearray(b'Foo'), bytearray(b'Bar'), bytearray(b'Baz')]
        """
        ...

    def recvn(self, numb, timeout=pwnlib.timeout.Timeout.default):
        r"""
        recvn(numb, timeout = default) -> str

        Receives exactly `n` bytes.

        If the request is not satisfied before ``timeout`` seconds pass,
        all data is buffered and an empty string (``''``) is returned.

        Raises:
            exceptions.EOFError: The connection closed before the request could be satisfied

        Returns:
            A string containing bytes received from the socket,
            or ``''`` if a timeout occurred while waiting.

        Examples:

            >>> t = tube()
            >>> data = b'hello world'
            >>> t.recv_raw = lambda *a: data
            >>> t.recvn(len(data)) == data
            True
            >>> t.recvn(len(data)+1) == data + data[:1]
            True
            >>> t.recv_raw = lambda *a: None
            >>> # The remaining data is buffered
            >>> t.recv() == data[1:]
            True
            >>> t.recv_raw = lambda *a: time.sleep(0.01) or b'a'
            >>> t.recvn(10, timeout=0.05)
            b''
            >>> t.recvn(10, timeout=0.06) # doctest: +ELLIPSIS
            b'aaaaaa...'
        """
        ...

    def recvnS(self, *a, **kw):
        r"""
        Same as :meth:`recvn`, but returns a str, decoding the result using `context.encoding`. (note that the binary versions are way faster)
        """
        ...

    def recvnb(self, *a, **kw):
        r"""
        Same as :meth:`recvn`, but returns a bytearray
        """
        ...

    def recvpred(self, pred, timeout=pwnlib.timeout.Timeout.default):
        r"""
        recvpred(pred, timeout = default) -> bytes

        Receives one byte at a time from the tube, until ``pred(all_bytes)``
        evaluates to True.

        If the request is not satisfied before ``timeout`` seconds pass,
        all data is buffered and an empty string (``''``) is returned.

        Arguments:
            pred(callable): Function to call, with the currently-accumulated data.
            timeout(int): Timeout for the operation

        Raises:
            exceptions.EOFError: The connection is closed

        Returns:
            A bytes object containing bytes received from the socket,
            or ``''`` if a timeout occurred while waiting.
        """
        ...

    def recvpredS(self, *a, **kw):
        r"""
        Same as :meth:`recvpred`, but returns a str, decoding the result using `context.encoding`. (note that the binary versions are way faster)
        """
        ...

    def recvpredb(self, *a, **kw):
        r"""
        Same as :meth:`recvpred`, but returns a bytearray
        """
        ...

    def recvregex(self, regex, exact=False, timeout=pwnlib.timeout.Timeout.default):
        r"""
        recvregex(regex, exact=False, timeout=default) -> bytes

        Wrapper around :func:`recvpred`, which will return when a regex
        matches the string in the buffer.

        By default :func:`re.RegexObject.search` is used, but if `exact` is
        set to True, then :func:`re.RegexObject.match` will be used instead.

        If the request is not satisfied before ``timeout`` seconds pass,
        all data is buffered and an empty string (``''``) is returned.
        """
        ...

    def recvregexS(self, *a, **kw):
        r"""
        Same as :meth:`recvregex`, but returns a str, decoding the result using `context.encoding`. (note that the binary versions are way faster)
        """
        ...

    def recvregexb(self, *a, **kw):
        r"""
        Same as :meth:`recvregex`, but returns a bytearray
        """
        ...

    def recvrepeat(self, timeout=pwnlib.timeout.Timeout.default):
        r"""
        recvrepeat(timeout=default) -> bytes

        Receives data until a timeout or EOF is reached.

        Examples:

            >>> data = [
            ... b'd',
            ... b'', # simulate timeout
            ... b'c',
            ... b'b',
            ... b'a',
            ... ]
            >>> def delayrecv(n, data=data):
            ...     return data.pop()
            >>> t = tube()
            >>> t.recv_raw = delayrecv
            >>> t.recvrepeat(0.2)
            b'abc'
            >>> t.recv()
            b'd'
        """
        ...

    def recvrepeatS(self, *a, **kw):
        r"""
        Same as :meth:`recvrepeat`, but returns a str, decoding the result using `context.encoding`. (note that the binary versions are way faster)
        """
        ...

    def recvrepeatb(self, *a, **kw):
        r"""
        Same as :meth:`recvrepeat`, but returns a bytearray
        """
        ...

    def recvuntil(self, delims, drop=False, timeout=pwnlib.timeout.Timeout.default):
        r"""
        recvuntil(delims, drop=False, timeout=default) -> bytes

        Receive data until one of `delims` is encountered.

        If the request is not satisfied before ``timeout`` seconds pass,
        all data is buffered and an empty string (``''``) is returned.

        arguments:
            delims(bytes,tuple): Byte-string of delimiters characters, or list of delimiter byte-strings.
            drop(bool): Drop the ending.  If :const:`True` it is removed from the end of the return value.

        Raises:
            exceptions.EOFError: The connection closed before the request could be satisfied

        Returns:
            A string containing bytes received from the socket,
            or ``''`` if a timeout occurred while waiting.

        Examples:

            >>> t = tube()
            >>> t.recv_raw = lambda n: b"Hello World!"
            >>> t.recvuntil(b' ')
            b'Hello '
            >>> _=t.clean(0)
            >>> # Matches on 'o' in 'Hello'
            >>> t.recvuntil((b' ',b'W',b'o',b'r'))
            b'Hello'
            >>> _=t.clean(0)
            >>> # Matches expressly full string
            >>> t.recvuntil(b' Wor')
            b'Hello Wor'
            >>> _=t.clean(0)
            >>> # Matches on full string, drops match
            >>> t.recvuntil(b' Wor', drop=True)
            b'Hello'

            >>> # Try with regex special characters
            >>> t = tube()
            >>> t.recv_raw = lambda n: b"Hello|World"
            >>> t.recvuntil(b'|', drop=True)
            b'Hello'
        """
        ...

    def recvuntilS(self, *a, **kw):
        r"""
        Same as :meth:`recvuntil`, but returns a str, decoding the result using `context.encoding`. (note that the binary versions are way faster)
        """
        ...

    def recvuntilb(self, *a, **kw):
        r"""
        Same as :meth:`recvuntil`, but returns a bytearray
        """
        ...

    def removeHandler(self, handler):
        r"""
        removeHandler(handler)

        Remove the specified handler from the underlying logger.
        """
        ...

    def send(self, data):
        r"""
        send(data)

        Sends data.

        If log level ``DEBUG`` is enabled, also prints out the data
        received.

        If it is not possible to send anymore because of a closed
        connection, it raises ``exceptions.EOFError``

        Examples:

            >>> def p(x): print(repr(x))
            >>> t = tube()
            >>> t.send_raw = p
            >>> t.send(b'hello')
            b'hello'
        """
        ...

    def send_raw(self, data):
        r"""
        send_raw(data)

        Should not be called directly. Sends data to the tube.

        Should return ``exceptions.EOFError``, if it is unable to send any
        more, because of a close tube.
        """
        ...

    def sendafter(self, delim, data, timeout=pwnlib.timeout.Timeout.default):
        r"""
        sendafter(delim, data, timeout = default) -> str

        A combination of ``recvuntil(delim, timeout=timeout)`` and ``send(data)``.
        """
        ...

    def sendline(self, line=b''):
        r"""
        sendline(data)

        Shorthand for ``t.send(data + t.newline)``.

        Examples:

            >>> def p(x): print(repr(x))
            >>> t = tube()
            >>> t.send_raw = p
            >>> t.sendline(b'hello')
            b'hello\n'
            >>> t.newline = b'\r\n'
            >>> t.sendline(b'hello')
            b'hello\r\n'
        """
        ...

    def sendlineafter(self, delim, data, timeout=pwnlib.timeout.Timeout.default):
        r"""
        sendlineafter(delim, data, timeout = default) -> str

        A combination of ``recvuntil(delim, timeout=timeout)`` and ``sendline(data)``.
        """
        ...

    def sendlines(self, lines=[]):

        ...

    def sendlinethen(self, delim, data, timeout=pwnlib.timeout.Timeout.default):
        r"""
        sendlinethen(delim, data, timeout = default) -> str

        A combination of ``sendline(data)`` and ``recvuntil(delim, timeout=timeout)``.
        """
        ...

    def sendthen(self, delim, data, timeout=pwnlib.timeout.Timeout.default):
        r"""
        sendthen(delim, data, timeout = default) -> str

        A combination of ``send(data)`` and ``recvuntil(delim, timeout=timeout)``.
        """
        ...

    def setLevel(self, level):
        r"""
        setLevel(level)

        Set the logging level for the underlying logger.
        """
        ...

    def settimeout(self, timeout):
        r"""
        settimeout(timeout)

        Set the timeout for receiving operations. If the string "default"
        is given, then :data:`context.timeout` will be used. If None is given,
        then there will be no timeout.

        Examples:

            >>> t = tube()
            >>> t.settimeout_raw = lambda t: None
            >>> t.settimeout(3)
            >>> t.timeout == 3
            True
        """
        ...

    def settimeout_raw(self, timeout):
        r"""
        settimeout_raw(timeout)

        Should not be called directly. Sets the timeout for
        the tube.
        """
        ...

    def shutdown(self, direction='send'):
        r"""
        shutdown(direction = "send")

        Closes the tube for futher reading or writing depending on `direction`.

        Arguments:
          direction(str): Which direction to close; "in", "read" or "recv"
            closes the tube in the ingoing direction, "out", "write" or "send"
            closes it in the outgoing direction.

        Returns:
          :const:`None`

        Examples:

            >>> def p(x): print(x)
            >>> t = tube()
            >>> t.shutdown_raw = p
            >>> _=list(map(t.shutdown, ('in', 'read', 'recv', 'out', 'write', 'send')))
            recv
            recv
            recv
            send
            send
            send
            >>> t.shutdown('bad_value') #doctest: +ELLIPSIS
            Traceback (most recent call last):
            ...
            KeyError: "direction must be in ['in', 'out', 'read', 'recv', 'send', 'write']"
        """
        ...

    def shutdown_raw(self, direction):
        r"""
        shutdown_raw(direction)

        Should not be called directly.  Closes the tube for further reading or
        writing.
        """
        ...

    def spawn_process(self, *args, **kwargs):
        r"""
        Spawns a new process having this tube as stdin, stdout and stderr.

        Takes the same arguments as :class:`subprocess.Popen`.
        """
        ...

    def stream(self, line_mode=True):
        r"""
        stream()

        Receive data until the tube exits, and print it to stdout.

        Similar to :func:`interactive`, except that no input is sent.

        Similar to ``print(tube.recvall())`` except that data is printed
        as it is received, rather than after all data is received.

        Arguments:
            line_mode(bool): Whether to receive line-by-line or raw data.

        Returns:
            All data printed.
        """
        ...

    def success(self, message, *args, **kwargs):
        r"""
        success(message, *args, **kwargs)

        Logs a success message.
        """
        ...

    def timeout_change(self):
        r"""
        Informs the raw layer of the tube that the timeout has changed.

        Should not be called directly.

        Inherited from :class:`Timeout`.
        """
        ...

    def u16(self, *a, **kw):

        ...

    def u32(self, *a, **kw):

        ...

    def u64(self, *a, **kw):

        ...

    def u8(self, *a, **kw):

        ...

    def unpack(self, *a, **kw):

        ...

    def unread(self, *a, **kw):
        r"""
        Alias for :meth:`unrecv`
        """
        ...

    def unrecv(self, data):
        r"""
        unrecv(data)

        Puts the specified data back at the beginning of the receive
        buffer.

        Examples:

            >>> t = tube()
            >>> t.recv_raw = lambda n: b'hello'
            >>> t.recv()
            b'hello'
            >>> t.recv()
            b'hello'
            >>> t.unrecv(b'world')
            >>> t.recv()
            b'world'
            >>> t.recv()
            b'hello'
        """
        ...

    def wait(self, timeout=pwnlib.timeout.Timeout.default):
        r"""
        Waits until the tube is closed.
        """
        ...

    def wait_for_close(self, timeout=pwnlib.timeout.Timeout.default):
        r"""
        Waits until the tube is closed.
        """
        ...

    def waitfor(self, *args, **kwargs):
        r"""
        Alias for :meth:`progress`.
        """
        ...

    def warn(self, *args, **kwargs):
        r"""
        Alias for :meth:`warning`.
        """
        ...

    def warn_once(self, *args, **kwargs):
        r"""
        Alias for :meth:`warning_once`.
        """
        ...

    def warning(self, message, *args, **kwargs):
        r"""
        warning(message, *args, **kwargs)

        Logs a warning message.
        """
        ...

    def warning_once(self, message, *args, **kwargs):
        r"""
        warning_once(message, *args, **kwargs)

        Logs a warning message.  The same message is never printed again.
        """
        ...

    def write(self, *a, **kw):
        r"""
        Alias for :meth:`send`
        """
        ...

    def write_raw(self, *a, **kw):
        r"""
        Alias for :meth:`send_raw`
        """
        ...

    def writeafter(self, *a, **kw):
        r"""
        Alias for :meth:`sendafter`
        """
        ...

    def writeline(self, *a, **kw):
        r"""
        Alias for :meth:`sendline`
        """
        ...

    def writelineafter(self, *a, **kw):
        r"""
        Alias for :meth:`sendlineafter`
        """
        ...

    def writelines(self, *a, **kw):
        r"""
        Alias for :meth:`sendlines`
        """
        ...

    def writelinethen(self, *a, **kw):
        r"""
        Alias for :meth:`sendlinethen`
        """
        ...

    def writethen(self, *a, **kw):
        r"""
        Alias for :meth:`sendthen`
        """
        ...

class remote (pwnlib.tubes.sock.sock):
    r"""
    Creates a TCP or UDP-connection to a remote host. It supports
    both IPv4 and IPv6.

    The returned object supports all the methods from
    :class:`pwnlib.tubes.sock` and :class:`pwnlib.tubes.tube`.

    Arguments:
        host(str): The host to connect to.
        port(int): The port to connect to.
        fam: The string "any", "ipv4" or "ipv6" or an integer to pass to :func:`socket.getaddrinfo`.
        typ: The string "tcp" or "udp" or an integer to pass to :func:`socket.getaddrinfo`.
        timeout: A positive number, None or the string "default".
        ssl(bool): Wrap the socket with SSL
        ssl_context(ssl.SSLContext): Specify SSLContext used to wrap the socket.
        sni: Set 'server_hostname' in ssl_args based on the host parameter.
        sock(socket.socket): Socket to inherit, rather than connecting
        ssl_args(dict): Pass ssl.wrap_socket named arguments in a dictionary.

    Examples:

        >>> r = remote('google.com', 443, ssl=True)
        >>> r.send(b'GET /\r\n\r\n')
        >>> r.recvn(4)
        b'HTTP'

        If a connection cannot be made, an exception is raised.

        >>> r = remote('127.0.0.1', 1)
        Traceback (most recent call last):
        ...
        PwnlibException: Could not connect to 127.0.0.1 on port 1

        You can also use :meth:`.remote.fromsocket` to wrap an existing socket.

        >>> import socket
        >>> s = socket.socket()
        >>> s.connect(('google.com', 80))
        >>> s.send(b'GET /' + b'\r\n'*2)
        9
        >>> r = remote.fromsocket(s)
        >>> r.recvn(4)
        b'HTTP'
    """
    def __enter__(self):
        r"""
        Permit use of 'with' to control scoping and closing sessions.

        Examples:

            >>> t = tube()
            >>> def p(x): print(x)
            >>> t.close = lambda: p("Closed!")
            >>> with t: pass
            Closed!
        """
        ...

    def __exit__(self, type, value, traceback):
        r"""
        Handles closing for 'with' statement

        See :meth:`__enter__`
        """
        ...

    def __init__(self, host, port, fam='any', typ='tcp', ssl=False, sock=None, ssl_context=None, ssl_args=None, sni=True, *args, **kwargs):
        r"""
        Initialize self.  See help(type(self)) for accurate signature.
        """
        ...

    def __lshift__(self, other):
        r"""
        Shorthand for connecting multiple tubes.

        See :meth:`connect_input` for more information.

        Examples:

            The following are equivalent ::

                tube_a >> tube.b
                tube_a.connect_input(tube_b)

            This is useful when chaining multiple tubes ::

                tube_a >> tube_b >> tube_a
                tube_a.connect_input(tube_b)
                tube_b.connect_input(tube_a)
        """
        ...

    def __ne__(self, other):
        r"""
        Shorthand for connecting tubes to eachother.

        The following are equivalent ::

            a >> b >> a
            a <> b

        See :meth:`connect_input` for more information.
        """
        ...

    def __rshift__(self, other):
        r"""
        Inverse of the ``<<`` operator.  See :meth:`__lshift__`.

        See :meth:`connect_input` for more information.
        """
        ...

    def _close_msg(self):

        ...

    def _connect(self, fam, typ):

        ...

    def _fillbuffer(self, timeout=pwnlib.timeout.Timeout.default):
        r"""
        _fillbuffer(timeout = default)

        Fills the internal buffer from the pipe, by calling
        :meth:`recv_raw` exactly once.

        Returns:

            The bytes of data received, or ``''`` if no data was received.

        Examples:

            >>> t = tube()
            >>> t.recv_raw = lambda *a: b'abc'
            >>> len(t.buffer)
            0
            >>> t._fillbuffer()
            b'abc'
            >>> len(t.buffer)
            3
        """
        ...

    def _get_timeout_seconds(self, value):

        ...

    def _getlevel(self, levelString):

        ...

    def _log(self, level, msg, args, kwargs, msgtype, progress=None):

        ...

    def _read(self, *a, **kw):
        r"""
        Alias for :meth:`_recv`
        """
        ...

    def _recv(self, numb=None, timeout=pwnlib.timeout.Timeout.default):
        r"""
        _recv(numb = 4096, timeout = default) -> str

        Receives one chunk of from the internal buffer or from the OS if the
        buffer is empty.
        """
        ...

    def addHandler(self, handler):
        r"""
        addHandler(handler)

        Add the specified handler to the underlying logger.
        """
        ...

    def can_read(self, *a, **kw):
        r"""
        Alias for :meth:`can_recv`
        """
        ...

    def can_read_raw(self, *a, **kw):
        r"""
        Alias for :meth:`can_recv_raw`
        """
        ...

    def can_recv(self, timeout=0):
        r"""
        can_recv(timeout = 0) -> bool

        Returns True, if there is data available within `timeout` seconds.

        Examples:

            >>> import time
            >>> t = tube()
            >>> t.can_recv_raw = lambda *a: False
            >>> t.can_recv()
            False
            >>> _=t.unrecv(b'data')
            >>> t.can_recv()
            True
            >>> _=t.recv()
            >>> t.can_recv()
            False
        """
        ...

    def can_recv_raw(self, timeout):
        r"""
        Tests:

            >>> l = listen()
            >>> r = remote('localhost', l.lport)
            >>> r.can_recv_raw(timeout=0)
            False
            >>> l.send(b'a')
            >>> r.can_recv_raw(timeout=1)
            True
            >>> r.recv()
            b'a'
            >>> r.can_recv_raw(timeout=0)
            False
            >>> l.close()
            >>> r.can_recv_raw(timeout=1)
            False
            >>> r.closed['recv']
            True
        """
        ...

    def clean(self, timeout=0.05):
        r"""
        clean(timeout = 0.05)

        Removes all the buffered data from a tube by calling
        :meth:`pwnlib.tubes.tube.tube.recv` with a low timeout until it fails.

        If ``timeout`` is zero, only cached data will be cleared.

        Note: If timeout is set to zero, the underlying network is
        not actually polled; only the internal buffer is cleared.

        Returns:

            All data received

        Examples:

            >>> t = tube()
            >>> t.unrecv(b'clean me up')
            >>> t.clean(0)
            b'clean me up'
            >>> len(t.buffer)
            0
        """
        ...

    def clean_and_log(self, timeout=0.05):
        r"""
        clean_and_log(timeout = 0.05)

        Works exactly as :meth:`pwnlib.tubes.tube.tube.clean`, but logs received
        data with :meth:`pwnlib.self.info`.

        Returns:

            All data received

        Examples:

            >>> def recv(n, data=[b'', b'hooray_data']):
            ...     while data: return data.pop()
            >>> t = tube()
            >>> t.recv_raw      = recv
            >>> t.connected_raw = lambda d: True
            >>> t.fileno        = lambda: 1234
            >>> with context.local(log_level='info'):
            ...     data = t.clean_and_log() #doctest: +ELLIPSIS
            [DEBUG] Received 0xb bytes:
                b'hooray_data'
            >>> data
            b'hooray_data'
            >>> context.clear()
        """
        ...

    def close(self):
        r"""
        close()

        Closes the tube.
        """
        ...

    def connect_both(self, other):
        r"""
        connect_both(other)

        Connects the both ends of this tube object with another tube object.
        """
        ...

    def connect_input(self, other):
        r"""
        connect_input(other)

        Connects the input of this tube to the output of another tube object.


        Examples:

            >>> def p(x): print(x.decode())
            >>> def recvone(n, data=[b'data']):
            ...     while data: return data.pop()
            ...     raise EOFError
            >>> a = tube()
            >>> b = tube()
            >>> a.recv_raw = recvone
            >>> b.send_raw = p
            >>> a.connected_raw = lambda d: True
            >>> b.connected_raw = lambda d: True
            >>> a.shutdown      = lambda d: True
            >>> b.shutdown      = lambda d: True
            >>> import time
            >>> _=(b.connect_input(a), time.sleep(0.1))
            data
        """
        ...

    def connect_output(self, other):
        r"""
        connect_output(other)

        Connects the output of this tube to the input of another tube object.

        Examples:

            >>> def p(x): print(repr(x))
            >>> def recvone(n, data=[b'data']):
            ...     while data: return data.pop()
            ...     raise EOFError
            >>> a = tube()
            >>> b = tube()
            >>> a.recv_raw = recvone
            >>> b.send_raw = p
            >>> a.connected_raw = lambda d: True
            >>> b.connected_raw = lambda d: True
            >>> a.shutdown      = lambda d: True
            >>> b.shutdown      = lambda d: True
            >>> _=(a.connect_output(b), time.sleep(0.1))
            b'data'
        """
        ...

    def connected(self, direction='any'):
        r"""
        connected(direction = 'any') -> bool

        Returns True if the tube is connected in the specified direction.

        Arguments:
          direction(str): Can be the string 'any', 'in', 'read', 'recv',
                          'out', 'write', 'send'.

        Doctest:

            >>> def p(x): print(x)
            >>> t = tube()
            >>> t.connected_raw = p
            >>> _=list(map(t.connected, ('any', 'in', 'read', 'recv', 'out', 'write', 'send')))
            any
            recv
            recv
            recv
            send
            send
            send
            >>> t.connected('bad_value') #doctest: +ELLIPSIS
            Traceback (most recent call last):
            ...
            KeyError: "direction must be in ['any', 'in', 'out', 'read', 'recv', 'send', 'write']"
        """
        ...

    def connected_raw(self, direction):
        r"""
        Tests:

            >>> l = listen()
            >>> r = remote('localhost', l.lport)
            >>> r.connected()
            True
            >>> l.close()
            >>> time.sleep(0.1) # Avoid race condition
            >>> r.connected()
            False
        """
        ...

    def countdown(self, timeout=pwnlib.timeout.Timeout.default):
        r"""
        Scoped timeout setter.  Sets the timeout within the scope,
        and restores it when leaving the scope.

        When accessing :attr:`timeout` within the scope, it will be
        calculated against the time when the scope was entered, in a
        countdown fashion.

        If :const:`None` is specified for ``timeout``, then the current
        timeout is used is made.  This allows :const:`None` to be specified
        as a default argument with less complexity.
        """
        ...

    def countdown_active(self):

        ...

    def critical(self, message, *args, **kwargs):
        r"""
        critical(message, *args, **kwargs)

        Logs a critical message.
        """
        ...

    def debug(self, message, *args, **kwargs):
        r"""
        debug(message, *args, **kwargs)

        Logs a debug message.
        """
        ...

    def error(self, message, *args, **kwargs):
        r"""
        error(message, *args, **kwargs)

        To be called outside an exception handler.

        Logs an error message, then raises a ``PwnlibException``.
        """
        ...

    def exception(self, message, *args, **kwargs):
        r"""
        exception(message, *args, **kwargs)

        To be called from an exception handler.

        Logs a error message, then re-raises the current exception.
        """
        ...

    def failure(self, message, *args, **kwargs):
        r"""
        failure(message, *args, **kwargs)

        Logs a failure message.
        """
        ...

    def fileno(self):
        r"""
        fileno() -> int

        Returns the file number used for reading.
        """
        ...

    def fit(self, *a, **kw):

        ...

    def flat(self, *a, **kw):

        ...

    def hexdump(self, message, *args, **kwargs):

        ...

    def indented(self, message, *args, **kwargs):
        r"""
        indented(message, *args, level = logging.INFO, **kwargs)

        Log a message but don't put a line prefix on it.

        Arguments:
            level(int): Alternate log level at which to set the indented
                        message.  Defaults to :const:`logging.INFO`.
        """
        ...

    def info(self, message, *args, **kwargs):
        r"""
        info(message, *args, **kwargs)

        Logs an info message.
        """
        ...

    def info_once(self, message, *args, **kwargs):
        r"""
        info_once(message, *args, **kwargs)

        Logs an info message.  The same message is never printed again.
        """
        ...

    def interactive(self, prompt='\x1b[1m\x1b[31m$\x1b[m '):
        r"""
        interactive(prompt = pwnlib.term.text.bold_red('$') + ' ')

        Does simultaneous reading and writing to the tube. In principle this just
        connects the tube to standard in and standard out, but in practice this
        is much more usable, since we are using :mod:`pwnlib.term` to print a
        floating prompt.

        Thus it only works in while in :data:`pwnlib.term.term_mode`.
        """
        ...

    def isEnabledFor(self, level):
        r"""
        isEnabledFor(level) -> bool

        See if the underlying logger is enabled for the specified level.
        """
        ...

    def local(self, timeout):
        r"""
        Scoped timeout setter.  Sets the timeout within the scope,
        and restores it when leaving the scope.
        """
        ...

    def log(self, level, message, *args, **kwargs):
        r"""
        log(level, message, *args, **kwargs)

        Logs a message with log level `level`.  The ``pwnlib`` formatter will
        use the default :mod:`logging` formater to format this message.
        """
        ...

    def p16(self, *a, **kw):

        ...

    def p32(self, *a, **kw):

        ...

    def p64(self, *a, **kw):

        ...

    def p8(self, *a, **kw):

        ...

    def pack(self, *a, **kw):

        ...

    def progress(self, message, status='', *args, **kwargs):
        r"""
        progress(message, status = '', *args, level = logging.INFO, **kwargs) -> Progress

        Creates a new progress logger which creates log records with log level
        `level`.

        Progress status can be updated using :meth:`Progress.status` and stopped
        using :meth:`Progress.success` or :meth:`Progress.failure`.

        If `term.term_mode` is enabled the progress logger will be animated.

        The progress manager also functions as a context manager.  Using context
        managers ensures that animations stop even if an exception is raised.

        .. code-block:: python

           with log.progress('Trying something...') as p:
               for i in range(10):
                   p.status("At %i" % i)
                   time.sleep(0.5)
               x = 1/0
        """
        ...

    def read(self, *a, **kw):
        r"""
        Alias for :meth:`recv`
        """
        ...

    def readS(self, *a, **kw):
        r"""
        Alias for :meth:`recvS`
        """
        ...

    def read_raw(self, *a, **kw):
        r"""
        Alias for :meth:`recv_raw`
        """
        ...

    def readall(self, *a, **kw):
        r"""
        Alias for :meth:`recvall`
        """
        ...

    def readallS(self, *a, **kw):
        r"""
        Alias for :meth:`recvallS`
        """
        ...

    def readallb(self, *a, **kw):
        r"""
        Alias for :meth:`recvallb`
        """
        ...

    def readb(self, *a, **kw):
        r"""
        Alias for :meth:`recvb`
        """
        ...

    def readline(self, *a, **kw):
        r"""
        Alias for :meth:`recvline`
        """
        ...

    def readlineS(self, *a, **kw):
        r"""
        Alias for :meth:`recvlineS`
        """
        ...

    def readline_contains(self, *a, **kw):
        r"""
        Alias for :meth:`recvline_contains`
        """
        ...

    def readline_containsS(self, *a, **kw):
        r"""
        Alias for :meth:`recvline_containsS`
        """
        ...

    def readline_containsb(self, *a, **kw):
        r"""
        Alias for :meth:`recvline_containsb`
        """
        ...

    def readline_endswith(self, *a, **kw):
        r"""
        Alias for :meth:`recvline_endswith`
        """
        ...

    def readline_endswithS(self, *a, **kw):
        r"""
        Alias for :meth:`recvline_endswithS`
        """
        ...

    def readline_endswithb(self, *a, **kw):
        r"""
        Alias for :meth:`recvline_endswithb`
        """
        ...

    def readline_pred(self, *a, **kw):
        r"""
        Alias for :meth:`recvline_pred`
        """
        ...

    def readline_regex(self, *a, **kw):
        r"""
        Alias for :meth:`recvline_regex`
        """
        ...

    def readline_regexS(self, *a, **kw):
        r"""
        Alias for :meth:`recvline_regexS`
        """
        ...

    def readline_regexb(self, *a, **kw):
        r"""
        Alias for :meth:`recvline_regexb`
        """
        ...

    def readline_startswith(self, *a, **kw):
        r"""
        Alias for :meth:`recvline_startswith`
        """
        ...

    def readline_startswithS(self, *a, **kw):
        r"""
        Alias for :meth:`recvline_startswithS`
        """
        ...

    def readline_startswithb(self, *a, **kw):
        r"""
        Alias for :meth:`recvline_startswithb`
        """
        ...

    def readlineb(self, *a, **kw):
        r"""
        Alias for :meth:`recvlineb`
        """
        ...

    def readlines(self, *a, **kw):
        r"""
        Alias for :meth:`recvlines`
        """
        ...

    def readlinesS(self, *a, **kw):
        r"""
        Alias for :meth:`recvlinesS`
        """
        ...

    def readlinesb(self, *a, **kw):
        r"""
        Alias for :meth:`recvlinesb`
        """
        ...

    def readn(self, *a, **kw):
        r"""
        Alias for :meth:`recvn`
        """
        ...

    def readnS(self, *a, **kw):
        r"""
        Alias for :meth:`recvnS`
        """
        ...

    def readnb(self, *a, **kw):
        r"""
        Alias for :meth:`recvnb`
        """
        ...

    def readpred(self, *a, **kw):
        r"""
        Alias for :meth:`recvpred`
        """
        ...

    def readpredS(self, *a, **kw):
        r"""
        Alias for :meth:`recvpredS`
        """
        ...

    def readpredb(self, *a, **kw):
        r"""
        Alias for :meth:`recvpredb`
        """
        ...

    def readregex(self, *a, **kw):
        r"""
        Alias for :meth:`recvregex`
        """
        ...

    def readregexS(self, *a, **kw):
        r"""
        Alias for :meth:`recvregexS`
        """
        ...

    def readregexb(self, *a, **kw):
        r"""
        Alias for :meth:`recvregexb`
        """
        ...

    def readrepeat(self, *a, **kw):
        r"""
        Alias for :meth:`recvrepeat`
        """
        ...

    def readrepeatS(self, *a, **kw):
        r"""
        Alias for :meth:`recvrepeatS`
        """
        ...

    def readrepeatb(self, *a, **kw):
        r"""
        Alias for :meth:`recvrepeatb`
        """
        ...

    def readuntil(self, *a, **kw):
        r"""
        Alias for :meth:`recvuntil`
        """
        ...

    def readuntilS(self, *a, **kw):
        r"""
        Alias for :meth:`recvuntilS`
        """
        ...

    def readuntilb(self, *a, **kw):
        r"""
        Alias for :meth:`recvuntilb`
        """
        ...

    def recv(self, numb=None, timeout=pwnlib.timeout.Timeout.default):
        r"""
        recv(numb = 4096, timeout = default) -> bytes

        Receives up to `numb` bytes of data from the tube, and returns
        as soon as any quantity of data is available.

        If the request is not satisfied before ``timeout`` seconds pass,
        all data is buffered and an empty string (``''``) is returned.

        Raises:
            exceptions.EOFError: The connection is closed

        Returns:
            A bytes object containing bytes received from the socket,
            or ``''`` if a timeout occurred while waiting.

        Examples:

            >>> t = tube()
            >>> # Fake a data source
            >>> t.recv_raw = lambda n: b'Hello, world'
            >>> t.recv() == b'Hello, world'
            True
            >>> t.unrecv(b'Woohoo')
            >>> t.recv() == b'Woohoo'
            True
            >>> with context.local(log_level='debug'):
            ...    _ = t.recv() # doctest: +ELLIPSIS
            [...] Received 0xc bytes:
                b'Hello, world'
        """
        ...

    def recvS(self, *a, **kw):
        r"""
        Same as :meth:`recv`, but returns a str, decoding the result using `context.encoding`. (note that the binary versions are way faster)
        """
        ...

    def recv_raw(self, numb, *a):
        r"""
        recv_raw(numb) -> str

        Should not be called directly. Receives data without using the buffer
        on the object.

        Unless there is a timeout or closed connection, this should always
        return data. In case of a timeout, it should return None, in case
        of a closed connection it should raise an ``exceptions.EOFError``.
        """
        ...

    def recvall(self, timeout=None):
        r"""
        recvall() -> str

        Receives data until the socket is closed.
        """
        ...

    def recvallS(self, *a, **kw):
        r"""
        Same as :meth:`recvall`, but returns a str, decoding the result using `context.encoding`. (note that the binary versions are way faster)
        """
        ...

    def recvallb(self, *a, **kw):
        r"""
        Same as :meth:`recvall`, but returns a bytearray
        """
        ...

    def recvb(self, *a, **kw):
        r"""
        Same as :meth:`recv`, but returns a bytearray
        """
        ...

    def recvline(self, keepends=True, timeout=pwnlib.timeout.Timeout.default):
        r"""
        recvline(keepends=True, timeout=default) -> bytes

        Receive a single line from the tube.

        A "line" is any sequence of bytes terminated by the byte sequence
        set in :attr:`newline`, which defaults to ``'\n'``.

        If the request is not satisfied before ``timeout`` seconds pass,
        all data is buffered and an empty string (``''``) is returned.

        Arguments:
            keepends(bool): Keep the line ending (:const:`True`).
            timeout(int): Timeout

        Return:
            All bytes received over the tube until the first
            newline ``'\n'`` is received.  Optionally retains
            the ending.

        Examples:

            >>> t = tube()
            >>> t.recv_raw = lambda n: b'Foo\nBar\r\nBaz\n'
            >>> t.recvline()
            b'Foo\n'
            >>> t.recvline()
            b'Bar\r\n'
            >>> t.recvline(keepends = False)
            b'Baz'
            >>> t.newline = b'\r\n'
            >>> t.recvline(keepends = False)
            b'Foo\nBar'
        """
        ...

    def recvlineS(self, *a, **kw):
        r"""
        Same as :meth:`recvline`, but returns a str, decoding the result using `context.encoding`. (note that the binary versions are way faster)
        """
        ...

    def recvline_contains(self, items, keepends=False, timeout=pwnlib.timeout.Timeout.default):
        r"""
        Receive lines until one line is found which contains at least
        one of `items`.

        Arguments:
            items(str,tuple): List of strings to search for, or a single string.
            keepends(bool): Return lines with newlines if :const:`True`
            timeout(int): Timeout, in seconds

        Examples:

            >>> t = tube()
            >>> t.recv_raw = lambda n: b"Hello\nWorld\nXylophone\n"
            >>> t.recvline_contains(b'r')
            b'World'
            >>> f = lambda n: b"cat dog bird\napple pear orange\nbicycle car train\n"
            >>> t = tube()
            >>> t.recv_raw = f
            >>> t.recvline_contains(b'pear')
            b'apple pear orange'
            >>> t = tube()
            >>> t.recv_raw = f
            >>> t.recvline_contains((b'car', b'train'))
            b'bicycle car train'
        """
        ...

    def recvline_containsS(self, *a, **kw):
        r"""
        Same as :meth:`recvline_contains`, but returns a str, decoding the result using `context.encoding`. (note that the binary versions are way faster)
        """
        ...

    def recvline_containsb(self, *a, **kw):
        r"""
        Same as :meth:`recvline_contains`, but returns a bytearray
        """
        ...

    def recvline_endswith(self, delims, keepends=False, timeout=pwnlib.timeout.Timeout.default):
        r"""
        recvline_endswith(delims, keepends=False, timeout=default) -> bytes

        Keep receiving lines until one is found that ends with one of
        `delims`.  Returns the last line received.

        If the request is not satisfied before ``timeout`` seconds pass,
        all data is buffered and an empty string (``''``) is returned.

        See :meth:`recvline_startswith` for more details.

        Examples:

            >>> t = tube()
            >>> t.recv_raw = lambda n: b'Foo\nBar\nBaz\nKaboodle\n'
            >>> t.recvline_endswith(b'r')
            b'Bar'
            >>> t.recvline_endswith((b'a',b'b',b'c',b'd',b'e'), True)
            b'Kaboodle\n'
            >>> t.recvline_endswith(b'oodle')
            b'Kaboodle'
        """
        ...

    def recvline_endswithS(self, *a, **kw):
        r"""
        Same as :meth:`recvline_endswith`, but returns a str, decoding the result using `context.encoding`. (note that the binary versions are way faster)
        """
        ...

    def recvline_endswithb(self, *a, **kw):
        r"""
        Same as :meth:`recvline_endswith`, but returns a bytearray
        """
        ...

    def recvline_pred(self, pred, keepends=False, timeout=pwnlib.timeout.Timeout.default):
        r"""
        recvline_pred(pred, keepends=False) -> bytes

        Receive data until ``pred(line)`` returns a truthy value.
        Drop all other data.

        If the request is not satisfied before ``timeout`` seconds pass,
        all data is buffered and an empty string (``''``) is returned.

        Arguments:
            pred(callable): Function to call.  Returns the line for which
                this function returns :const:`True`.

        Examples:

            >>> t = tube()
            >>> t.recv_raw = lambda n: b"Foo\nBar\nBaz\n"
            >>> t.recvline_pred(lambda line: line == b"Bar\n")
            b'Bar'
            >>> t.recvline_pred(lambda line: line == b"Bar\n", keepends=True)
            b'Bar\n'
            >>> t.recvline_pred(lambda line: line == b'Nope!', timeout=0.1)
            b''
        """
        ...

    def recvline_regex(self, regex, exact=False, keepends=False, timeout=pwnlib.timeout.Timeout.default):
        r"""
        recvline_regex(regex, exact=False, keepends=False, timeout=default) -> bytes

        Wrapper around :func:`recvline_pred`, which will return when a regex
        matches a line.

        By default :func:`re.RegexObject.search` is used, but if `exact` is
        set to True, then :func:`re.RegexObject.match` will be used instead.

        If the request is not satisfied before ``timeout`` seconds pass,
        all data is buffered and an empty string (``''``) is returned.
        """
        ...

    def recvline_regexS(self, *a, **kw):
        r"""
        Same as :meth:`recvline_regex`, but returns a str, decoding the result using `context.encoding`. (note that the binary versions are way faster)
        """
        ...

    def recvline_regexb(self, *a, **kw):
        r"""
        Same as :meth:`recvline_regex`, but returns a bytearray
        """
        ...

    def recvline_startswith(self, delims, keepends=False, timeout=pwnlib.timeout.Timeout.default):
        r"""
        recvline_startswith(delims, keepends=False, timeout=default) -> bytes

        Keep receiving lines until one is found that starts with one of
        `delims`.  Returns the last line received.

        If the request is not satisfied before ``timeout`` seconds pass,
        all data is buffered and an empty string (``''``) is returned.

        Arguments:
            delims(str,tuple): List of strings to search for, or string of single characters
            keepends(bool): Return lines with newlines if :const:`True`
            timeout(int): Timeout, in seconds

        Returns:
            The first line received which starts with a delimiter in ``delims``.

        Examples:

            >>> t = tube()
            >>> t.recv_raw = lambda n: b"Hello\nWorld\nXylophone\n"
            >>> t.recvline_startswith((b'W',b'X',b'Y',b'Z'))
            b'World'
            >>> t.recvline_startswith((b'W',b'X',b'Y',b'Z'), True)
            b'Xylophone\n'
            >>> t.recvline_startswith(b'Wo')
            b'World'
        """
        ...

    def recvline_startswithS(self, *a, **kw):
        r"""
        Same as :meth:`recvline_startswith`, but returns a str, decoding the result using `context.encoding`. (note that the binary versions are way faster)
        """
        ...

    def recvline_startswithb(self, *a, **kw):
        r"""
        Same as :meth:`recvline_startswith`, but returns a bytearray
        """
        ...

    def recvlineb(self, *a, **kw):
        r"""
        Same as :meth:`recvline`, but returns a bytearray
        """
        ...

    def recvlines(self, numlines=1048576, keepends=False, timeout=pwnlib.timeout.Timeout.default):
        r"""
        recvlines(numlines, keepends=False, timeout=default) -> list of bytes objects

        Receive up to ``numlines`` lines.

        A "line" is any sequence of bytes terminated by the byte sequence
        set by :attr:`newline`, which defaults to ``'\n'``.

        If the request is not satisfied before ``timeout`` seconds pass,
        all data is buffered and an empty string (``''``) is returned.

        Arguments:
            numlines(int): Maximum number of lines to receive
            keepends(bool): Keep newlines at the end of each line (:const:`False`).
            timeout(int): Maximum timeout

        Raises:
            exceptions.EOFError: The connection closed before the request could be satisfied

        Returns:
            A string containing bytes received from the socket,
            or ``''`` if a timeout occurred while waiting.

        Examples:

            >>> t = tube()
            >>> t.recv_raw = lambda n: b'\n'
            >>> t.recvlines(3)
            [b'', b'', b'']
            >>> t.recv_raw = lambda n: b'Foo\nBar\nBaz\n'
            >>> t.recvlines(3)
            [b'Foo', b'Bar', b'Baz']
            >>> t.recvlines(3, True)
            [b'Foo\n', b'Bar\n', b'Baz\n']
        """
        ...

    def recvlinesS(self, numlines=1048576, keepends=False, timeout=pwnlib.timeout.Timeout.default):
        r"""
        recvlinesS(numlines, keepends=False, timeout=default) -> str list

        This function is identical to :meth:`recvlines`, but decodes
        the received bytes into string using :func:`context.encoding`.
        You should use :meth:`recvlines` whenever possible for better performance.

        Examples:

            >>> t = tube()
            >>> t.recv_raw = lambda n: b'\n'
            >>> t.recvlinesS(3)
            ['', '', '']
            >>> t.recv_raw = lambda n: b'Foo\nBar\nBaz\n'
            >>> t.recvlinesS(3)
            ['Foo', 'Bar', 'Baz']
        """
        ...

    def recvlinesb(self, numlines=1048576, keepends=False, timeout=pwnlib.timeout.Timeout.default):
        r"""
        recvlinesb(numlines, keepends=False, timeout=default) -> bytearray list

        This function is identical to :meth:`recvlines`, but returns a bytearray.

        Examples:

            >>> t = tube()
            >>> t.recv_raw = lambda n: b'\n'
            >>> t.recvlinesb(3)
            [bytearray(b''), bytearray(b''), bytearray(b'')]
            >>> t.recv_raw = lambda n: b'Foo\nBar\nBaz\n'
            >>> t.recvlinesb(3)
            [bytearray(b'Foo'), bytearray(b'Bar'), bytearray(b'Baz')]
        """
        ...

    def recvn(self, numb, timeout=pwnlib.timeout.Timeout.default):
        r"""
        recvn(numb, timeout = default) -> str

        Receives exactly `n` bytes.

        If the request is not satisfied before ``timeout`` seconds pass,
        all data is buffered and an empty string (``''``) is returned.

        Raises:
            exceptions.EOFError: The connection closed before the request could be satisfied

        Returns:
            A string containing bytes received from the socket,
            or ``''`` if a timeout occurred while waiting.

        Examples:

            >>> t = tube()
            >>> data = b'hello world'
            >>> t.recv_raw = lambda *a: data
            >>> t.recvn(len(data)) == data
            True
            >>> t.recvn(len(data)+1) == data + data[:1]
            True
            >>> t.recv_raw = lambda *a: None
            >>> # The remaining data is buffered
            >>> t.recv() == data[1:]
            True
            >>> t.recv_raw = lambda *a: time.sleep(0.01) or b'a'
            >>> t.recvn(10, timeout=0.05)
            b''
            >>> t.recvn(10, timeout=0.06) # doctest: +ELLIPSIS
            b'aaaaaa...'
        """
        ...

    def recvnS(self, *a, **kw):
        r"""
        Same as :meth:`recvn`, but returns a str, decoding the result using `context.encoding`. (note that the binary versions are way faster)
        """
        ...

    def recvnb(self, *a, **kw):
        r"""
        Same as :meth:`recvn`, but returns a bytearray
        """
        ...

    def recvpred(self, pred, timeout=pwnlib.timeout.Timeout.default):
        r"""
        recvpred(pred, timeout = default) -> bytes

        Receives one byte at a time from the tube, until ``pred(all_bytes)``
        evaluates to True.

        If the request is not satisfied before ``timeout`` seconds pass,
        all data is buffered and an empty string (``''``) is returned.

        Arguments:
            pred(callable): Function to call, with the currently-accumulated data.
            timeout(int): Timeout for the operation

        Raises:
            exceptions.EOFError: The connection is closed

        Returns:
            A bytes object containing bytes received from the socket,
            or ``''`` if a timeout occurred while waiting.
        """
        ...

    def recvpredS(self, *a, **kw):
        r"""
        Same as :meth:`recvpred`, but returns a str, decoding the result using `context.encoding`. (note that the binary versions are way faster)
        """
        ...

    def recvpredb(self, *a, **kw):
        r"""
        Same as :meth:`recvpred`, but returns a bytearray
        """
        ...

    def recvregex(self, regex, exact=False, timeout=pwnlib.timeout.Timeout.default):
        r"""
        recvregex(regex, exact=False, timeout=default) -> bytes

        Wrapper around :func:`recvpred`, which will return when a regex
        matches the string in the buffer.

        By default :func:`re.RegexObject.search` is used, but if `exact` is
        set to True, then :func:`re.RegexObject.match` will be used instead.

        If the request is not satisfied before ``timeout`` seconds pass,
        all data is buffered and an empty string (``''``) is returned.
        """
        ...

    def recvregexS(self, *a, **kw):
        r"""
        Same as :meth:`recvregex`, but returns a str, decoding the result using `context.encoding`. (note that the binary versions are way faster)
        """
        ...

    def recvregexb(self, *a, **kw):
        r"""
        Same as :meth:`recvregex`, but returns a bytearray
        """
        ...

    def recvrepeat(self, timeout=pwnlib.timeout.Timeout.default):
        r"""
        recvrepeat(timeout=default) -> bytes

        Receives data until a timeout or EOF is reached.

        Examples:

            >>> data = [
            ... b'd',
            ... b'', # simulate timeout
            ... b'c',
            ... b'b',
            ... b'a',
            ... ]
            >>> def delayrecv(n, data=data):
            ...     return data.pop()
            >>> t = tube()
            >>> t.recv_raw = delayrecv
            >>> t.recvrepeat(0.2)
            b'abc'
            >>> t.recv()
            b'd'
        """
        ...

    def recvrepeatS(self, *a, **kw):
        r"""
        Same as :meth:`recvrepeat`, but returns a str, decoding the result using `context.encoding`. (note that the binary versions are way faster)
        """
        ...

    def recvrepeatb(self, *a, **kw):
        r"""
        Same as :meth:`recvrepeat`, but returns a bytearray
        """
        ...

    def recvuntil(self, delims, drop=False, timeout=pwnlib.timeout.Timeout.default):
        r"""
        recvuntil(delims, drop=False, timeout=default) -> bytes

        Receive data until one of `delims` is encountered.

        If the request is not satisfied before ``timeout`` seconds pass,
        all data is buffered and an empty string (``''``) is returned.

        arguments:
            delims(bytes,tuple): Byte-string of delimiters characters, or list of delimiter byte-strings.
            drop(bool): Drop the ending.  If :const:`True` it is removed from the end of the return value.

        Raises:
            exceptions.EOFError: The connection closed before the request could be satisfied

        Returns:
            A string containing bytes received from the socket,
            or ``''`` if a timeout occurred while waiting.

        Examples:

            >>> t = tube()
            >>> t.recv_raw = lambda n: b"Hello World!"
            >>> t.recvuntil(b' ')
            b'Hello '
            >>> _=t.clean(0)
            >>> # Matches on 'o' in 'Hello'
            >>> t.recvuntil((b' ',b'W',b'o',b'r'))
            b'Hello'
            >>> _=t.clean(0)
            >>> # Matches expressly full string
            >>> t.recvuntil(b' Wor')
            b'Hello Wor'
            >>> _=t.clean(0)
            >>> # Matches on full string, drops match
            >>> t.recvuntil(b' Wor', drop=True)
            b'Hello'

            >>> # Try with regex special characters
            >>> t = tube()
            >>> t.recv_raw = lambda n: b"Hello|World"
            >>> t.recvuntil(b'|', drop=True)
            b'Hello'
        """
        ...

    def recvuntilS(self, *a, **kw):
        r"""
        Same as :meth:`recvuntil`, but returns a str, decoding the result using `context.encoding`. (note that the binary versions are way faster)
        """
        ...

    def recvuntilb(self, *a, **kw):
        r"""
        Same as :meth:`recvuntil`, but returns a bytearray
        """
        ...

    def removeHandler(self, handler):
        r"""
        removeHandler(handler)

        Remove the specified handler from the underlying logger.
        """
        ...

    def send(self, data):
        r"""
        send(data)

        Sends data.

        If log level ``DEBUG`` is enabled, also prints out the data
        received.

        If it is not possible to send anymore because of a closed
        connection, it raises ``exceptions.EOFError``

        Examples:

            >>> def p(x): print(repr(x))
            >>> t = tube()
            >>> t.send_raw = p
            >>> t.send(b'hello')
            b'hello'
        """
        ...

    def send_raw(self, data):
        r"""
        send_raw(data)

        Should not be called directly. Sends data to the tube.

        Should return ``exceptions.EOFError``, if it is unable to send any
        more, because of a close tube.
        """
        ...

    def sendafter(self, delim, data, timeout=pwnlib.timeout.Timeout.default):
        r"""
        sendafter(delim, data, timeout = default) -> str

        A combination of ``recvuntil(delim, timeout=timeout)`` and ``send(data)``.
        """
        ...

    def sendline(self, line=b''):
        r"""
        sendline(data)

        Shorthand for ``t.send(data + t.newline)``.

        Examples:

            >>> def p(x): print(repr(x))
            >>> t = tube()
            >>> t.send_raw = p
            >>> t.sendline(b'hello')
            b'hello\n'
            >>> t.newline = b'\r\n'
            >>> t.sendline(b'hello')
            b'hello\r\n'
        """
        ...

    def sendlineafter(self, delim, data, timeout=pwnlib.timeout.Timeout.default):
        r"""
        sendlineafter(delim, data, timeout = default) -> str

        A combination of ``recvuntil(delim, timeout=timeout)`` and ``sendline(data)``.
        """
        ...

    def sendlines(self, lines=[]):

        ...

    def sendlinethen(self, delim, data, timeout=pwnlib.timeout.Timeout.default):
        r"""
        sendlinethen(delim, data, timeout = default) -> str

        A combination of ``sendline(data)`` and ``recvuntil(delim, timeout=timeout)``.
        """
        ...

    def sendthen(self, delim, data, timeout=pwnlib.timeout.Timeout.default):
        r"""
        sendthen(delim, data, timeout = default) -> str

        A combination of ``send(data)`` and ``recvuntil(delim, timeout=timeout)``.
        """
        ...

    def setLevel(self, level):
        r"""
        setLevel(level)

        Set the logging level for the underlying logger.
        """
        ...

    def settimeout(self, timeout):
        r"""
        settimeout(timeout)

        Set the timeout for receiving operations. If the string "default"
        is given, then :data:`context.timeout` will be used. If None is given,
        then there will be no timeout.

        Examples:

            >>> t = tube()
            >>> t.settimeout_raw = lambda t: None
            >>> t.settimeout(3)
            >>> t.timeout == 3
            True
        """
        ...

    def settimeout_raw(self, timeout):
        r"""
        settimeout_raw(timeout)

        Should not be called directly. Sets the timeout for
        the tube.
        """
        ...

    def shutdown(self, direction='send'):
        r"""
        shutdown(direction = "send")

        Closes the tube for futher reading or writing depending on `direction`.

        Arguments:
          direction(str): Which direction to close; "in", "read" or "recv"
            closes the tube in the ingoing direction, "out", "write" or "send"
            closes it in the outgoing direction.

        Returns:
          :const:`None`

        Examples:

            >>> def p(x): print(x)
            >>> t = tube()
            >>> t.shutdown_raw = p
            >>> _=list(map(t.shutdown, ('in', 'read', 'recv', 'out', 'write', 'send')))
            recv
            recv
            recv
            send
            send
            send
            >>> t.shutdown('bad_value') #doctest: +ELLIPSIS
            Traceback (most recent call last):
            ...
            KeyError: "direction must be in ['in', 'out', 'read', 'recv', 'send', 'write']"
        """
        ...

    def shutdown_raw(self, direction):
        r"""
        shutdown_raw(direction)

        Should not be called directly.  Closes the tube for further reading or
        writing.
        """
        ...

    def spawn_process(self, *args, **kwargs):
        r"""
        Spawns a new process having this tube as stdin, stdout and stderr.

        Takes the same arguments as :class:`subprocess.Popen`.
        """
        ...

    def stream(self, line_mode=True):
        r"""
        stream()

        Receive data until the tube exits, and print it to stdout.

        Similar to :func:`interactive`, except that no input is sent.

        Similar to ``print(tube.recvall())`` except that data is printed
        as it is received, rather than after all data is received.

        Arguments:
            line_mode(bool): Whether to receive line-by-line or raw data.

        Returns:
            All data printed.
        """
        ...

    def success(self, message, *args, **kwargs):
        r"""
        success(message, *args, **kwargs)

        Logs a success message.
        """
        ...

    def timeout_change(self):
        r"""
        Informs the raw layer of the tube that the timeout has changed.

        Should not be called directly.

        Inherited from :class:`Timeout`.
        """
        ...

    def u16(self, *a, **kw):

        ...

    def u32(self, *a, **kw):

        ...

    def u64(self, *a, **kw):

        ...

    def u8(self, *a, **kw):

        ...

    def unpack(self, *a, **kw):

        ...

    def unread(self, *a, **kw):
        r"""
        Alias for :meth:`unrecv`
        """
        ...

    def unrecv(self, data):
        r"""
        unrecv(data)

        Puts the specified data back at the beginning of the receive
        buffer.

        Examples:

            >>> t = tube()
            >>> t.recv_raw = lambda n: b'hello'
            >>> t.recv()
            b'hello'
            >>> t.recv()
            b'hello'
            >>> t.unrecv(b'world')
            >>> t.recv()
            b'world'
            >>> t.recv()
            b'hello'
        """
        ...

    def wait(self, timeout=pwnlib.timeout.Timeout.default):
        r"""
        Waits until the tube is closed.
        """
        ...

    def wait_for_close(self, timeout=pwnlib.timeout.Timeout.default):
        r"""
        Waits until the tube is closed.
        """
        ...

    def waitfor(self, *args, **kwargs):
        r"""
        Alias for :meth:`progress`.
        """
        ...

    def warn(self, *args, **kwargs):
        r"""
        Alias for :meth:`warning`.
        """
        ...

    def warn_once(self, *args, **kwargs):
        r"""
        Alias for :meth:`warning_once`.
        """
        ...

    def warning(self, message, *args, **kwargs):
        r"""
        warning(message, *args, **kwargs)

        Logs a warning message.
        """
        ...

    def warning_once(self, message, *args, **kwargs):
        r"""
        warning_once(message, *args, **kwargs)

        Logs a warning message.  The same message is never printed again.
        """
        ...

    def write(self, *a, **kw):
        r"""
        Alias for :meth:`send`
        """
        ...

    def write_raw(self, *a, **kw):
        r"""
        Alias for :meth:`send_raw`
        """
        ...

    def writeafter(self, *a, **kw):
        r"""
        Alias for :meth:`sendafter`
        """
        ...

    def writeline(self, *a, **kw):
        r"""
        Alias for :meth:`sendline`
        """
        ...

    def writelineafter(self, *a, **kw):
        r"""
        Alias for :meth:`sendlineafter`
        """
        ...

    def writelines(self, *a, **kw):
        r"""
        Alias for :meth:`sendlines`
        """
        ...

    def writelinethen(self, *a, **kw):
        r"""
        Alias for :meth:`sendlinethen`
        """
        ...

    def writethen(self, *a, **kw):
        r"""
        Alias for :meth:`sendthen`
        """
        ...

class tcp (pwnlib.tubes.remote.remote):
    r"""
    Creates a TCP or UDP-connection to a remote host. It supports
    both IPv4 and IPv6.

    The returned object supports all the methods from
    :class:`pwnlib.tubes.sock` and :class:`pwnlib.tubes.tube`.

    Arguments:
        host(str): The host to connect to.
        port(int): The port to connect to.
        fam: The string "any", "ipv4" or "ipv6" or an integer to pass to :func:`socket.getaddrinfo`.
        typ: The string "tcp" or "udp" or an integer to pass to :func:`socket.getaddrinfo`.
        timeout: A positive number, None or the string "default".
        ssl(bool): Wrap the socket with SSL
        ssl_context(ssl.SSLContext): Specify SSLContext used to wrap the socket.
        sni: Set 'server_hostname' in ssl_args based on the host parameter.
        sock(socket.socket): Socket to inherit, rather than connecting
        ssl_args(dict): Pass ssl.wrap_socket named arguments in a dictionary.

    Examples:

        >>> r = remote('google.com', 443, ssl=True)
        >>> r.send(b'GET /\r\n\r\n')
        >>> r.recvn(4)
        b'HTTP'

        If a connection cannot be made, an exception is raised.

        >>> r = remote('127.0.0.1', 1)
        Traceback (most recent call last):
        ...
        PwnlibException: Could not connect to 127.0.0.1 on port 1

        You can also use :meth:`.remote.fromsocket` to wrap an existing socket.

        >>> import socket
        >>> s = socket.socket()
        >>> s.connect(('google.com', 80))
        >>> s.send(b'GET /' + b'\r\n'*2)
        9
        >>> r = remote.fromsocket(s)
        >>> r.recvn(4)
        b'HTTP'
    """
    def __enter__(self):
        r"""
        Permit use of 'with' to control scoping and closing sessions.

        Examples:

            >>> t = tube()
            >>> def p(x): print(x)
            >>> t.close = lambda: p("Closed!")
            >>> with t: pass
            Closed!
        """
        ...

    def __exit__(self, type, value, traceback):
        r"""
        Handles closing for 'with' statement

        See :meth:`__enter__`
        """
        ...

    def __init__(self, host, port, *a, **kw):
        r"""
        Initialize self.  See help(type(self)) for accurate signature.
        """
        ...

    def __lshift__(self, other):
        r"""
        Shorthand for connecting multiple tubes.

        See :meth:`connect_input` for more information.

        Examples:

            The following are equivalent ::

                tube_a >> tube.b
                tube_a.connect_input(tube_b)

            This is useful when chaining multiple tubes ::

                tube_a >> tube_b >> tube_a
                tube_a.connect_input(tube_b)
                tube_b.connect_input(tube_a)
        """
        ...

    def __ne__(self, other):
        r"""
        Shorthand for connecting tubes to eachother.

        The following are equivalent ::

            a >> b >> a
            a <> b

        See :meth:`connect_input` for more information.
        """
        ...

    def __rshift__(self, other):
        r"""
        Inverse of the ``<<`` operator.  See :meth:`__lshift__`.

        See :meth:`connect_input` for more information.
        """
        ...

    def _close_msg(self):

        ...

    def _connect(self, fam, typ):

        ...

    def _fillbuffer(self, timeout=pwnlib.timeout.Timeout.default):
        r"""
        _fillbuffer(timeout = default)

        Fills the internal buffer from the pipe, by calling
        :meth:`recv_raw` exactly once.

        Returns:

            The bytes of data received, or ``''`` if no data was received.

        Examples:

            >>> t = tube()
            >>> t.recv_raw = lambda *a: b'abc'
            >>> len(t.buffer)
            0
            >>> t._fillbuffer()
            b'abc'
            >>> len(t.buffer)
            3
        """
        ...

    def _get_timeout_seconds(self, value):

        ...

    def _getlevel(self, levelString):

        ...

    def _log(self, level, msg, args, kwargs, msgtype, progress=None):

        ...

    def _read(self, *a, **kw):
        r"""
        Alias for :meth:`_recv`
        """
        ...

    def _recv(self, numb=None, timeout=pwnlib.timeout.Timeout.default):
        r"""
        _recv(numb = 4096, timeout = default) -> str

        Receives one chunk of from the internal buffer or from the OS if the
        buffer is empty.
        """
        ...

    def addHandler(self, handler):
        r"""
        addHandler(handler)

        Add the specified handler to the underlying logger.
        """
        ...

    def can_read(self, *a, **kw):
        r"""
        Alias for :meth:`can_recv`
        """
        ...

    def can_read_raw(self, *a, **kw):
        r"""
        Alias for :meth:`can_recv_raw`
        """
        ...

    def can_recv(self, timeout=0):
        r"""
        can_recv(timeout = 0) -> bool

        Returns True, if there is data available within `timeout` seconds.

        Examples:

            >>> import time
            >>> t = tube()
            >>> t.can_recv_raw = lambda *a: False
            >>> t.can_recv()
            False
            >>> _=t.unrecv(b'data')
            >>> t.can_recv()
            True
            >>> _=t.recv()
            >>> t.can_recv()
            False
        """
        ...

    def can_recv_raw(self, timeout):
        r"""
        Tests:

            >>> l = listen()
            >>> r = remote('localhost', l.lport)
            >>> r.can_recv_raw(timeout=0)
            False
            >>> l.send(b'a')
            >>> r.can_recv_raw(timeout=1)
            True
            >>> r.recv()
            b'a'
            >>> r.can_recv_raw(timeout=0)
            False
            >>> l.close()
            >>> r.can_recv_raw(timeout=1)
            False
            >>> r.closed['recv']
            True
        """
        ...

    def clean(self, timeout=0.05):
        r"""
        clean(timeout = 0.05)

        Removes all the buffered data from a tube by calling
        :meth:`pwnlib.tubes.tube.tube.recv` with a low timeout until it fails.

        If ``timeout`` is zero, only cached data will be cleared.

        Note: If timeout is set to zero, the underlying network is
        not actually polled; only the internal buffer is cleared.

        Returns:

            All data received

        Examples:

            >>> t = tube()
            >>> t.unrecv(b'clean me up')
            >>> t.clean(0)
            b'clean me up'
            >>> len(t.buffer)
            0
        """
        ...

    def clean_and_log(self, timeout=0.05):
        r"""
        clean_and_log(timeout = 0.05)

        Works exactly as :meth:`pwnlib.tubes.tube.tube.clean`, but logs received
        data with :meth:`pwnlib.self.info`.

        Returns:

            All data received

        Examples:

            >>> def recv(n, data=[b'', b'hooray_data']):
            ...     while data: return data.pop()
            >>> t = tube()
            >>> t.recv_raw      = recv
            >>> t.connected_raw = lambda d: True
            >>> t.fileno        = lambda: 1234
            >>> with context.local(log_level='info'):
            ...     data = t.clean_and_log() #doctest: +ELLIPSIS
            [DEBUG] Received 0xb bytes:
                b'hooray_data'
            >>> data
            b'hooray_data'
            >>> context.clear()
        """
        ...

    def close(self):
        r"""
        close()

        Closes the tube.
        """
        ...

    def connect_both(self, other):
        r"""
        connect_both(other)

        Connects the both ends of this tube object with another tube object.
        """
        ...

    def connect_input(self, other):
        r"""
        connect_input(other)

        Connects the input of this tube to the output of another tube object.


        Examples:

            >>> def p(x): print(x.decode())
            >>> def recvone(n, data=[b'data']):
            ...     while data: return data.pop()
            ...     raise EOFError
            >>> a = tube()
            >>> b = tube()
            >>> a.recv_raw = recvone
            >>> b.send_raw = p
            >>> a.connected_raw = lambda d: True
            >>> b.connected_raw = lambda d: True
            >>> a.shutdown      = lambda d: True
            >>> b.shutdown      = lambda d: True
            >>> import time
            >>> _=(b.connect_input(a), time.sleep(0.1))
            data
        """
        ...

    def connect_output(self, other):
        r"""
        connect_output(other)

        Connects the output of this tube to the input of another tube object.

        Examples:

            >>> def p(x): print(repr(x))
            >>> def recvone(n, data=[b'data']):
            ...     while data: return data.pop()
            ...     raise EOFError
            >>> a = tube()
            >>> b = tube()
            >>> a.recv_raw = recvone
            >>> b.send_raw = p
            >>> a.connected_raw = lambda d: True
            >>> b.connected_raw = lambda d: True
            >>> a.shutdown      = lambda d: True
            >>> b.shutdown      = lambda d: True
            >>> _=(a.connect_output(b), time.sleep(0.1))
            b'data'
        """
        ...

    def connected(self, direction='any'):
        r"""
        connected(direction = 'any') -> bool

        Returns True if the tube is connected in the specified direction.

        Arguments:
          direction(str): Can be the string 'any', 'in', 'read', 'recv',
                          'out', 'write', 'send'.

        Doctest:

            >>> def p(x): print(x)
            >>> t = tube()
            >>> t.connected_raw = p
            >>> _=list(map(t.connected, ('any', 'in', 'read', 'recv', 'out', 'write', 'send')))
            any
            recv
            recv
            recv
            send
            send
            send
            >>> t.connected('bad_value') #doctest: +ELLIPSIS
            Traceback (most recent call last):
            ...
            KeyError: "direction must be in ['any', 'in', 'out', 'read', 'recv', 'send', 'write']"
        """
        ...

    def connected_raw(self, direction):
        r"""
        Tests:

            >>> l = listen()
            >>> r = remote('localhost', l.lport)
            >>> r.connected()
            True
            >>> l.close()
            >>> time.sleep(0.1) # Avoid race condition
            >>> r.connected()
            False
        """
        ...

    def countdown(self, timeout=pwnlib.timeout.Timeout.default):
        r"""
        Scoped timeout setter.  Sets the timeout within the scope,
        and restores it when leaving the scope.

        When accessing :attr:`timeout` within the scope, it will be
        calculated against the time when the scope was entered, in a
        countdown fashion.

        If :const:`None` is specified for ``timeout``, then the current
        timeout is used is made.  This allows :const:`None` to be specified
        as a default argument with less complexity.
        """
        ...

    def countdown_active(self):

        ...

    def critical(self, message, *args, **kwargs):
        r"""
        critical(message, *args, **kwargs)

        Logs a critical message.
        """
        ...

    def debug(self, message, *args, **kwargs):
        r"""
        debug(message, *args, **kwargs)

        Logs a debug message.
        """
        ...

    def error(self, message, *args, **kwargs):
        r"""
        error(message, *args, **kwargs)

        To be called outside an exception handler.

        Logs an error message, then raises a ``PwnlibException``.
        """
        ...

    def exception(self, message, *args, **kwargs):
        r"""
        exception(message, *args, **kwargs)

        To be called from an exception handler.

        Logs a error message, then re-raises the current exception.
        """
        ...

    def failure(self, message, *args, **kwargs):
        r"""
        failure(message, *args, **kwargs)

        Logs a failure message.
        """
        ...

    def fileno(self):
        r"""
        fileno() -> int

        Returns the file number used for reading.
        """
        ...

    def fit(self, *a, **kw):

        ...

    def flat(self, *a, **kw):

        ...

    def hexdump(self, message, *args, **kwargs):

        ...

    def indented(self, message, *args, **kwargs):
        r"""
        indented(message, *args, level = logging.INFO, **kwargs)

        Log a message but don't put a line prefix on it.

        Arguments:
            level(int): Alternate log level at which to set the indented
                        message.  Defaults to :const:`logging.INFO`.
        """
        ...

    def info(self, message, *args, **kwargs):
        r"""
        info(message, *args, **kwargs)

        Logs an info message.
        """
        ...

    def info_once(self, message, *args, **kwargs):
        r"""
        info_once(message, *args, **kwargs)

        Logs an info message.  The same message is never printed again.
        """
        ...

    def interactive(self, prompt='\x1b[1m\x1b[31m$\x1b[m '):
        r"""
        interactive(prompt = pwnlib.term.text.bold_red('$') + ' ')

        Does simultaneous reading and writing to the tube. In principle this just
        connects the tube to standard in and standard out, but in practice this
        is much more usable, since we are using :mod:`pwnlib.term` to print a
        floating prompt.

        Thus it only works in while in :data:`pwnlib.term.term_mode`.
        """
        ...

    def isEnabledFor(self, level):
        r"""
        isEnabledFor(level) -> bool

        See if the underlying logger is enabled for the specified level.
        """
        ...

    def local(self, timeout):
        r"""
        Scoped timeout setter.  Sets the timeout within the scope,
        and restores it when leaving the scope.
        """
        ...

    def log(self, level, message, *args, **kwargs):
        r"""
        log(level, message, *args, **kwargs)

        Logs a message with log level `level`.  The ``pwnlib`` formatter will
        use the default :mod:`logging` formater to format this message.
        """
        ...

    def p16(self, *a, **kw):

        ...

    def p32(self, *a, **kw):

        ...

    def p64(self, *a, **kw):

        ...

    def p8(self, *a, **kw):

        ...

    def pack(self, *a, **kw):

        ...

    def progress(self, message, status='', *args, **kwargs):
        r"""
        progress(message, status = '', *args, level = logging.INFO, **kwargs) -> Progress

        Creates a new progress logger which creates log records with log level
        `level`.

        Progress status can be updated using :meth:`Progress.status` and stopped
        using :meth:`Progress.success` or :meth:`Progress.failure`.

        If `term.term_mode` is enabled the progress logger will be animated.

        The progress manager also functions as a context manager.  Using context
        managers ensures that animations stop even if an exception is raised.

        .. code-block:: python

           with log.progress('Trying something...') as p:
               for i in range(10):
                   p.status("At %i" % i)
                   time.sleep(0.5)
               x = 1/0
        """
        ...

    def read(self, *a, **kw):
        r"""
        Alias for :meth:`recv`
        """
        ...

    def readS(self, *a, **kw):
        r"""
        Alias for :meth:`recvS`
        """
        ...

    def read_raw(self, *a, **kw):
        r"""
        Alias for :meth:`recv_raw`
        """
        ...

    def readall(self, *a, **kw):
        r"""
        Alias for :meth:`recvall`
        """
        ...

    def readallS(self, *a, **kw):
        r"""
        Alias for :meth:`recvallS`
        """
        ...

    def readallb(self, *a, **kw):
        r"""
        Alias for :meth:`recvallb`
        """
        ...

    def readb(self, *a, **kw):
        r"""
        Alias for :meth:`recvb`
        """
        ...

    def readline(self, *a, **kw):
        r"""
        Alias for :meth:`recvline`
        """
        ...

    def readlineS(self, *a, **kw):
        r"""
        Alias for :meth:`recvlineS`
        """
        ...

    def readline_contains(self, *a, **kw):
        r"""
        Alias for :meth:`recvline_contains`
        """
        ...

    def readline_containsS(self, *a, **kw):
        r"""
        Alias for :meth:`recvline_containsS`
        """
        ...

    def readline_containsb(self, *a, **kw):
        r"""
        Alias for :meth:`recvline_containsb`
        """
        ...

    def readline_endswith(self, *a, **kw):
        r"""
        Alias for :meth:`recvline_endswith`
        """
        ...

    def readline_endswithS(self, *a, **kw):
        r"""
        Alias for :meth:`recvline_endswithS`
        """
        ...

    def readline_endswithb(self, *a, **kw):
        r"""
        Alias for :meth:`recvline_endswithb`
        """
        ...

    def readline_pred(self, *a, **kw):
        r"""
        Alias for :meth:`recvline_pred`
        """
        ...

    def readline_regex(self, *a, **kw):
        r"""
        Alias for :meth:`recvline_regex`
        """
        ...

    def readline_regexS(self, *a, **kw):
        r"""
        Alias for :meth:`recvline_regexS`
        """
        ...

    def readline_regexb(self, *a, **kw):
        r"""
        Alias for :meth:`recvline_regexb`
        """
        ...

    def readline_startswith(self, *a, **kw):
        r"""
        Alias for :meth:`recvline_startswith`
        """
        ...

    def readline_startswithS(self, *a, **kw):
        r"""
        Alias for :meth:`recvline_startswithS`
        """
        ...

    def readline_startswithb(self, *a, **kw):
        r"""
        Alias for :meth:`recvline_startswithb`
        """
        ...

    def readlineb(self, *a, **kw):
        r"""
        Alias for :meth:`recvlineb`
        """
        ...

    def readlines(self, *a, **kw):
        r"""
        Alias for :meth:`recvlines`
        """
        ...

    def readlinesS(self, *a, **kw):
        r"""
        Alias for :meth:`recvlinesS`
        """
        ...

    def readlinesb(self, *a, **kw):
        r"""
        Alias for :meth:`recvlinesb`
        """
        ...

    def readn(self, *a, **kw):
        r"""
        Alias for :meth:`recvn`
        """
        ...

    def readnS(self, *a, **kw):
        r"""
        Alias for :meth:`recvnS`
        """
        ...

    def readnb(self, *a, **kw):
        r"""
        Alias for :meth:`recvnb`
        """
        ...

    def readpred(self, *a, **kw):
        r"""
        Alias for :meth:`recvpred`
        """
        ...

    def readpredS(self, *a, **kw):
        r"""
        Alias for :meth:`recvpredS`
        """
        ...

    def readpredb(self, *a, **kw):
        r"""
        Alias for :meth:`recvpredb`
        """
        ...

    def readregex(self, *a, **kw):
        r"""
        Alias for :meth:`recvregex`
        """
        ...

    def readregexS(self, *a, **kw):
        r"""
        Alias for :meth:`recvregexS`
        """
        ...

    def readregexb(self, *a, **kw):
        r"""
        Alias for :meth:`recvregexb`
        """
        ...

    def readrepeat(self, *a, **kw):
        r"""
        Alias for :meth:`recvrepeat`
        """
        ...

    def readrepeatS(self, *a, **kw):
        r"""
        Alias for :meth:`recvrepeatS`
        """
        ...

    def readrepeatb(self, *a, **kw):
        r"""
        Alias for :meth:`recvrepeatb`
        """
        ...

    def readuntil(self, *a, **kw):
        r"""
        Alias for :meth:`recvuntil`
        """
        ...

    def readuntilS(self, *a, **kw):
        r"""
        Alias for :meth:`recvuntilS`
        """
        ...

    def readuntilb(self, *a, **kw):
        r"""
        Alias for :meth:`recvuntilb`
        """
        ...

    def recv(self, numb=None, timeout=pwnlib.timeout.Timeout.default):
        r"""
        recv(numb = 4096, timeout = default) -> bytes

        Receives up to `numb` bytes of data from the tube, and returns
        as soon as any quantity of data is available.

        If the request is not satisfied before ``timeout`` seconds pass,
        all data is buffered and an empty string (``''``) is returned.

        Raises:
            exceptions.EOFError: The connection is closed

        Returns:
            A bytes object containing bytes received from the socket,
            or ``''`` if a timeout occurred while waiting.

        Examples:

            >>> t = tube()
            >>> # Fake a data source
            >>> t.recv_raw = lambda n: b'Hello, world'
            >>> t.recv() == b'Hello, world'
            True
            >>> t.unrecv(b'Woohoo')
            >>> t.recv() == b'Woohoo'
            True
            >>> with context.local(log_level='debug'):
            ...    _ = t.recv() # doctest: +ELLIPSIS
            [...] Received 0xc bytes:
                b'Hello, world'
        """
        ...

    def recvS(self, *a, **kw):
        r"""
        Same as :meth:`recv`, but returns a str, decoding the result using `context.encoding`. (note that the binary versions are way faster)
        """
        ...

    def recv_raw(self, numb, *a):
        r"""
        recv_raw(numb) -> str

        Should not be called directly. Receives data without using the buffer
        on the object.

        Unless there is a timeout or closed connection, this should always
        return data. In case of a timeout, it should return None, in case
        of a closed connection it should raise an ``exceptions.EOFError``.
        """
        ...

    def recvall(self, timeout=None):
        r"""
        recvall() -> str

        Receives data until the socket is closed.
        """
        ...

    def recvallS(self, *a, **kw):
        r"""
        Same as :meth:`recvall`, but returns a str, decoding the result using `context.encoding`. (note that the binary versions are way faster)
        """
        ...

    def recvallb(self, *a, **kw):
        r"""
        Same as :meth:`recvall`, but returns a bytearray
        """
        ...

    def recvb(self, *a, **kw):
        r"""
        Same as :meth:`recv`, but returns a bytearray
        """
        ...

    def recvline(self, keepends=True, timeout=pwnlib.timeout.Timeout.default):
        r"""
        recvline(keepends=True, timeout=default) -> bytes

        Receive a single line from the tube.

        A "line" is any sequence of bytes terminated by the byte sequence
        set in :attr:`newline`, which defaults to ``'\n'``.

        If the request is not satisfied before ``timeout`` seconds pass,
        all data is buffered and an empty string (``''``) is returned.

        Arguments:
            keepends(bool): Keep the line ending (:const:`True`).
            timeout(int): Timeout

        Return:
            All bytes received over the tube until the first
            newline ``'\n'`` is received.  Optionally retains
            the ending.

        Examples:

            >>> t = tube()
            >>> t.recv_raw = lambda n: b'Foo\nBar\r\nBaz\n'
            >>> t.recvline()
            b'Foo\n'
            >>> t.recvline()
            b'Bar\r\n'
            >>> t.recvline(keepends = False)
            b'Baz'
            >>> t.newline = b'\r\n'
            >>> t.recvline(keepends = False)
            b'Foo\nBar'
        """
        ...

    def recvlineS(self, *a, **kw):
        r"""
        Same as :meth:`recvline`, but returns a str, decoding the result using `context.encoding`. (note that the binary versions are way faster)
        """
        ...

    def recvline_contains(self, items, keepends=False, timeout=pwnlib.timeout.Timeout.default):
        r"""
        Receive lines until one line is found which contains at least
        one of `items`.

        Arguments:
            items(str,tuple): List of strings to search for, or a single string.
            keepends(bool): Return lines with newlines if :const:`True`
            timeout(int): Timeout, in seconds

        Examples:

            >>> t = tube()
            >>> t.recv_raw = lambda n: b"Hello\nWorld\nXylophone\n"
            >>> t.recvline_contains(b'r')
            b'World'
            >>> f = lambda n: b"cat dog bird\napple pear orange\nbicycle car train\n"
            >>> t = tube()
            >>> t.recv_raw = f
            >>> t.recvline_contains(b'pear')
            b'apple pear orange'
            >>> t = tube()
            >>> t.recv_raw = f
            >>> t.recvline_contains((b'car', b'train'))
            b'bicycle car train'
        """
        ...

    def recvline_containsS(self, *a, **kw):
        r"""
        Same as :meth:`recvline_contains`, but returns a str, decoding the result using `context.encoding`. (note that the binary versions are way faster)
        """
        ...

    def recvline_containsb(self, *a, **kw):
        r"""
        Same as :meth:`recvline_contains`, but returns a bytearray
        """
        ...

    def recvline_endswith(self, delims, keepends=False, timeout=pwnlib.timeout.Timeout.default):
        r"""
        recvline_endswith(delims, keepends=False, timeout=default) -> bytes

        Keep receiving lines until one is found that ends with one of
        `delims`.  Returns the last line received.

        If the request is not satisfied before ``timeout`` seconds pass,
        all data is buffered and an empty string (``''``) is returned.

        See :meth:`recvline_startswith` for more details.

        Examples:

            >>> t = tube()
            >>> t.recv_raw = lambda n: b'Foo\nBar\nBaz\nKaboodle\n'
            >>> t.recvline_endswith(b'r')
            b'Bar'
            >>> t.recvline_endswith((b'a',b'b',b'c',b'd',b'e'), True)
            b'Kaboodle\n'
            >>> t.recvline_endswith(b'oodle')
            b'Kaboodle'
        """
        ...

    def recvline_endswithS(self, *a, **kw):
        r"""
        Same as :meth:`recvline_endswith`, but returns a str, decoding the result using `context.encoding`. (note that the binary versions are way faster)
        """
        ...

    def recvline_endswithb(self, *a, **kw):
        r"""
        Same as :meth:`recvline_endswith`, but returns a bytearray
        """
        ...

    def recvline_pred(self, pred, keepends=False, timeout=pwnlib.timeout.Timeout.default):
        r"""
        recvline_pred(pred, keepends=False) -> bytes

        Receive data until ``pred(line)`` returns a truthy value.
        Drop all other data.

        If the request is not satisfied before ``timeout`` seconds pass,
        all data is buffered and an empty string (``''``) is returned.

        Arguments:
            pred(callable): Function to call.  Returns the line for which
                this function returns :const:`True`.

        Examples:

            >>> t = tube()
            >>> t.recv_raw = lambda n: b"Foo\nBar\nBaz\n"
            >>> t.recvline_pred(lambda line: line == b"Bar\n")
            b'Bar'
            >>> t.recvline_pred(lambda line: line == b"Bar\n", keepends=True)
            b'Bar\n'
            >>> t.recvline_pred(lambda line: line == b'Nope!', timeout=0.1)
            b''
        """
        ...

    def recvline_regex(self, regex, exact=False, keepends=False, timeout=pwnlib.timeout.Timeout.default):
        r"""
        recvline_regex(regex, exact=False, keepends=False, timeout=default) -> bytes

        Wrapper around :func:`recvline_pred`, which will return when a regex
        matches a line.

        By default :func:`re.RegexObject.search` is used, but if `exact` is
        set to True, then :func:`re.RegexObject.match` will be used instead.

        If the request is not satisfied before ``timeout`` seconds pass,
        all data is buffered and an empty string (``''``) is returned.
        """
        ...

    def recvline_regexS(self, *a, **kw):
        r"""
        Same as :meth:`recvline_regex`, but returns a str, decoding the result using `context.encoding`. (note that the binary versions are way faster)
        """
        ...

    def recvline_regexb(self, *a, **kw):
        r"""
        Same as :meth:`recvline_regex`, but returns a bytearray
        """
        ...

    def recvline_startswith(self, delims, keepends=False, timeout=pwnlib.timeout.Timeout.default):
        r"""
        recvline_startswith(delims, keepends=False, timeout=default) -> bytes

        Keep receiving lines until one is found that starts with one of
        `delims`.  Returns the last line received.

        If the request is not satisfied before ``timeout`` seconds pass,
        all data is buffered and an empty string (``''``) is returned.

        Arguments:
            delims(str,tuple): List of strings to search for, or string of single characters
            keepends(bool): Return lines with newlines if :const:`True`
            timeout(int): Timeout, in seconds

        Returns:
            The first line received which starts with a delimiter in ``delims``.

        Examples:

            >>> t = tube()
            >>> t.recv_raw = lambda n: b"Hello\nWorld\nXylophone\n"
            >>> t.recvline_startswith((b'W',b'X',b'Y',b'Z'))
            b'World'
            >>> t.recvline_startswith((b'W',b'X',b'Y',b'Z'), True)
            b'Xylophone\n'
            >>> t.recvline_startswith(b'Wo')
            b'World'
        """
        ...

    def recvline_startswithS(self, *a, **kw):
        r"""
        Same as :meth:`recvline_startswith`, but returns a str, decoding the result using `context.encoding`. (note that the binary versions are way faster)
        """
        ...

    def recvline_startswithb(self, *a, **kw):
        r"""
        Same as :meth:`recvline_startswith`, but returns a bytearray
        """
        ...

    def recvlineb(self, *a, **kw):
        r"""
        Same as :meth:`recvline`, but returns a bytearray
        """
        ...

    def recvlines(self, numlines=1048576, keepends=False, timeout=pwnlib.timeout.Timeout.default):
        r"""
        recvlines(numlines, keepends=False, timeout=default) -> list of bytes objects

        Receive up to ``numlines`` lines.

        A "line" is any sequence of bytes terminated by the byte sequence
        set by :attr:`newline`, which defaults to ``'\n'``.

        If the request is not satisfied before ``timeout`` seconds pass,
        all data is buffered and an empty string (``''``) is returned.

        Arguments:
            numlines(int): Maximum number of lines to receive
            keepends(bool): Keep newlines at the end of each line (:const:`False`).
            timeout(int): Maximum timeout

        Raises:
            exceptions.EOFError: The connection closed before the request could be satisfied

        Returns:
            A string containing bytes received from the socket,
            or ``''`` if a timeout occurred while waiting.

        Examples:

            >>> t = tube()
            >>> t.recv_raw = lambda n: b'\n'
            >>> t.recvlines(3)
            [b'', b'', b'']
            >>> t.recv_raw = lambda n: b'Foo\nBar\nBaz\n'
            >>> t.recvlines(3)
            [b'Foo', b'Bar', b'Baz']
            >>> t.recvlines(3, True)
            [b'Foo\n', b'Bar\n', b'Baz\n']
        """
        ...

    def recvlinesS(self, numlines=1048576, keepends=False, timeout=pwnlib.timeout.Timeout.default):
        r"""
        recvlinesS(numlines, keepends=False, timeout=default) -> str list

        This function is identical to :meth:`recvlines`, but decodes
        the received bytes into string using :func:`context.encoding`.
        You should use :meth:`recvlines` whenever possible for better performance.

        Examples:

            >>> t = tube()
            >>> t.recv_raw = lambda n: b'\n'
            >>> t.recvlinesS(3)
            ['', '', '']
            >>> t.recv_raw = lambda n: b'Foo\nBar\nBaz\n'
            >>> t.recvlinesS(3)
            ['Foo', 'Bar', 'Baz']
        """
        ...

    def recvlinesb(self, numlines=1048576, keepends=False, timeout=pwnlib.timeout.Timeout.default):
        r"""
        recvlinesb(numlines, keepends=False, timeout=default) -> bytearray list

        This function is identical to :meth:`recvlines`, but returns a bytearray.

        Examples:

            >>> t = tube()
            >>> t.recv_raw = lambda n: b'\n'
            >>> t.recvlinesb(3)
            [bytearray(b''), bytearray(b''), bytearray(b'')]
            >>> t.recv_raw = lambda n: b'Foo\nBar\nBaz\n'
            >>> t.recvlinesb(3)
            [bytearray(b'Foo'), bytearray(b'Bar'), bytearray(b'Baz')]
        """
        ...

    def recvn(self, numb, timeout=pwnlib.timeout.Timeout.default):
        r"""
        recvn(numb, timeout = default) -> str

        Receives exactly `n` bytes.

        If the request is not satisfied before ``timeout`` seconds pass,
        all data is buffered and an empty string (``''``) is returned.

        Raises:
            exceptions.EOFError: The connection closed before the request could be satisfied

        Returns:
            A string containing bytes received from the socket,
            or ``''`` if a timeout occurred while waiting.

        Examples:

            >>> t = tube()
            >>> data = b'hello world'
            >>> t.recv_raw = lambda *a: data
            >>> t.recvn(len(data)) == data
            True
            >>> t.recvn(len(data)+1) == data + data[:1]
            True
            >>> t.recv_raw = lambda *a: None
            >>> # The remaining data is buffered
            >>> t.recv() == data[1:]
            True
            >>> t.recv_raw = lambda *a: time.sleep(0.01) or b'a'
            >>> t.recvn(10, timeout=0.05)
            b''
            >>> t.recvn(10, timeout=0.06) # doctest: +ELLIPSIS
            b'aaaaaa...'
        """
        ...

    def recvnS(self, *a, **kw):
        r"""
        Same as :meth:`recvn`, but returns a str, decoding the result using `context.encoding`. (note that the binary versions are way faster)
        """
        ...

    def recvnb(self, *a, **kw):
        r"""
        Same as :meth:`recvn`, but returns a bytearray
        """
        ...

    def recvpred(self, pred, timeout=pwnlib.timeout.Timeout.default):
        r"""
        recvpred(pred, timeout = default) -> bytes

        Receives one byte at a time from the tube, until ``pred(all_bytes)``
        evaluates to True.

        If the request is not satisfied before ``timeout`` seconds pass,
        all data is buffered and an empty string (``''``) is returned.

        Arguments:
            pred(callable): Function to call, with the currently-accumulated data.
            timeout(int): Timeout for the operation

        Raises:
            exceptions.EOFError: The connection is closed

        Returns:
            A bytes object containing bytes received from the socket,
            or ``''`` if a timeout occurred while waiting.
        """
        ...

    def recvpredS(self, *a, **kw):
        r"""
        Same as :meth:`recvpred`, but returns a str, decoding the result using `context.encoding`. (note that the binary versions are way faster)
        """
        ...

    def recvpredb(self, *a, **kw):
        r"""
        Same as :meth:`recvpred`, but returns a bytearray
        """
        ...

    def recvregex(self, regex, exact=False, timeout=pwnlib.timeout.Timeout.default):
        r"""
        recvregex(regex, exact=False, timeout=default) -> bytes

        Wrapper around :func:`recvpred`, which will return when a regex
        matches the string in the buffer.

        By default :func:`re.RegexObject.search` is used, but if `exact` is
        set to True, then :func:`re.RegexObject.match` will be used instead.

        If the request is not satisfied before ``timeout`` seconds pass,
        all data is buffered and an empty string (``''``) is returned.
        """
        ...

    def recvregexS(self, *a, **kw):
        r"""
        Same as :meth:`recvregex`, but returns a str, decoding the result using `context.encoding`. (note that the binary versions are way faster)
        """
        ...

    def recvregexb(self, *a, **kw):
        r"""
        Same as :meth:`recvregex`, but returns a bytearray
        """
        ...

    def recvrepeat(self, timeout=pwnlib.timeout.Timeout.default):
        r"""
        recvrepeat(timeout=default) -> bytes

        Receives data until a timeout or EOF is reached.

        Examples:

            >>> data = [
            ... b'd',
            ... b'', # simulate timeout
            ... b'c',
            ... b'b',
            ... b'a',
            ... ]
            >>> def delayrecv(n, data=data):
            ...     return data.pop()
            >>> t = tube()
            >>> t.recv_raw = delayrecv
            >>> t.recvrepeat(0.2)
            b'abc'
            >>> t.recv()
            b'd'
        """
        ...

    def recvrepeatS(self, *a, **kw):
        r"""
        Same as :meth:`recvrepeat`, but returns a str, decoding the result using `context.encoding`. (note that the binary versions are way faster)
        """
        ...

    def recvrepeatb(self, *a, **kw):
        r"""
        Same as :meth:`recvrepeat`, but returns a bytearray
        """
        ...

    def recvuntil(self, delims, drop=False, timeout=pwnlib.timeout.Timeout.default):
        r"""
        recvuntil(delims, drop=False, timeout=default) -> bytes

        Receive data until one of `delims` is encountered.

        If the request is not satisfied before ``timeout`` seconds pass,
        all data is buffered and an empty string (``''``) is returned.

        arguments:
            delims(bytes,tuple): Byte-string of delimiters characters, or list of delimiter byte-strings.
            drop(bool): Drop the ending.  If :const:`True` it is removed from the end of the return value.

        Raises:
            exceptions.EOFError: The connection closed before the request could be satisfied

        Returns:
            A string containing bytes received from the socket,
            or ``''`` if a timeout occurred while waiting.

        Examples:

            >>> t = tube()
            >>> t.recv_raw = lambda n: b"Hello World!"
            >>> t.recvuntil(b' ')
            b'Hello '
            >>> _=t.clean(0)
            >>> # Matches on 'o' in 'Hello'
            >>> t.recvuntil((b' ',b'W',b'o',b'r'))
            b'Hello'
            >>> _=t.clean(0)
            >>> # Matches expressly full string
            >>> t.recvuntil(b' Wor')
            b'Hello Wor'
            >>> _=t.clean(0)
            >>> # Matches on full string, drops match
            >>> t.recvuntil(b' Wor', drop=True)
            b'Hello'

            >>> # Try with regex special characters
            >>> t = tube()
            >>> t.recv_raw = lambda n: b"Hello|World"
            >>> t.recvuntil(b'|', drop=True)
            b'Hello'
        """
        ...

    def recvuntilS(self, *a, **kw):
        r"""
        Same as :meth:`recvuntil`, but returns a str, decoding the result using `context.encoding`. (note that the binary versions are way faster)
        """
        ...

    def recvuntilb(self, *a, **kw):
        r"""
        Same as :meth:`recvuntil`, but returns a bytearray
        """
        ...

    def removeHandler(self, handler):
        r"""
        removeHandler(handler)

        Remove the specified handler from the underlying logger.
        """
        ...

    def send(self, data):
        r"""
        send(data)

        Sends data.

        If log level ``DEBUG`` is enabled, also prints out the data
        received.

        If it is not possible to send anymore because of a closed
        connection, it raises ``exceptions.EOFError``

        Examples:

            >>> def p(x): print(repr(x))
            >>> t = tube()
            >>> t.send_raw = p
            >>> t.send(b'hello')
            b'hello'
        """
        ...

    def send_raw(self, data):
        r"""
        send_raw(data)

        Should not be called directly. Sends data to the tube.

        Should return ``exceptions.EOFError``, if it is unable to send any
        more, because of a close tube.
        """
        ...

    def sendafter(self, delim, data, timeout=pwnlib.timeout.Timeout.default):
        r"""
        sendafter(delim, data, timeout = default) -> str

        A combination of ``recvuntil(delim, timeout=timeout)`` and ``send(data)``.
        """
        ...

    def sendline(self, line=b''):
        r"""
        sendline(data)

        Shorthand for ``t.send(data + t.newline)``.

        Examples:

            >>> def p(x): print(repr(x))
            >>> t = tube()
            >>> t.send_raw = p
            >>> t.sendline(b'hello')
            b'hello\n'
            >>> t.newline = b'\r\n'
            >>> t.sendline(b'hello')
            b'hello\r\n'
        """
        ...

    def sendlineafter(self, delim, data, timeout=pwnlib.timeout.Timeout.default):
        r"""
        sendlineafter(delim, data, timeout = default) -> str

        A combination of ``recvuntil(delim, timeout=timeout)`` and ``sendline(data)``.
        """
        ...

    def sendlines(self, lines=[]):

        ...

    def sendlinethen(self, delim, data, timeout=pwnlib.timeout.Timeout.default):
        r"""
        sendlinethen(delim, data, timeout = default) -> str

        A combination of ``sendline(data)`` and ``recvuntil(delim, timeout=timeout)``.
        """
        ...

    def sendthen(self, delim, data, timeout=pwnlib.timeout.Timeout.default):
        r"""
        sendthen(delim, data, timeout = default) -> str

        A combination of ``send(data)`` and ``recvuntil(delim, timeout=timeout)``.
        """
        ...

    def setLevel(self, level):
        r"""
        setLevel(level)

        Set the logging level for the underlying logger.
        """
        ...

    def settimeout(self, timeout):
        r"""
        settimeout(timeout)

        Set the timeout for receiving operations. If the string "default"
        is given, then :data:`context.timeout` will be used. If None is given,
        then there will be no timeout.

        Examples:

            >>> t = tube()
            >>> t.settimeout_raw = lambda t: None
            >>> t.settimeout(3)
            >>> t.timeout == 3
            True
        """
        ...

    def settimeout_raw(self, timeout):
        r"""
        settimeout_raw(timeout)

        Should not be called directly. Sets the timeout for
        the tube.
        """
        ...

    def shutdown(self, direction='send'):
        r"""
        shutdown(direction = "send")

        Closes the tube for futher reading or writing depending on `direction`.

        Arguments:
          direction(str): Which direction to close; "in", "read" or "recv"
            closes the tube in the ingoing direction, "out", "write" or "send"
            closes it in the outgoing direction.

        Returns:
          :const:`None`

        Examples:

            >>> def p(x): print(x)
            >>> t = tube()
            >>> t.shutdown_raw = p
            >>> _=list(map(t.shutdown, ('in', 'read', 'recv', 'out', 'write', 'send')))
            recv
            recv
            recv
            send
            send
            send
            >>> t.shutdown('bad_value') #doctest: +ELLIPSIS
            Traceback (most recent call last):
            ...
            KeyError: "direction must be in ['in', 'out', 'read', 'recv', 'send', 'write']"
        """
        ...

    def shutdown_raw(self, direction):
        r"""
        shutdown_raw(direction)

        Should not be called directly.  Closes the tube for further reading or
        writing.
        """
        ...

    def spawn_process(self, *args, **kwargs):
        r"""
        Spawns a new process having this tube as stdin, stdout and stderr.

        Takes the same arguments as :class:`subprocess.Popen`.
        """
        ...

    def stream(self, line_mode=True):
        r"""
        stream()

        Receive data until the tube exits, and print it to stdout.

        Similar to :func:`interactive`, except that no input is sent.

        Similar to ``print(tube.recvall())`` except that data is printed
        as it is received, rather than after all data is received.

        Arguments:
            line_mode(bool): Whether to receive line-by-line or raw data.

        Returns:
            All data printed.
        """
        ...

    def success(self, message, *args, **kwargs):
        r"""
        success(message, *args, **kwargs)

        Logs a success message.
        """
        ...

    def timeout_change(self):
        r"""
        Informs the raw layer of the tube that the timeout has changed.

        Should not be called directly.

        Inherited from :class:`Timeout`.
        """
        ...

    def u16(self, *a, **kw):

        ...

    def u32(self, *a, **kw):

        ...

    def u64(self, *a, **kw):

        ...

    def u8(self, *a, **kw):

        ...

    def unpack(self, *a, **kw):

        ...

    def unread(self, *a, **kw):
        r"""
        Alias for :meth:`unrecv`
        """
        ...

    def unrecv(self, data):
        r"""
        unrecv(data)

        Puts the specified data back at the beginning of the receive
        buffer.

        Examples:

            >>> t = tube()
            >>> t.recv_raw = lambda n: b'hello'
            >>> t.recv()
            b'hello'
            >>> t.recv()
            b'hello'
            >>> t.unrecv(b'world')
            >>> t.recv()
            b'world'
            >>> t.recv()
            b'hello'
        """
        ...

    def wait(self, timeout=pwnlib.timeout.Timeout.default):
        r"""
        Waits until the tube is closed.
        """
        ...

    def wait_for_close(self, timeout=pwnlib.timeout.Timeout.default):
        r"""
        Waits until the tube is closed.
        """
        ...

    def waitfor(self, *args, **kwargs):
        r"""
        Alias for :meth:`progress`.
        """
        ...

    def warn(self, *args, **kwargs):
        r"""
        Alias for :meth:`warning`.
        """
        ...

    def warn_once(self, *args, **kwargs):
        r"""
        Alias for :meth:`warning_once`.
        """
        ...

    def warning(self, message, *args, **kwargs):
        r"""
        warning(message, *args, **kwargs)

        Logs a warning message.
        """
        ...

    def warning_once(self, message, *args, **kwargs):
        r"""
        warning_once(message, *args, **kwargs)

        Logs a warning message.  The same message is never printed again.
        """
        ...

    def write(self, *a, **kw):
        r"""
        Alias for :meth:`send`
        """
        ...

    def write_raw(self, *a, **kw):
        r"""
        Alias for :meth:`send_raw`
        """
        ...

    def writeafter(self, *a, **kw):
        r"""
        Alias for :meth:`sendafter`
        """
        ...

    def writeline(self, *a, **kw):
        r"""
        Alias for :meth:`sendline`
        """
        ...

    def writelineafter(self, *a, **kw):
        r"""
        Alias for :meth:`sendlineafter`
        """
        ...

    def writelines(self, *a, **kw):
        r"""
        Alias for :meth:`sendlines`
        """
        ...

    def writelinethen(self, *a, **kw):
        r"""
        Alias for :meth:`sendlinethen`
        """
        ...

    def writethen(self, *a, **kw):
        r"""
        Alias for :meth:`sendthen`
        """
        ...

class udp (pwnlib.tubes.remote.remote):
    r"""
    Creates a TCP or UDP-connection to a remote host. It supports
    both IPv4 and IPv6.

    The returned object supports all the methods from
    :class:`pwnlib.tubes.sock` and :class:`pwnlib.tubes.tube`.

    Arguments:
        host(str): The host to connect to.
        port(int): The port to connect to.
        fam: The string "any", "ipv4" or "ipv6" or an integer to pass to :func:`socket.getaddrinfo`.
        typ: The string "tcp" or "udp" or an integer to pass to :func:`socket.getaddrinfo`.
        timeout: A positive number, None or the string "default".
        ssl(bool): Wrap the socket with SSL
        ssl_context(ssl.SSLContext): Specify SSLContext used to wrap the socket.
        sni: Set 'server_hostname' in ssl_args based on the host parameter.
        sock(socket.socket): Socket to inherit, rather than connecting
        ssl_args(dict): Pass ssl.wrap_socket named arguments in a dictionary.

    Examples:

        >>> r = remote('google.com', 443, ssl=True)
        >>> r.send(b'GET /\r\n\r\n')
        >>> r.recvn(4)
        b'HTTP'

        If a connection cannot be made, an exception is raised.

        >>> r = remote('127.0.0.1', 1)
        Traceback (most recent call last):
        ...
        PwnlibException: Could not connect to 127.0.0.1 on port 1

        You can also use :meth:`.remote.fromsocket` to wrap an existing socket.

        >>> import socket
        >>> s = socket.socket()
        >>> s.connect(('google.com', 80))
        >>> s.send(b'GET /' + b'\r\n'*2)
        9
        >>> r = remote.fromsocket(s)
        >>> r.recvn(4)
        b'HTTP'
    """
    def __enter__(self):
        r"""
        Permit use of 'with' to control scoping and closing sessions.

        Examples:

            >>> t = tube()
            >>> def p(x): print(x)
            >>> t.close = lambda: p("Closed!")
            >>> with t: pass
            Closed!
        """
        ...

    def __exit__(self, type, value, traceback):
        r"""
        Handles closing for 'with' statement

        See :meth:`__enter__`
        """
        ...

    def __init__(self, host, port, *a, **kw):
        r"""
        Initialize self.  See help(type(self)) for accurate signature.
        """
        ...

    def __lshift__(self, other):
        r"""
        Shorthand for connecting multiple tubes.

        See :meth:`connect_input` for more information.

        Examples:

            The following are equivalent ::

                tube_a >> tube.b
                tube_a.connect_input(tube_b)

            This is useful when chaining multiple tubes ::

                tube_a >> tube_b >> tube_a
                tube_a.connect_input(tube_b)
                tube_b.connect_input(tube_a)
        """
        ...

    def __ne__(self, other):
        r"""
        Shorthand for connecting tubes to eachother.

        The following are equivalent ::

            a >> b >> a
            a <> b

        See :meth:`connect_input` for more information.
        """
        ...

    def __rshift__(self, other):
        r"""
        Inverse of the ``<<`` operator.  See :meth:`__lshift__`.

        See :meth:`connect_input` for more information.
        """
        ...

    def _close_msg(self):

        ...

    def _connect(self, fam, typ):

        ...

    def _fillbuffer(self, timeout=pwnlib.timeout.Timeout.default):
        r"""
        _fillbuffer(timeout = default)

        Fills the internal buffer from the pipe, by calling
        :meth:`recv_raw` exactly once.

        Returns:

            The bytes of data received, or ``''`` if no data was received.

        Examples:

            >>> t = tube()
            >>> t.recv_raw = lambda *a: b'abc'
            >>> len(t.buffer)
            0
            >>> t._fillbuffer()
            b'abc'
            >>> len(t.buffer)
            3
        """
        ...

    def _get_timeout_seconds(self, value):

        ...

    def _getlevel(self, levelString):

        ...

    def _log(self, level, msg, args, kwargs, msgtype, progress=None):

        ...

    def _read(self, *a, **kw):
        r"""
        Alias for :meth:`_recv`
        """
        ...

    def _recv(self, numb=None, timeout=pwnlib.timeout.Timeout.default):
        r"""
        _recv(numb = 4096, timeout = default) -> str

        Receives one chunk of from the internal buffer or from the OS if the
        buffer is empty.
        """
        ...

    def addHandler(self, handler):
        r"""
        addHandler(handler)

        Add the specified handler to the underlying logger.
        """
        ...

    def can_read(self, *a, **kw):
        r"""
        Alias for :meth:`can_recv`
        """
        ...

    def can_read_raw(self, *a, **kw):
        r"""
        Alias for :meth:`can_recv_raw`
        """
        ...

    def can_recv(self, timeout=0):
        r"""
        can_recv(timeout = 0) -> bool

        Returns True, if there is data available within `timeout` seconds.

        Examples:

            >>> import time
            >>> t = tube()
            >>> t.can_recv_raw = lambda *a: False
            >>> t.can_recv()
            False
            >>> _=t.unrecv(b'data')
            >>> t.can_recv()
            True
            >>> _=t.recv()
            >>> t.can_recv()
            False
        """
        ...

    def can_recv_raw(self, timeout):
        r"""
        Tests:

            >>> l = listen()
            >>> r = remote('localhost', l.lport)
            >>> r.can_recv_raw(timeout=0)
            False
            >>> l.send(b'a')
            >>> r.can_recv_raw(timeout=1)
            True
            >>> r.recv()
            b'a'
            >>> r.can_recv_raw(timeout=0)
            False
            >>> l.close()
            >>> r.can_recv_raw(timeout=1)
            False
            >>> r.closed['recv']
            True
        """
        ...

    def clean(self, timeout=0.05):
        r"""
        clean(timeout = 0.05)

        Removes all the buffered data from a tube by calling
        :meth:`pwnlib.tubes.tube.tube.recv` with a low timeout until it fails.

        If ``timeout`` is zero, only cached data will be cleared.

        Note: If timeout is set to zero, the underlying network is
        not actually polled; only the internal buffer is cleared.

        Returns:

            All data received

        Examples:

            >>> t = tube()
            >>> t.unrecv(b'clean me up')
            >>> t.clean(0)
            b'clean me up'
            >>> len(t.buffer)
            0
        """
        ...

    def clean_and_log(self, timeout=0.05):
        r"""
        clean_and_log(timeout = 0.05)

        Works exactly as :meth:`pwnlib.tubes.tube.tube.clean`, but logs received
        data with :meth:`pwnlib.self.info`.

        Returns:

            All data received

        Examples:

            >>> def recv(n, data=[b'', b'hooray_data']):
            ...     while data: return data.pop()
            >>> t = tube()
            >>> t.recv_raw      = recv
            >>> t.connected_raw = lambda d: True
            >>> t.fileno        = lambda: 1234
            >>> with context.local(log_level='info'):
            ...     data = t.clean_and_log() #doctest: +ELLIPSIS
            [DEBUG] Received 0xb bytes:
                b'hooray_data'
            >>> data
            b'hooray_data'
            >>> context.clear()
        """
        ...

    def close(self):
        r"""
        close()

        Closes the tube.
        """
        ...

    def connect_both(self, other):
        r"""
        connect_both(other)

        Connects the both ends of this tube object with another tube object.
        """
        ...

    def connect_input(self, other):
        r"""
        connect_input(other)

        Connects the input of this tube to the output of another tube object.


        Examples:

            >>> def p(x): print(x.decode())
            >>> def recvone(n, data=[b'data']):
            ...     while data: return data.pop()
            ...     raise EOFError
            >>> a = tube()
            >>> b = tube()
            >>> a.recv_raw = recvone
            >>> b.send_raw = p
            >>> a.connected_raw = lambda d: True
            >>> b.connected_raw = lambda d: True
            >>> a.shutdown      = lambda d: True
            >>> b.shutdown      = lambda d: True
            >>> import time
            >>> _=(b.connect_input(a), time.sleep(0.1))
            data
        """
        ...

    def connect_output(self, other):
        r"""
        connect_output(other)

        Connects the output of this tube to the input of another tube object.

        Examples:

            >>> def p(x): print(repr(x))
            >>> def recvone(n, data=[b'data']):
            ...     while data: return data.pop()
            ...     raise EOFError
            >>> a = tube()
            >>> b = tube()
            >>> a.recv_raw = recvone
            >>> b.send_raw = p
            >>> a.connected_raw = lambda d: True
            >>> b.connected_raw = lambda d: True
            >>> a.shutdown      = lambda d: True
            >>> b.shutdown      = lambda d: True
            >>> _=(a.connect_output(b), time.sleep(0.1))
            b'data'
        """
        ...

    def connected(self, direction='any'):
        r"""
        connected(direction = 'any') -> bool

        Returns True if the tube is connected in the specified direction.

        Arguments:
          direction(str): Can be the string 'any', 'in', 'read', 'recv',
                          'out', 'write', 'send'.

        Doctest:

            >>> def p(x): print(x)
            >>> t = tube()
            >>> t.connected_raw = p
            >>> _=list(map(t.connected, ('any', 'in', 'read', 'recv', 'out', 'write', 'send')))
            any
            recv
            recv
            recv
            send
            send
            send
            >>> t.connected('bad_value') #doctest: +ELLIPSIS
            Traceback (most recent call last):
            ...
            KeyError: "direction must be in ['any', 'in', 'out', 'read', 'recv', 'send', 'write']"
        """
        ...

    def connected_raw(self, direction):
        r"""
        Tests:

            >>> l = listen()
            >>> r = remote('localhost', l.lport)
            >>> r.connected()
            True
            >>> l.close()
            >>> time.sleep(0.1) # Avoid race condition
            >>> r.connected()
            False
        """
        ...

    def countdown(self, timeout=pwnlib.timeout.Timeout.default):
        r"""
        Scoped timeout setter.  Sets the timeout within the scope,
        and restores it when leaving the scope.

        When accessing :attr:`timeout` within the scope, it will be
        calculated against the time when the scope was entered, in a
        countdown fashion.

        If :const:`None` is specified for ``timeout``, then the current
        timeout is used is made.  This allows :const:`None` to be specified
        as a default argument with less complexity.
        """
        ...

    def countdown_active(self):

        ...

    def critical(self, message, *args, **kwargs):
        r"""
        critical(message, *args, **kwargs)

        Logs a critical message.
        """
        ...

    def debug(self, message, *args, **kwargs):
        r"""
        debug(message, *args, **kwargs)

        Logs a debug message.
        """
        ...

    def error(self, message, *args, **kwargs):
        r"""
        error(message, *args, **kwargs)

        To be called outside an exception handler.

        Logs an error message, then raises a ``PwnlibException``.
        """
        ...

    def exception(self, message, *args, **kwargs):
        r"""
        exception(message, *args, **kwargs)

        To be called from an exception handler.

        Logs a error message, then re-raises the current exception.
        """
        ...

    def failure(self, message, *args, **kwargs):
        r"""
        failure(message, *args, **kwargs)

        Logs a failure message.
        """
        ...

    def fileno(self):
        r"""
        fileno() -> int

        Returns the file number used for reading.
        """
        ...

    def fit(self, *a, **kw):

        ...

    def flat(self, *a, **kw):

        ...

    def hexdump(self, message, *args, **kwargs):

        ...

    def indented(self, message, *args, **kwargs):
        r"""
        indented(message, *args, level = logging.INFO, **kwargs)

        Log a message but don't put a line prefix on it.

        Arguments:
            level(int): Alternate log level at which to set the indented
                        message.  Defaults to :const:`logging.INFO`.
        """
        ...

    def info(self, message, *args, **kwargs):
        r"""
        info(message, *args, **kwargs)

        Logs an info message.
        """
        ...

    def info_once(self, message, *args, **kwargs):
        r"""
        info_once(message, *args, **kwargs)

        Logs an info message.  The same message is never printed again.
        """
        ...

    def interactive(self, prompt='\x1b[1m\x1b[31m$\x1b[m '):
        r"""
        interactive(prompt = pwnlib.term.text.bold_red('$') + ' ')

        Does simultaneous reading and writing to the tube. In principle this just
        connects the tube to standard in and standard out, but in practice this
        is much more usable, since we are using :mod:`pwnlib.term` to print a
        floating prompt.

        Thus it only works in while in :data:`pwnlib.term.term_mode`.
        """
        ...

    def isEnabledFor(self, level):
        r"""
        isEnabledFor(level) -> bool

        See if the underlying logger is enabled for the specified level.
        """
        ...

    def local(self, timeout):
        r"""
        Scoped timeout setter.  Sets the timeout within the scope,
        and restores it when leaving the scope.
        """
        ...

    def log(self, level, message, *args, **kwargs):
        r"""
        log(level, message, *args, **kwargs)

        Logs a message with log level `level`.  The ``pwnlib`` formatter will
        use the default :mod:`logging` formater to format this message.
        """
        ...

    def p16(self, *a, **kw):

        ...

    def p32(self, *a, **kw):

        ...

    def p64(self, *a, **kw):

        ...

    def p8(self, *a, **kw):

        ...

    def pack(self, *a, **kw):

        ...

    def progress(self, message, status='', *args, **kwargs):
        r"""
        progress(message, status = '', *args, level = logging.INFO, **kwargs) -> Progress

        Creates a new progress logger which creates log records with log level
        `level`.

        Progress status can be updated using :meth:`Progress.status` and stopped
        using :meth:`Progress.success` or :meth:`Progress.failure`.

        If `term.term_mode` is enabled the progress logger will be animated.

        The progress manager also functions as a context manager.  Using context
        managers ensures that animations stop even if an exception is raised.

        .. code-block:: python

           with log.progress('Trying something...') as p:
               for i in range(10):
                   p.status("At %i" % i)
                   time.sleep(0.5)
               x = 1/0
        """
        ...

    def read(self, *a, **kw):
        r"""
        Alias for :meth:`recv`
        """
        ...

    def readS(self, *a, **kw):
        r"""
        Alias for :meth:`recvS`
        """
        ...

    def read_raw(self, *a, **kw):
        r"""
        Alias for :meth:`recv_raw`
        """
        ...

    def readall(self, *a, **kw):
        r"""
        Alias for :meth:`recvall`
        """
        ...

    def readallS(self, *a, **kw):
        r"""
        Alias for :meth:`recvallS`
        """
        ...

    def readallb(self, *a, **kw):
        r"""
        Alias for :meth:`recvallb`
        """
        ...

    def readb(self, *a, **kw):
        r"""
        Alias for :meth:`recvb`
        """
        ...

    def readline(self, *a, **kw):
        r"""
        Alias for :meth:`recvline`
        """
        ...

    def readlineS(self, *a, **kw):
        r"""
        Alias for :meth:`recvlineS`
        """
        ...

    def readline_contains(self, *a, **kw):
        r"""
        Alias for :meth:`recvline_contains`
        """
        ...

    def readline_containsS(self, *a, **kw):
        r"""
        Alias for :meth:`recvline_containsS`
        """
        ...

    def readline_containsb(self, *a, **kw):
        r"""
        Alias for :meth:`recvline_containsb`
        """
        ...

    def readline_endswith(self, *a, **kw):
        r"""
        Alias for :meth:`recvline_endswith`
        """
        ...

    def readline_endswithS(self, *a, **kw):
        r"""
        Alias for :meth:`recvline_endswithS`
        """
        ...

    def readline_endswithb(self, *a, **kw):
        r"""
        Alias for :meth:`recvline_endswithb`
        """
        ...

    def readline_pred(self, *a, **kw):
        r"""
        Alias for :meth:`recvline_pred`
        """
        ...

    def readline_regex(self, *a, **kw):
        r"""
        Alias for :meth:`recvline_regex`
        """
        ...

    def readline_regexS(self, *a, **kw):
        r"""
        Alias for :meth:`recvline_regexS`
        """
        ...

    def readline_regexb(self, *a, **kw):
        r"""
        Alias for :meth:`recvline_regexb`
        """
        ...

    def readline_startswith(self, *a, **kw):
        r"""
        Alias for :meth:`recvline_startswith`
        """
        ...

    def readline_startswithS(self, *a, **kw):
        r"""
        Alias for :meth:`recvline_startswithS`
        """
        ...

    def readline_startswithb(self, *a, **kw):
        r"""
        Alias for :meth:`recvline_startswithb`
        """
        ...

    def readlineb(self, *a, **kw):
        r"""
        Alias for :meth:`recvlineb`
        """
        ...

    def readlines(self, *a, **kw):
        r"""
        Alias for :meth:`recvlines`
        """
        ...

    def readlinesS(self, *a, **kw):
        r"""
        Alias for :meth:`recvlinesS`
        """
        ...

    def readlinesb(self, *a, **kw):
        r"""
        Alias for :meth:`recvlinesb`
        """
        ...

    def readn(self, *a, **kw):
        r"""
        Alias for :meth:`recvn`
        """
        ...

    def readnS(self, *a, **kw):
        r"""
        Alias for :meth:`recvnS`
        """
        ...

    def readnb(self, *a, **kw):
        r"""
        Alias for :meth:`recvnb`
        """
        ...

    def readpred(self, *a, **kw):
        r"""
        Alias for :meth:`recvpred`
        """
        ...

    def readpredS(self, *a, **kw):
        r"""
        Alias for :meth:`recvpredS`
        """
        ...

    def readpredb(self, *a, **kw):
        r"""
        Alias for :meth:`recvpredb`
        """
        ...

    def readregex(self, *a, **kw):
        r"""
        Alias for :meth:`recvregex`
        """
        ...

    def readregexS(self, *a, **kw):
        r"""
        Alias for :meth:`recvregexS`
        """
        ...

    def readregexb(self, *a, **kw):
        r"""
        Alias for :meth:`recvregexb`
        """
        ...

    def readrepeat(self, *a, **kw):
        r"""
        Alias for :meth:`recvrepeat`
        """
        ...

    def readrepeatS(self, *a, **kw):
        r"""
        Alias for :meth:`recvrepeatS`
        """
        ...

    def readrepeatb(self, *a, **kw):
        r"""
        Alias for :meth:`recvrepeatb`
        """
        ...

    def readuntil(self, *a, **kw):
        r"""
        Alias for :meth:`recvuntil`
        """
        ...

    def readuntilS(self, *a, **kw):
        r"""
        Alias for :meth:`recvuntilS`
        """
        ...

    def readuntilb(self, *a, **kw):
        r"""
        Alias for :meth:`recvuntilb`
        """
        ...

    def recv(self, numb=None, timeout=pwnlib.timeout.Timeout.default):
        r"""
        recv(numb = 4096, timeout = default) -> bytes

        Receives up to `numb` bytes of data from the tube, and returns
        as soon as any quantity of data is available.

        If the request is not satisfied before ``timeout`` seconds pass,
        all data is buffered and an empty string (``''``) is returned.

        Raises:
            exceptions.EOFError: The connection is closed

        Returns:
            A bytes object containing bytes received from the socket,
            or ``''`` if a timeout occurred while waiting.

        Examples:

            >>> t = tube()
            >>> # Fake a data source
            >>> t.recv_raw = lambda n: b'Hello, world'
            >>> t.recv() == b'Hello, world'
            True
            >>> t.unrecv(b'Woohoo')
            >>> t.recv() == b'Woohoo'
            True
            >>> with context.local(log_level='debug'):
            ...    _ = t.recv() # doctest: +ELLIPSIS
            [...] Received 0xc bytes:
                b'Hello, world'
        """
        ...

    def recvS(self, *a, **kw):
        r"""
        Same as :meth:`recv`, but returns a str, decoding the result using `context.encoding`. (note that the binary versions are way faster)
        """
        ...

    def recv_raw(self, numb, *a):
        r"""
        recv_raw(numb) -> str

        Should not be called directly. Receives data without using the buffer
        on the object.

        Unless there is a timeout or closed connection, this should always
        return data. In case of a timeout, it should return None, in case
        of a closed connection it should raise an ``exceptions.EOFError``.
        """
        ...

    def recvall(self, timeout=None):
        r"""
        recvall() -> str

        Receives data until the socket is closed.
        """
        ...

    def recvallS(self, *a, **kw):
        r"""
        Same as :meth:`recvall`, but returns a str, decoding the result using `context.encoding`. (note that the binary versions are way faster)
        """
        ...

    def recvallb(self, *a, **kw):
        r"""
        Same as :meth:`recvall`, but returns a bytearray
        """
        ...

    def recvb(self, *a, **kw):
        r"""
        Same as :meth:`recv`, but returns a bytearray
        """
        ...

    def recvline(self, keepends=True, timeout=pwnlib.timeout.Timeout.default):
        r"""
        recvline(keepends=True, timeout=default) -> bytes

        Receive a single line from the tube.

        A "line" is any sequence of bytes terminated by the byte sequence
        set in :attr:`newline`, which defaults to ``'\n'``.

        If the request is not satisfied before ``timeout`` seconds pass,
        all data is buffered and an empty string (``''``) is returned.

        Arguments:
            keepends(bool): Keep the line ending (:const:`True`).
            timeout(int): Timeout

        Return:
            All bytes received over the tube until the first
            newline ``'\n'`` is received.  Optionally retains
            the ending.

        Examples:

            >>> t = tube()
            >>> t.recv_raw = lambda n: b'Foo\nBar\r\nBaz\n'
            >>> t.recvline()
            b'Foo\n'
            >>> t.recvline()
            b'Bar\r\n'
            >>> t.recvline(keepends = False)
            b'Baz'
            >>> t.newline = b'\r\n'
            >>> t.recvline(keepends = False)
            b'Foo\nBar'
        """
        ...

    def recvlineS(self, *a, **kw):
        r"""
        Same as :meth:`recvline`, but returns a str, decoding the result using `context.encoding`. (note that the binary versions are way faster)
        """
        ...

    def recvline_contains(self, items, keepends=False, timeout=pwnlib.timeout.Timeout.default):
        r"""
        Receive lines until one line is found which contains at least
        one of `items`.

        Arguments:
            items(str,tuple): List of strings to search for, or a single string.
            keepends(bool): Return lines with newlines if :const:`True`
            timeout(int): Timeout, in seconds

        Examples:

            >>> t = tube()
            >>> t.recv_raw = lambda n: b"Hello\nWorld\nXylophone\n"
            >>> t.recvline_contains(b'r')
            b'World'
            >>> f = lambda n: b"cat dog bird\napple pear orange\nbicycle car train\n"
            >>> t = tube()
            >>> t.recv_raw = f
            >>> t.recvline_contains(b'pear')
            b'apple pear orange'
            >>> t = tube()
            >>> t.recv_raw = f
            >>> t.recvline_contains((b'car', b'train'))
            b'bicycle car train'
        """
        ...

    def recvline_containsS(self, *a, **kw):
        r"""
        Same as :meth:`recvline_contains`, but returns a str, decoding the result using `context.encoding`. (note that the binary versions are way faster)
        """
        ...

    def recvline_containsb(self, *a, **kw):
        r"""
        Same as :meth:`recvline_contains`, but returns a bytearray
        """
        ...

    def recvline_endswith(self, delims, keepends=False, timeout=pwnlib.timeout.Timeout.default):
        r"""
        recvline_endswith(delims, keepends=False, timeout=default) -> bytes

        Keep receiving lines until one is found that ends with one of
        `delims`.  Returns the last line received.

        If the request is not satisfied before ``timeout`` seconds pass,
        all data is buffered and an empty string (``''``) is returned.

        See :meth:`recvline_startswith` for more details.

        Examples:

            >>> t = tube()
            >>> t.recv_raw = lambda n: b'Foo\nBar\nBaz\nKaboodle\n'
            >>> t.recvline_endswith(b'r')
            b'Bar'
            >>> t.recvline_endswith((b'a',b'b',b'c',b'd',b'e'), True)
            b'Kaboodle\n'
            >>> t.recvline_endswith(b'oodle')
            b'Kaboodle'
        """
        ...

    def recvline_endswithS(self, *a, **kw):
        r"""
        Same as :meth:`recvline_endswith`, but returns a str, decoding the result using `context.encoding`. (note that the binary versions are way faster)
        """
        ...

    def recvline_endswithb(self, *a, **kw):
        r"""
        Same as :meth:`recvline_endswith`, but returns a bytearray
        """
        ...

    def recvline_pred(self, pred, keepends=False, timeout=pwnlib.timeout.Timeout.default):
        r"""
        recvline_pred(pred, keepends=False) -> bytes

        Receive data until ``pred(line)`` returns a truthy value.
        Drop all other data.

        If the request is not satisfied before ``timeout`` seconds pass,
        all data is buffered and an empty string (``''``) is returned.

        Arguments:
            pred(callable): Function to call.  Returns the line for which
                this function returns :const:`True`.

        Examples:

            >>> t = tube()
            >>> t.recv_raw = lambda n: b"Foo\nBar\nBaz\n"
            >>> t.recvline_pred(lambda line: line == b"Bar\n")
            b'Bar'
            >>> t.recvline_pred(lambda line: line == b"Bar\n", keepends=True)
            b'Bar\n'
            >>> t.recvline_pred(lambda line: line == b'Nope!', timeout=0.1)
            b''
        """
        ...

    def recvline_regex(self, regex, exact=False, keepends=False, timeout=pwnlib.timeout.Timeout.default):
        r"""
        recvline_regex(regex, exact=False, keepends=False, timeout=default) -> bytes

        Wrapper around :func:`recvline_pred`, which will return when a regex
        matches a line.

        By default :func:`re.RegexObject.search` is used, but if `exact` is
        set to True, then :func:`re.RegexObject.match` will be used instead.

        If the request is not satisfied before ``timeout`` seconds pass,
        all data is buffered and an empty string (``''``) is returned.
        """
        ...

    def recvline_regexS(self, *a, **kw):
        r"""
        Same as :meth:`recvline_regex`, but returns a str, decoding the result using `context.encoding`. (note that the binary versions are way faster)
        """
        ...

    def recvline_regexb(self, *a, **kw):
        r"""
        Same as :meth:`recvline_regex`, but returns a bytearray
        """
        ...

    def recvline_startswith(self, delims, keepends=False, timeout=pwnlib.timeout.Timeout.default):
        r"""
        recvline_startswith(delims, keepends=False, timeout=default) -> bytes

        Keep receiving lines until one is found that starts with one of
        `delims`.  Returns the last line received.

        If the request is not satisfied before ``timeout`` seconds pass,
        all data is buffered and an empty string (``''``) is returned.

        Arguments:
            delims(str,tuple): List of strings to search for, or string of single characters
            keepends(bool): Return lines with newlines if :const:`True`
            timeout(int): Timeout, in seconds

        Returns:
            The first line received which starts with a delimiter in ``delims``.

        Examples:

            >>> t = tube()
            >>> t.recv_raw = lambda n: b"Hello\nWorld\nXylophone\n"
            >>> t.recvline_startswith((b'W',b'X',b'Y',b'Z'))
            b'World'
            >>> t.recvline_startswith((b'W',b'X',b'Y',b'Z'), True)
            b'Xylophone\n'
            >>> t.recvline_startswith(b'Wo')
            b'World'
        """
        ...

    def recvline_startswithS(self, *a, **kw):
        r"""
        Same as :meth:`recvline_startswith`, but returns a str, decoding the result using `context.encoding`. (note that the binary versions are way faster)
        """
        ...

    def recvline_startswithb(self, *a, **kw):
        r"""
        Same as :meth:`recvline_startswith`, but returns a bytearray
        """
        ...

    def recvlineb(self, *a, **kw):
        r"""
        Same as :meth:`recvline`, but returns a bytearray
        """
        ...

    def recvlines(self, numlines=1048576, keepends=False, timeout=pwnlib.timeout.Timeout.default):
        r"""
        recvlines(numlines, keepends=False, timeout=default) -> list of bytes objects

        Receive up to ``numlines`` lines.

        A "line" is any sequence of bytes terminated by the byte sequence
        set by :attr:`newline`, which defaults to ``'\n'``.

        If the request is not satisfied before ``timeout`` seconds pass,
        all data is buffered and an empty string (``''``) is returned.

        Arguments:
            numlines(int): Maximum number of lines to receive
            keepends(bool): Keep newlines at the end of each line (:const:`False`).
            timeout(int): Maximum timeout

        Raises:
            exceptions.EOFError: The connection closed before the request could be satisfied

        Returns:
            A string containing bytes received from the socket,
            or ``''`` if a timeout occurred while waiting.

        Examples:

            >>> t = tube()
            >>> t.recv_raw = lambda n: b'\n'
            >>> t.recvlines(3)
            [b'', b'', b'']
            >>> t.recv_raw = lambda n: b'Foo\nBar\nBaz\n'
            >>> t.recvlines(3)
            [b'Foo', b'Bar', b'Baz']
            >>> t.recvlines(3, True)
            [b'Foo\n', b'Bar\n', b'Baz\n']
        """
        ...

    def recvlinesS(self, numlines=1048576, keepends=False, timeout=pwnlib.timeout.Timeout.default):
        r"""
        recvlinesS(numlines, keepends=False, timeout=default) -> str list

        This function is identical to :meth:`recvlines`, but decodes
        the received bytes into string using :func:`context.encoding`.
        You should use :meth:`recvlines` whenever possible for better performance.

        Examples:

            >>> t = tube()
            >>> t.recv_raw = lambda n: b'\n'
            >>> t.recvlinesS(3)
            ['', '', '']
            >>> t.recv_raw = lambda n: b'Foo\nBar\nBaz\n'
            >>> t.recvlinesS(3)
            ['Foo', 'Bar', 'Baz']
        """
        ...

    def recvlinesb(self, numlines=1048576, keepends=False, timeout=pwnlib.timeout.Timeout.default):
        r"""
        recvlinesb(numlines, keepends=False, timeout=default) -> bytearray list

        This function is identical to :meth:`recvlines`, but returns a bytearray.

        Examples:

            >>> t = tube()
            >>> t.recv_raw = lambda n: b'\n'
            >>> t.recvlinesb(3)
            [bytearray(b''), bytearray(b''), bytearray(b'')]
            >>> t.recv_raw = lambda n: b'Foo\nBar\nBaz\n'
            >>> t.recvlinesb(3)
            [bytearray(b'Foo'), bytearray(b'Bar'), bytearray(b'Baz')]
        """
        ...

    def recvn(self, numb, timeout=pwnlib.timeout.Timeout.default):
        r"""
        recvn(numb, timeout = default) -> str

        Receives exactly `n` bytes.

        If the request is not satisfied before ``timeout`` seconds pass,
        all data is buffered and an empty string (``''``) is returned.

        Raises:
            exceptions.EOFError: The connection closed before the request could be satisfied

        Returns:
            A string containing bytes received from the socket,
            or ``''`` if a timeout occurred while waiting.

        Examples:

            >>> t = tube()
            >>> data = b'hello world'
            >>> t.recv_raw = lambda *a: data
            >>> t.recvn(len(data)) == data
            True
            >>> t.recvn(len(data)+1) == data + data[:1]
            True
            >>> t.recv_raw = lambda *a: None
            >>> # The remaining data is buffered
            >>> t.recv() == data[1:]
            True
            >>> t.recv_raw = lambda *a: time.sleep(0.01) or b'a'
            >>> t.recvn(10, timeout=0.05)
            b''
            >>> t.recvn(10, timeout=0.06) # doctest: +ELLIPSIS
            b'aaaaaa...'
        """
        ...

    def recvnS(self, *a, **kw):
        r"""
        Same as :meth:`recvn`, but returns a str, decoding the result using `context.encoding`. (note that the binary versions are way faster)
        """
        ...

    def recvnb(self, *a, **kw):
        r"""
        Same as :meth:`recvn`, but returns a bytearray
        """
        ...

    def recvpred(self, pred, timeout=pwnlib.timeout.Timeout.default):
        r"""
        recvpred(pred, timeout = default) -> bytes

        Receives one byte at a time from the tube, until ``pred(all_bytes)``
        evaluates to True.

        If the request is not satisfied before ``timeout`` seconds pass,
        all data is buffered and an empty string (``''``) is returned.

        Arguments:
            pred(callable): Function to call, with the currently-accumulated data.
            timeout(int): Timeout for the operation

        Raises:
            exceptions.EOFError: The connection is closed

        Returns:
            A bytes object containing bytes received from the socket,
            or ``''`` if a timeout occurred while waiting.
        """
        ...

    def recvpredS(self, *a, **kw):
        r"""
        Same as :meth:`recvpred`, but returns a str, decoding the result using `context.encoding`. (note that the binary versions are way faster)
        """
        ...

    def recvpredb(self, *a, **kw):
        r"""
        Same as :meth:`recvpred`, but returns a bytearray
        """
        ...

    def recvregex(self, regex, exact=False, timeout=pwnlib.timeout.Timeout.default):
        r"""
        recvregex(regex, exact=False, timeout=default) -> bytes

        Wrapper around :func:`recvpred`, which will return when a regex
        matches the string in the buffer.

        By default :func:`re.RegexObject.search` is used, but if `exact` is
        set to True, then :func:`re.RegexObject.match` will be used instead.

        If the request is not satisfied before ``timeout`` seconds pass,
        all data is buffered and an empty string (``''``) is returned.
        """
        ...

    def recvregexS(self, *a, **kw):
        r"""
        Same as :meth:`recvregex`, but returns a str, decoding the result using `context.encoding`. (note that the binary versions are way faster)
        """
        ...

    def recvregexb(self, *a, **kw):
        r"""
        Same as :meth:`recvregex`, but returns a bytearray
        """
        ...

    def recvrepeat(self, timeout=pwnlib.timeout.Timeout.default):
        r"""
        recvrepeat(timeout=default) -> bytes

        Receives data until a timeout or EOF is reached.

        Examples:

            >>> data = [
            ... b'd',
            ... b'', # simulate timeout
            ... b'c',
            ... b'b',
            ... b'a',
            ... ]
            >>> def delayrecv(n, data=data):
            ...     return data.pop()
            >>> t = tube()
            >>> t.recv_raw = delayrecv
            >>> t.recvrepeat(0.2)
            b'abc'
            >>> t.recv()
            b'd'
        """
        ...

    def recvrepeatS(self, *a, **kw):
        r"""
        Same as :meth:`recvrepeat`, but returns a str, decoding the result using `context.encoding`. (note that the binary versions are way faster)
        """
        ...

    def recvrepeatb(self, *a, **kw):
        r"""
        Same as :meth:`recvrepeat`, but returns a bytearray
        """
        ...

    def recvuntil(self, delims, drop=False, timeout=pwnlib.timeout.Timeout.default):
        r"""
        recvuntil(delims, drop=False, timeout=default) -> bytes

        Receive data until one of `delims` is encountered.

        If the request is not satisfied before ``timeout`` seconds pass,
        all data is buffered and an empty string (``''``) is returned.

        arguments:
            delims(bytes,tuple): Byte-string of delimiters characters, or list of delimiter byte-strings.
            drop(bool): Drop the ending.  If :const:`True` it is removed from the end of the return value.

        Raises:
            exceptions.EOFError: The connection closed before the request could be satisfied

        Returns:
            A string containing bytes received from the socket,
            or ``''`` if a timeout occurred while waiting.

        Examples:

            >>> t = tube()
            >>> t.recv_raw = lambda n: b"Hello World!"
            >>> t.recvuntil(b' ')
            b'Hello '
            >>> _=t.clean(0)
            >>> # Matches on 'o' in 'Hello'
            >>> t.recvuntil((b' ',b'W',b'o',b'r'))
            b'Hello'
            >>> _=t.clean(0)
            >>> # Matches expressly full string
            >>> t.recvuntil(b' Wor')
            b'Hello Wor'
            >>> _=t.clean(0)
            >>> # Matches on full string, drops match
            >>> t.recvuntil(b' Wor', drop=True)
            b'Hello'

            >>> # Try with regex special characters
            >>> t = tube()
            >>> t.recv_raw = lambda n: b"Hello|World"
            >>> t.recvuntil(b'|', drop=True)
            b'Hello'
        """
        ...

    def recvuntilS(self, *a, **kw):
        r"""
        Same as :meth:`recvuntil`, but returns a str, decoding the result using `context.encoding`. (note that the binary versions are way faster)
        """
        ...

    def recvuntilb(self, *a, **kw):
        r"""
        Same as :meth:`recvuntil`, but returns a bytearray
        """
        ...

    def removeHandler(self, handler):
        r"""
        removeHandler(handler)

        Remove the specified handler from the underlying logger.
        """
        ...

    def send(self, data):
        r"""
        send(data)

        Sends data.

        If log level ``DEBUG`` is enabled, also prints out the data
        received.

        If it is not possible to send anymore because of a closed
        connection, it raises ``exceptions.EOFError``

        Examples:

            >>> def p(x): print(repr(x))
            >>> t = tube()
            >>> t.send_raw = p
            >>> t.send(b'hello')
            b'hello'
        """
        ...

    def send_raw(self, data):
        r"""
        send_raw(data)

        Should not be called directly. Sends data to the tube.

        Should return ``exceptions.EOFError``, if it is unable to send any
        more, because of a close tube.
        """
        ...

    def sendafter(self, delim, data, timeout=pwnlib.timeout.Timeout.default):
        r"""
        sendafter(delim, data, timeout = default) -> str

        A combination of ``recvuntil(delim, timeout=timeout)`` and ``send(data)``.
        """
        ...

    def sendline(self, line=b''):
        r"""
        sendline(data)

        Shorthand for ``t.send(data + t.newline)``.

        Examples:

            >>> def p(x): print(repr(x))
            >>> t = tube()
            >>> t.send_raw = p
            >>> t.sendline(b'hello')
            b'hello\n'
            >>> t.newline = b'\r\n'
            >>> t.sendline(b'hello')
            b'hello\r\n'
        """
        ...

    def sendlineafter(self, delim, data, timeout=pwnlib.timeout.Timeout.default):
        r"""
        sendlineafter(delim, data, timeout = default) -> str

        A combination of ``recvuntil(delim, timeout=timeout)`` and ``sendline(data)``.
        """
        ...

    def sendlines(self, lines=[]):

        ...

    def sendlinethen(self, delim, data, timeout=pwnlib.timeout.Timeout.default):
        r"""
        sendlinethen(delim, data, timeout = default) -> str

        A combination of ``sendline(data)`` and ``recvuntil(delim, timeout=timeout)``.
        """
        ...

    def sendthen(self, delim, data, timeout=pwnlib.timeout.Timeout.default):
        r"""
        sendthen(delim, data, timeout = default) -> str

        A combination of ``send(data)`` and ``recvuntil(delim, timeout=timeout)``.
        """
        ...

    def setLevel(self, level):
        r"""
        setLevel(level)

        Set the logging level for the underlying logger.
        """
        ...

    def settimeout(self, timeout):
        r"""
        settimeout(timeout)

        Set the timeout for receiving operations. If the string "default"
        is given, then :data:`context.timeout` will be used. If None is given,
        then there will be no timeout.

        Examples:

            >>> t = tube()
            >>> t.settimeout_raw = lambda t: None
            >>> t.settimeout(3)
            >>> t.timeout == 3
            True
        """
        ...

    def settimeout_raw(self, timeout):
        r"""
        settimeout_raw(timeout)

        Should not be called directly. Sets the timeout for
        the tube.
        """
        ...

    def shutdown(self, direction='send'):
        r"""
        shutdown(direction = "send")

        Closes the tube for futher reading or writing depending on `direction`.

        Arguments:
          direction(str): Which direction to close; "in", "read" or "recv"
            closes the tube in the ingoing direction, "out", "write" or "send"
            closes it in the outgoing direction.

        Returns:
          :const:`None`

        Examples:

            >>> def p(x): print(x)
            >>> t = tube()
            >>> t.shutdown_raw = p
            >>> _=list(map(t.shutdown, ('in', 'read', 'recv', 'out', 'write', 'send')))
            recv
            recv
            recv
            send
            send
            send
            >>> t.shutdown('bad_value') #doctest: +ELLIPSIS
            Traceback (most recent call last):
            ...
            KeyError: "direction must be in ['in', 'out', 'read', 'recv', 'send', 'write']"
        """
        ...

    def shutdown_raw(self, direction):
        r"""
        shutdown_raw(direction)

        Should not be called directly.  Closes the tube for further reading or
        writing.
        """
        ...

    def spawn_process(self, *args, **kwargs):
        r"""
        Spawns a new process having this tube as stdin, stdout and stderr.

        Takes the same arguments as :class:`subprocess.Popen`.
        """
        ...

    def stream(self, line_mode=True):
        r"""
        stream()

        Receive data until the tube exits, and print it to stdout.

        Similar to :func:`interactive`, except that no input is sent.

        Similar to ``print(tube.recvall())`` except that data is printed
        as it is received, rather than after all data is received.

        Arguments:
            line_mode(bool): Whether to receive line-by-line or raw data.

        Returns:
            All data printed.
        """
        ...

    def success(self, message, *args, **kwargs):
        r"""
        success(message, *args, **kwargs)

        Logs a success message.
        """
        ...

    def timeout_change(self):
        r"""
        Informs the raw layer of the tube that the timeout has changed.

        Should not be called directly.

        Inherited from :class:`Timeout`.
        """
        ...

    def u16(self, *a, **kw):

        ...

    def u32(self, *a, **kw):

        ...

    def u64(self, *a, **kw):

        ...

    def u8(self, *a, **kw):

        ...

    def unpack(self, *a, **kw):

        ...

    def unread(self, *a, **kw):
        r"""
        Alias for :meth:`unrecv`
        """
        ...

    def unrecv(self, data):
        r"""
        unrecv(data)

        Puts the specified data back at the beginning of the receive
        buffer.

        Examples:

            >>> t = tube()
            >>> t.recv_raw = lambda n: b'hello'
            >>> t.recv()
            b'hello'
            >>> t.recv()
            b'hello'
            >>> t.unrecv(b'world')
            >>> t.recv()
            b'world'
            >>> t.recv()
            b'hello'
        """
        ...

    def wait(self, timeout=pwnlib.timeout.Timeout.default):
        r"""
        Waits until the tube is closed.
        """
        ...

    def wait_for_close(self, timeout=pwnlib.timeout.Timeout.default):
        r"""
        Waits until the tube is closed.
        """
        ...

    def waitfor(self, *args, **kwargs):
        r"""
        Alias for :meth:`progress`.
        """
        ...

    def warn(self, *args, **kwargs):
        r"""
        Alias for :meth:`warning`.
        """
        ...

    def warn_once(self, *args, **kwargs):
        r"""
        Alias for :meth:`warning_once`.
        """
        ...

    def warning(self, message, *args, **kwargs):
        r"""
        warning(message, *args, **kwargs)

        Logs a warning message.
        """
        ...

    def warning_once(self, message, *args, **kwargs):
        r"""
        warning_once(message, *args, **kwargs)

        Logs a warning message.  The same message is never printed again.
        """
        ...

    def write(self, *a, **kw):
        r"""
        Alias for :meth:`send`
        """
        ...

    def write_raw(self, *a, **kw):
        r"""
        Alias for :meth:`send_raw`
        """
        ...

    def writeafter(self, *a, **kw):
        r"""
        Alias for :meth:`sendafter`
        """
        ...

    def writeline(self, *a, **kw):
        r"""
        Alias for :meth:`sendline`
        """
        ...

    def writelineafter(self, *a, **kw):
        r"""
        Alias for :meth:`sendlineafter`
        """
        ...

    def writelines(self, *a, **kw):
        r"""
        Alias for :meth:`sendlines`
        """
        ...

    def writelinethen(self, *a, **kw):
        r"""
        Alias for :meth:`sendlinethen`
        """
        ...

    def writethen(self, *a, **kw):
        r"""
        Alias for :meth:`sendthen`
        """
        ...


import pwnlib.tubes.serialtube

class serialtube (pwnlib.tubes.tube.tube):
    r"""
    Container of all the tube functions common to sockets, TTYs and SSH connetions.
    """
    def __enter__(self):
        r"""
        Permit use of 'with' to control scoping and closing sessions.

        Examples:

            >>> t = tube()
            >>> def p(x): print(x)
            >>> t.close = lambda: p("Closed!")
            >>> with t: pass
            Closed!
        """
        ...

    def __exit__(self, type, value, traceback):
        r"""
        Handles closing for 'with' statement

        See :meth:`__enter__`
        """
        ...

    def __init__(self, port=None, baudrate=115200, convert_newlines=True, bytesize=8, parity='N', stopbits=1, xonxoff=False, rtscts=False, dsrdtr=False, *a, **kw):
        r"""
        Initialize self.  See help(type(self)) for accurate signature.
        """
        ...

    def __lshift__(self, other):
        r"""
        Shorthand for connecting multiple tubes.

        See :meth:`connect_input` for more information.

        Examples:

            The following are equivalent ::

                tube_a >> tube.b
                tube_a.connect_input(tube_b)

            This is useful when chaining multiple tubes ::

                tube_a >> tube_b >> tube_a
                tube_a.connect_input(tube_b)
                tube_b.connect_input(tube_a)
        """
        ...

    def __ne__(self, other):
        r"""
        Shorthand for connecting tubes to eachother.

        The following are equivalent ::

            a >> b >> a
            a <> b

        See :meth:`connect_input` for more information.
        """
        ...

    def __rshift__(self, other):
        r"""
        Inverse of the ``<<`` operator.  See :meth:`__lshift__`.

        See :meth:`connect_input` for more information.
        """
        ...

    def _fillbuffer(self, timeout=pwnlib.timeout.Timeout.default):
        r"""
        _fillbuffer(timeout = default)

        Fills the internal buffer from the pipe, by calling
        :meth:`recv_raw` exactly once.

        Returns:

            The bytes of data received, or ``''`` if no data was received.

        Examples:

            >>> t = tube()
            >>> t.recv_raw = lambda *a: b'abc'
            >>> len(t.buffer)
            0
            >>> t._fillbuffer()
            b'abc'
            >>> len(t.buffer)
            3
        """
        ...

    def _get_timeout_seconds(self, value):

        ...

    def _getlevel(self, levelString):

        ...

    def _log(self, level, msg, args, kwargs, msgtype, progress=None):

        ...

    def _read(self, *a, **kw):
        r"""
        Alias for :meth:`_recv`
        """
        ...

    def _recv(self, numb=None, timeout=pwnlib.timeout.Timeout.default):
        r"""
        _recv(numb = 4096, timeout = default) -> str

        Receives one chunk of from the internal buffer or from the OS if the
        buffer is empty.
        """
        ...

    def addHandler(self, handler):
        r"""
        addHandler(handler)

        Add the specified handler to the underlying logger.
        """
        ...

    def can_read(self, *a, **kw):
        r"""
        Alias for :meth:`can_recv`
        """
        ...

    def can_read_raw(self, *a, **kw):
        r"""
        Alias for :meth:`can_recv_raw`
        """
        ...

    def can_recv(self, timeout=0):
        r"""
        can_recv(timeout = 0) -> bool

        Returns True, if there is data available within `timeout` seconds.

        Examples:

            >>> import time
            >>> t = tube()
            >>> t.can_recv_raw = lambda *a: False
            >>> t.can_recv()
            False
            >>> _=t.unrecv(b'data')
            >>> t.can_recv()
            True
            >>> _=t.recv()
            >>> t.can_recv()
            False
        """
        ...

    def can_recv_raw(self, timeout):
        r"""
        can_recv_raw(timeout) -> bool

        Should not be called directly. Returns True, if
        there is data available within the timeout, but
        ignores the buffer on the object.
        """
        ...

    def clean(self, timeout=0.05):
        r"""
        clean(timeout = 0.05)

        Removes all the buffered data from a tube by calling
        :meth:`pwnlib.tubes.tube.tube.recv` with a low timeout until it fails.

        If ``timeout`` is zero, only cached data will be cleared.

        Note: If timeout is set to zero, the underlying network is
        not actually polled; only the internal buffer is cleared.

        Returns:

            All data received

        Examples:

            >>> t = tube()
            >>> t.unrecv(b'clean me up')
            >>> t.clean(0)
            b'clean me up'
            >>> len(t.buffer)
            0
        """
        ...

    def clean_and_log(self, timeout=0.05):
        r"""
        clean_and_log(timeout = 0.05)

        Works exactly as :meth:`pwnlib.tubes.tube.tube.clean`, but logs received
        data with :meth:`pwnlib.self.info`.

        Returns:

            All data received

        Examples:

            >>> def recv(n, data=[b'', b'hooray_data']):
            ...     while data: return data.pop()
            >>> t = tube()
            >>> t.recv_raw      = recv
            >>> t.connected_raw = lambda d: True
            >>> t.fileno        = lambda: 1234
            >>> with context.local(log_level='info'):
            ...     data = t.clean_and_log() #doctest: +ELLIPSIS
            [DEBUG] Received 0xb bytes:
                b'hooray_data'
            >>> data
            b'hooray_data'
            >>> context.clear()
        """
        ...

    def close(self):
        r"""
        close()

        Closes the tube.
        """
        ...

    def connect_both(self, other):
        r"""
        connect_both(other)

        Connects the both ends of this tube object with another tube object.
        """
        ...

    def connect_input(self, other):
        r"""
        connect_input(other)

        Connects the input of this tube to the output of another tube object.


        Examples:

            >>> def p(x): print(x.decode())
            >>> def recvone(n, data=[b'data']):
            ...     while data: return data.pop()
            ...     raise EOFError
            >>> a = tube()
            >>> b = tube()
            >>> a.recv_raw = recvone
            >>> b.send_raw = p
            >>> a.connected_raw = lambda d: True
            >>> b.connected_raw = lambda d: True
            >>> a.shutdown      = lambda d: True
            >>> b.shutdown      = lambda d: True
            >>> import time
            >>> _=(b.connect_input(a), time.sleep(0.1))
            data
        """
        ...

    def connect_output(self, other):
        r"""
        connect_output(other)

        Connects the output of this tube to the input of another tube object.

        Examples:

            >>> def p(x): print(repr(x))
            >>> def recvone(n, data=[b'data']):
            ...     while data: return data.pop()
            ...     raise EOFError
            >>> a = tube()
            >>> b = tube()
            >>> a.recv_raw = recvone
            >>> b.send_raw = p
            >>> a.connected_raw = lambda d: True
            >>> b.connected_raw = lambda d: True
            >>> a.shutdown      = lambda d: True
            >>> b.shutdown      = lambda d: True
            >>> _=(a.connect_output(b), time.sleep(0.1))
            b'data'
        """
        ...

    def connected(self, direction='any'):
        r"""
        connected(direction = 'any') -> bool

        Returns True if the tube is connected in the specified direction.

        Arguments:
          direction(str): Can be the string 'any', 'in', 'read', 'recv',
                          'out', 'write', 'send'.

        Doctest:

            >>> def p(x): print(x)
            >>> t = tube()
            >>> t.connected_raw = p
            >>> _=list(map(t.connected, ('any', 'in', 'read', 'recv', 'out', 'write', 'send')))
            any
            recv
            recv
            recv
            send
            send
            send
            >>> t.connected('bad_value') #doctest: +ELLIPSIS
            Traceback (most recent call last):
            ...
            KeyError: "direction must be in ['any', 'in', 'out', 'read', 'recv', 'send', 'write']"
        """
        ...

    def connected_raw(self, direction):
        r"""
        connected(direction = 'any') -> bool

        Should not be called directly.  Returns True iff the
        tube is connected in the given direction.
        """
        ...

    def countdown(self, timeout=pwnlib.timeout.Timeout.default):
        r"""
        Scoped timeout setter.  Sets the timeout within the scope,
        and restores it when leaving the scope.

        When accessing :attr:`timeout` within the scope, it will be
        calculated against the time when the scope was entered, in a
        countdown fashion.

        If :const:`None` is specified for ``timeout``, then the current
        timeout is used is made.  This allows :const:`None` to be specified
        as a default argument with less complexity.
        """
        ...

    def countdown_active(self):

        ...

    def critical(self, message, *args, **kwargs):
        r"""
        critical(message, *args, **kwargs)

        Logs a critical message.
        """
        ...

    def debug(self, message, *args, **kwargs):
        r"""
        debug(message, *args, **kwargs)

        Logs a debug message.
        """
        ...

    def error(self, message, *args, **kwargs):
        r"""
        error(message, *args, **kwargs)

        To be called outside an exception handler.

        Logs an error message, then raises a ``PwnlibException``.
        """
        ...

    def exception(self, message, *args, **kwargs):
        r"""
        exception(message, *args, **kwargs)

        To be called from an exception handler.

        Logs a error message, then re-raises the current exception.
        """
        ...

    def failure(self, message, *args, **kwargs):
        r"""
        failure(message, *args, **kwargs)

        Logs a failure message.
        """
        ...

    def fileno(self):
        r"""
        fileno() -> int

        Returns the file number used for reading.
        """
        ...

    def fit(self, *a, **kw):

        ...

    def flat(self, *a, **kw):

        ...

    def hexdump(self, message, *args, **kwargs):

        ...

    def indented(self, message, *args, **kwargs):
        r"""
        indented(message, *args, level = logging.INFO, **kwargs)

        Log a message but don't put a line prefix on it.

        Arguments:
            level(int): Alternate log level at which to set the indented
                        message.  Defaults to :const:`logging.INFO`.
        """
        ...

    def info(self, message, *args, **kwargs):
        r"""
        info(message, *args, **kwargs)

        Logs an info message.
        """
        ...

    def info_once(self, message, *args, **kwargs):
        r"""
        info_once(message, *args, **kwargs)

        Logs an info message.  The same message is never printed again.
        """
        ...

    def interactive(self, prompt='\x1b[1m\x1b[31m$\x1b[m '):
        r"""
        interactive(prompt = pwnlib.term.text.bold_red('$') + ' ')

        Does simultaneous reading and writing to the tube. In principle this just
        connects the tube to standard in and standard out, but in practice this
        is much more usable, since we are using :mod:`pwnlib.term` to print a
        floating prompt.

        Thus it only works in while in :data:`pwnlib.term.term_mode`.
        """
        ...

    def isEnabledFor(self, level):
        r"""
        isEnabledFor(level) -> bool

        See if the underlying logger is enabled for the specified level.
        """
        ...

    def local(self, timeout):
        r"""
        Scoped timeout setter.  Sets the timeout within the scope,
        and restores it when leaving the scope.
        """
        ...

    def log(self, level, message, *args, **kwargs):
        r"""
        log(level, message, *args, **kwargs)

        Logs a message with log level `level`.  The ``pwnlib`` formatter will
        use the default :mod:`logging` formater to format this message.
        """
        ...

    def p16(self, *a, **kw):

        ...

    def p32(self, *a, **kw):

        ...

    def p64(self, *a, **kw):

        ...

    def p8(self, *a, **kw):

        ...

    def pack(self, *a, **kw):

        ...

    def progress(self, message, status='', *args, **kwargs):
        r"""
        progress(message, status = '', *args, level = logging.INFO, **kwargs) -> Progress

        Creates a new progress logger which creates log records with log level
        `level`.

        Progress status can be updated using :meth:`Progress.status` and stopped
        using :meth:`Progress.success` or :meth:`Progress.failure`.

        If `term.term_mode` is enabled the progress logger will be animated.

        The progress manager also functions as a context manager.  Using context
        managers ensures that animations stop even if an exception is raised.

        .. code-block:: python

           with log.progress('Trying something...') as p:
               for i in range(10):
                   p.status("At %i" % i)
                   time.sleep(0.5)
               x = 1/0
        """
        ...

    def read(self, *a, **kw):
        r"""
        Alias for :meth:`recv`
        """
        ...

    def readS(self, *a, **kw):
        r"""
        Alias for :meth:`recvS`
        """
        ...

    def read_raw(self, *a, **kw):
        r"""
        Alias for :meth:`recv_raw`
        """
        ...

    def readall(self, *a, **kw):
        r"""
        Alias for :meth:`recvall`
        """
        ...

    def readallS(self, *a, **kw):
        r"""
        Alias for :meth:`recvallS`
        """
        ...

    def readallb(self, *a, **kw):
        r"""
        Alias for :meth:`recvallb`
        """
        ...

    def readb(self, *a, **kw):
        r"""
        Alias for :meth:`recvb`
        """
        ...

    def readline(self, *a, **kw):
        r"""
        Alias for :meth:`recvline`
        """
        ...

    def readlineS(self, *a, **kw):
        r"""
        Alias for :meth:`recvlineS`
        """
        ...

    def readline_contains(self, *a, **kw):
        r"""
        Alias for :meth:`recvline_contains`
        """
        ...

    def readline_containsS(self, *a, **kw):
        r"""
        Alias for :meth:`recvline_containsS`
        """
        ...

    def readline_containsb(self, *a, **kw):
        r"""
        Alias for :meth:`recvline_containsb`
        """
        ...

    def readline_endswith(self, *a, **kw):
        r"""
        Alias for :meth:`recvline_endswith`
        """
        ...

    def readline_endswithS(self, *a, **kw):
        r"""
        Alias for :meth:`recvline_endswithS`
        """
        ...

    def readline_endswithb(self, *a, **kw):
        r"""
        Alias for :meth:`recvline_endswithb`
        """
        ...

    def readline_pred(self, *a, **kw):
        r"""
        Alias for :meth:`recvline_pred`
        """
        ...

    def readline_regex(self, *a, **kw):
        r"""
        Alias for :meth:`recvline_regex`
        """
        ...

    def readline_regexS(self, *a, **kw):
        r"""
        Alias for :meth:`recvline_regexS`
        """
        ...

    def readline_regexb(self, *a, **kw):
        r"""
        Alias for :meth:`recvline_regexb`
        """
        ...

    def readline_startswith(self, *a, **kw):
        r"""
        Alias for :meth:`recvline_startswith`
        """
        ...

    def readline_startswithS(self, *a, **kw):
        r"""
        Alias for :meth:`recvline_startswithS`
        """
        ...

    def readline_startswithb(self, *a, **kw):
        r"""
        Alias for :meth:`recvline_startswithb`
        """
        ...

    def readlineb(self, *a, **kw):
        r"""
        Alias for :meth:`recvlineb`
        """
        ...

    def readlines(self, *a, **kw):
        r"""
        Alias for :meth:`recvlines`
        """
        ...

    def readlinesS(self, *a, **kw):
        r"""
        Alias for :meth:`recvlinesS`
        """
        ...

    def readlinesb(self, *a, **kw):
        r"""
        Alias for :meth:`recvlinesb`
        """
        ...

    def readn(self, *a, **kw):
        r"""
        Alias for :meth:`recvn`
        """
        ...

    def readnS(self, *a, **kw):
        r"""
        Alias for :meth:`recvnS`
        """
        ...

    def readnb(self, *a, **kw):
        r"""
        Alias for :meth:`recvnb`
        """
        ...

    def readpred(self, *a, **kw):
        r"""
        Alias for :meth:`recvpred`
        """
        ...

    def readpredS(self, *a, **kw):
        r"""
        Alias for :meth:`recvpredS`
        """
        ...

    def readpredb(self, *a, **kw):
        r"""
        Alias for :meth:`recvpredb`
        """
        ...

    def readregex(self, *a, **kw):
        r"""
        Alias for :meth:`recvregex`
        """
        ...

    def readregexS(self, *a, **kw):
        r"""
        Alias for :meth:`recvregexS`
        """
        ...

    def readregexb(self, *a, **kw):
        r"""
        Alias for :meth:`recvregexb`
        """
        ...

    def readrepeat(self, *a, **kw):
        r"""
        Alias for :meth:`recvrepeat`
        """
        ...

    def readrepeatS(self, *a, **kw):
        r"""
        Alias for :meth:`recvrepeatS`
        """
        ...

    def readrepeatb(self, *a, **kw):
        r"""
        Alias for :meth:`recvrepeatb`
        """
        ...

    def readuntil(self, *a, **kw):
        r"""
        Alias for :meth:`recvuntil`
        """
        ...

    def readuntilS(self, *a, **kw):
        r"""
        Alias for :meth:`recvuntilS`
        """
        ...

    def readuntilb(self, *a, **kw):
        r"""
        Alias for :meth:`recvuntilb`
        """
        ...

    def recv(self, numb=None, timeout=pwnlib.timeout.Timeout.default):
        r"""
        recv(numb = 4096, timeout = default) -> bytes

        Receives up to `numb` bytes of data from the tube, and returns
        as soon as any quantity of data is available.

        If the request is not satisfied before ``timeout`` seconds pass,
        all data is buffered and an empty string (``''``) is returned.

        Raises:
            exceptions.EOFError: The connection is closed

        Returns:
            A bytes object containing bytes received from the socket,
            or ``''`` if a timeout occurred while waiting.

        Examples:

            >>> t = tube()
            >>> # Fake a data source
            >>> t.recv_raw = lambda n: b'Hello, world'
            >>> t.recv() == b'Hello, world'
            True
            >>> t.unrecv(b'Woohoo')
            >>> t.recv() == b'Woohoo'
            True
            >>> with context.local(log_level='debug'):
            ...    _ = t.recv() # doctest: +ELLIPSIS
            [...] Received 0xc bytes:
                b'Hello, world'
        """
        ...

    def recvS(self, *a, **kw):
        r"""
        Same as :meth:`recv`, but returns a str, decoding the result using `context.encoding`. (note that the binary versions are way faster)
        """
        ...

    def recv_raw(self, numb):
        r"""
        recv_raw(numb) -> str

        Should not be called directly. Receives data without using the buffer
        on the object.

        Unless there is a timeout or closed connection, this should always
        return data. In case of a timeout, it should return None, in case
        of a closed connection it should raise an ``exceptions.EOFError``.
        """
        ...

    def recvall(self, timeout=None):
        r"""
        recvall() -> bytes

        Receives data until EOF is reached.
        """
        ...

    def recvallS(self, *a, **kw):
        r"""
        Same as :meth:`recvall`, but returns a str, decoding the result using `context.encoding`. (note that the binary versions are way faster)
        """
        ...

    def recvallb(self, *a, **kw):
        r"""
        Same as :meth:`recvall`, but returns a bytearray
        """
        ...

    def recvb(self, *a, **kw):
        r"""
        Same as :meth:`recv`, but returns a bytearray
        """
        ...

    def recvline(self, keepends=True, timeout=pwnlib.timeout.Timeout.default):
        r"""
        recvline(keepends=True, timeout=default) -> bytes

        Receive a single line from the tube.

        A "line" is any sequence of bytes terminated by the byte sequence
        set in :attr:`newline`, which defaults to ``'\n'``.

        If the request is not satisfied before ``timeout`` seconds pass,
        all data is buffered and an empty string (``''``) is returned.

        Arguments:
            keepends(bool): Keep the line ending (:const:`True`).
            timeout(int): Timeout

        Return:
            All bytes received over the tube until the first
            newline ``'\n'`` is received.  Optionally retains
            the ending.

        Examples:

            >>> t = tube()
            >>> t.recv_raw = lambda n: b'Foo\nBar\r\nBaz\n'
            >>> t.recvline()
            b'Foo\n'
            >>> t.recvline()
            b'Bar\r\n'
            >>> t.recvline(keepends = False)
            b'Baz'
            >>> t.newline = b'\r\n'
            >>> t.recvline(keepends = False)
            b'Foo\nBar'
        """
        ...

    def recvlineS(self, *a, **kw):
        r"""
        Same as :meth:`recvline`, but returns a str, decoding the result using `context.encoding`. (note that the binary versions are way faster)
        """
        ...

    def recvline_contains(self, items, keepends=False, timeout=pwnlib.timeout.Timeout.default):
        r"""
        Receive lines until one line is found which contains at least
        one of `items`.

        Arguments:
            items(str,tuple): List of strings to search for, or a single string.
            keepends(bool): Return lines with newlines if :const:`True`
            timeout(int): Timeout, in seconds

        Examples:

            >>> t = tube()
            >>> t.recv_raw = lambda n: b"Hello\nWorld\nXylophone\n"
            >>> t.recvline_contains(b'r')
            b'World'
            >>> f = lambda n: b"cat dog bird\napple pear orange\nbicycle car train\n"
            >>> t = tube()
            >>> t.recv_raw = f
            >>> t.recvline_contains(b'pear')
            b'apple pear orange'
            >>> t = tube()
            >>> t.recv_raw = f
            >>> t.recvline_contains((b'car', b'train'))
            b'bicycle car train'
        """
        ...

    def recvline_containsS(self, *a, **kw):
        r"""
        Same as :meth:`recvline_contains`, but returns a str, decoding the result using `context.encoding`. (note that the binary versions are way faster)
        """
        ...

    def recvline_containsb(self, *a, **kw):
        r"""
        Same as :meth:`recvline_contains`, but returns a bytearray
        """
        ...

    def recvline_endswith(self, delims, keepends=False, timeout=pwnlib.timeout.Timeout.default):
        r"""
        recvline_endswith(delims, keepends=False, timeout=default) -> bytes

        Keep receiving lines until one is found that ends with one of
        `delims`.  Returns the last line received.

        If the request is not satisfied before ``timeout`` seconds pass,
        all data is buffered and an empty string (``''``) is returned.

        See :meth:`recvline_startswith` for more details.

        Examples:

            >>> t = tube()
            >>> t.recv_raw = lambda n: b'Foo\nBar\nBaz\nKaboodle\n'
            >>> t.recvline_endswith(b'r')
            b'Bar'
            >>> t.recvline_endswith((b'a',b'b',b'c',b'd',b'e'), True)
            b'Kaboodle\n'
            >>> t.recvline_endswith(b'oodle')
            b'Kaboodle'
        """
        ...

    def recvline_endswithS(self, *a, **kw):
        r"""
        Same as :meth:`recvline_endswith`, but returns a str, decoding the result using `context.encoding`. (note that the binary versions are way faster)
        """
        ...

    def recvline_endswithb(self, *a, **kw):
        r"""
        Same as :meth:`recvline_endswith`, but returns a bytearray
        """
        ...

    def recvline_pred(self, pred, keepends=False, timeout=pwnlib.timeout.Timeout.default):
        r"""
        recvline_pred(pred, keepends=False) -> bytes

        Receive data until ``pred(line)`` returns a truthy value.
        Drop all other data.

        If the request is not satisfied before ``timeout`` seconds pass,
        all data is buffered and an empty string (``''``) is returned.

        Arguments:
            pred(callable): Function to call.  Returns the line for which
                this function returns :const:`True`.

        Examples:

            >>> t = tube()
            >>> t.recv_raw = lambda n: b"Foo\nBar\nBaz\n"
            >>> t.recvline_pred(lambda line: line == b"Bar\n")
            b'Bar'
            >>> t.recvline_pred(lambda line: line == b"Bar\n", keepends=True)
            b'Bar\n'
            >>> t.recvline_pred(lambda line: line == b'Nope!', timeout=0.1)
            b''
        """
        ...

    def recvline_regex(self, regex, exact=False, keepends=False, timeout=pwnlib.timeout.Timeout.default):
        r"""
        recvline_regex(regex, exact=False, keepends=False, timeout=default) -> bytes

        Wrapper around :func:`recvline_pred`, which will return when a regex
        matches a line.

        By default :func:`re.RegexObject.search` is used, but if `exact` is
        set to True, then :func:`re.RegexObject.match` will be used instead.

        If the request is not satisfied before ``timeout`` seconds pass,
        all data is buffered and an empty string (``''``) is returned.
        """
        ...

    def recvline_regexS(self, *a, **kw):
        r"""
        Same as :meth:`recvline_regex`, but returns a str, decoding the result using `context.encoding`. (note that the binary versions are way faster)
        """
        ...

    def recvline_regexb(self, *a, **kw):
        r"""
        Same as :meth:`recvline_regex`, but returns a bytearray
        """
        ...

    def recvline_startswith(self, delims, keepends=False, timeout=pwnlib.timeout.Timeout.default):
        r"""
        recvline_startswith(delims, keepends=False, timeout=default) -> bytes

        Keep receiving lines until one is found that starts with one of
        `delims`.  Returns the last line received.

        If the request is not satisfied before ``timeout`` seconds pass,
        all data is buffered and an empty string (``''``) is returned.

        Arguments:
            delims(str,tuple): List of strings to search for, or string of single characters
            keepends(bool): Return lines with newlines if :const:`True`
            timeout(int): Timeout, in seconds

        Returns:
            The first line received which starts with a delimiter in ``delims``.

        Examples:

            >>> t = tube()
            >>> t.recv_raw = lambda n: b"Hello\nWorld\nXylophone\n"
            >>> t.recvline_startswith((b'W',b'X',b'Y',b'Z'))
            b'World'
            >>> t.recvline_startswith((b'W',b'X',b'Y',b'Z'), True)
            b'Xylophone\n'
            >>> t.recvline_startswith(b'Wo')
            b'World'
        """
        ...

    def recvline_startswithS(self, *a, **kw):
        r"""
        Same as :meth:`recvline_startswith`, but returns a str, decoding the result using `context.encoding`. (note that the binary versions are way faster)
        """
        ...

    def recvline_startswithb(self, *a, **kw):
        r"""
        Same as :meth:`recvline_startswith`, but returns a bytearray
        """
        ...

    def recvlineb(self, *a, **kw):
        r"""
        Same as :meth:`recvline`, but returns a bytearray
        """
        ...

    def recvlines(self, numlines=1048576, keepends=False, timeout=pwnlib.timeout.Timeout.default):
        r"""
        recvlines(numlines, keepends=False, timeout=default) -> list of bytes objects

        Receive up to ``numlines`` lines.

        A "line" is any sequence of bytes terminated by the byte sequence
        set by :attr:`newline`, which defaults to ``'\n'``.

        If the request is not satisfied before ``timeout`` seconds pass,
        all data is buffered and an empty string (``''``) is returned.

        Arguments:
            numlines(int): Maximum number of lines to receive
            keepends(bool): Keep newlines at the end of each line (:const:`False`).
            timeout(int): Maximum timeout

        Raises:
            exceptions.EOFError: The connection closed before the request could be satisfied

        Returns:
            A string containing bytes received from the socket,
            or ``''`` if a timeout occurred while waiting.

        Examples:

            >>> t = tube()
            >>> t.recv_raw = lambda n: b'\n'
            >>> t.recvlines(3)
            [b'', b'', b'']
            >>> t.recv_raw = lambda n: b'Foo\nBar\nBaz\n'
            >>> t.recvlines(3)
            [b'Foo', b'Bar', b'Baz']
            >>> t.recvlines(3, True)
            [b'Foo\n', b'Bar\n', b'Baz\n']
        """
        ...

    def recvlinesS(self, numlines=1048576, keepends=False, timeout=pwnlib.timeout.Timeout.default):
        r"""
        recvlinesS(numlines, keepends=False, timeout=default) -> str list

        This function is identical to :meth:`recvlines`, but decodes
        the received bytes into string using :func:`context.encoding`.
        You should use :meth:`recvlines` whenever possible for better performance.

        Examples:

            >>> t = tube()
            >>> t.recv_raw = lambda n: b'\n'
            >>> t.recvlinesS(3)
            ['', '', '']
            >>> t.recv_raw = lambda n: b'Foo\nBar\nBaz\n'
            >>> t.recvlinesS(3)
            ['Foo', 'Bar', 'Baz']
        """
        ...

    def recvlinesb(self, numlines=1048576, keepends=False, timeout=pwnlib.timeout.Timeout.default):
        r"""
        recvlinesb(numlines, keepends=False, timeout=default) -> bytearray list

        This function is identical to :meth:`recvlines`, but returns a bytearray.

        Examples:

            >>> t = tube()
            >>> t.recv_raw = lambda n: b'\n'
            >>> t.recvlinesb(3)
            [bytearray(b''), bytearray(b''), bytearray(b'')]
            >>> t.recv_raw = lambda n: b'Foo\nBar\nBaz\n'
            >>> t.recvlinesb(3)
            [bytearray(b'Foo'), bytearray(b'Bar'), bytearray(b'Baz')]
        """
        ...

    def recvn(self, numb, timeout=pwnlib.timeout.Timeout.default):
        r"""
        recvn(numb, timeout = default) -> str

        Receives exactly `n` bytes.

        If the request is not satisfied before ``timeout`` seconds pass,
        all data is buffered and an empty string (``''``) is returned.

        Raises:
            exceptions.EOFError: The connection closed before the request could be satisfied

        Returns:
            A string containing bytes received from the socket,
            or ``''`` if a timeout occurred while waiting.

        Examples:

            >>> t = tube()
            >>> data = b'hello world'
            >>> t.recv_raw = lambda *a: data
            >>> t.recvn(len(data)) == data
            True
            >>> t.recvn(len(data)+1) == data + data[:1]
            True
            >>> t.recv_raw = lambda *a: None
            >>> # The remaining data is buffered
            >>> t.recv() == data[1:]
            True
            >>> t.recv_raw = lambda *a: time.sleep(0.01) or b'a'
            >>> t.recvn(10, timeout=0.05)
            b''
            >>> t.recvn(10, timeout=0.06) # doctest: +ELLIPSIS
            b'aaaaaa...'
        """
        ...

    def recvnS(self, *a, **kw):
        r"""
        Same as :meth:`recvn`, but returns a str, decoding the result using `context.encoding`. (note that the binary versions are way faster)
        """
        ...

    def recvnb(self, *a, **kw):
        r"""
        Same as :meth:`recvn`, but returns a bytearray
        """
        ...

    def recvpred(self, pred, timeout=pwnlib.timeout.Timeout.default):
        r"""
        recvpred(pred, timeout = default) -> bytes

        Receives one byte at a time from the tube, until ``pred(all_bytes)``
        evaluates to True.

        If the request is not satisfied before ``timeout`` seconds pass,
        all data is buffered and an empty string (``''``) is returned.

        Arguments:
            pred(callable): Function to call, with the currently-accumulated data.
            timeout(int): Timeout for the operation

        Raises:
            exceptions.EOFError: The connection is closed

        Returns:
            A bytes object containing bytes received from the socket,
            or ``''`` if a timeout occurred while waiting.
        """
        ...

    def recvpredS(self, *a, **kw):
        r"""
        Same as :meth:`recvpred`, but returns a str, decoding the result using `context.encoding`. (note that the binary versions are way faster)
        """
        ...

    def recvpredb(self, *a, **kw):
        r"""
        Same as :meth:`recvpred`, but returns a bytearray
        """
        ...

    def recvregex(self, regex, exact=False, timeout=pwnlib.timeout.Timeout.default):
        r"""
        recvregex(regex, exact=False, timeout=default) -> bytes

        Wrapper around :func:`recvpred`, which will return when a regex
        matches the string in the buffer.

        By default :func:`re.RegexObject.search` is used, but if `exact` is
        set to True, then :func:`re.RegexObject.match` will be used instead.

        If the request is not satisfied before ``timeout`` seconds pass,
        all data is buffered and an empty string (``''``) is returned.
        """
        ...

    def recvregexS(self, *a, **kw):
        r"""
        Same as :meth:`recvregex`, but returns a str, decoding the result using `context.encoding`. (note that the binary versions are way faster)
        """
        ...

    def recvregexb(self, *a, **kw):
        r"""
        Same as :meth:`recvregex`, but returns a bytearray
        """
        ...

    def recvrepeat(self, timeout=pwnlib.timeout.Timeout.default):
        r"""
        recvrepeat(timeout=default) -> bytes

        Receives data until a timeout or EOF is reached.

        Examples:

            >>> data = [
            ... b'd',
            ... b'', # simulate timeout
            ... b'c',
            ... b'b',
            ... b'a',
            ... ]
            >>> def delayrecv(n, data=data):
            ...     return data.pop()
            >>> t = tube()
            >>> t.recv_raw = delayrecv
            >>> t.recvrepeat(0.2)
            b'abc'
            >>> t.recv()
            b'd'
        """
        ...

    def recvrepeatS(self, *a, **kw):
        r"""
        Same as :meth:`recvrepeat`, but returns a str, decoding the result using `context.encoding`. (note that the binary versions are way faster)
        """
        ...

    def recvrepeatb(self, *a, **kw):
        r"""
        Same as :meth:`recvrepeat`, but returns a bytearray
        """
        ...

    def recvuntil(self, delims, drop=False, timeout=pwnlib.timeout.Timeout.default):
        r"""
        recvuntil(delims, drop=False, timeout=default) -> bytes

        Receive data until one of `delims` is encountered.

        If the request is not satisfied before ``timeout`` seconds pass,
        all data is buffered and an empty string (``''``) is returned.

        arguments:
            delims(bytes,tuple): Byte-string of delimiters characters, or list of delimiter byte-strings.
            drop(bool): Drop the ending.  If :const:`True` it is removed from the end of the return value.

        Raises:
            exceptions.EOFError: The connection closed before the request could be satisfied

        Returns:
            A string containing bytes received from the socket,
            or ``''`` if a timeout occurred while waiting.

        Examples:

            >>> t = tube()
            >>> t.recv_raw = lambda n: b"Hello World!"
            >>> t.recvuntil(b' ')
            b'Hello '
            >>> _=t.clean(0)
            >>> # Matches on 'o' in 'Hello'
            >>> t.recvuntil((b' ',b'W',b'o',b'r'))
            b'Hello'
            >>> _=t.clean(0)
            >>> # Matches expressly full string
            >>> t.recvuntil(b' Wor')
            b'Hello Wor'
            >>> _=t.clean(0)
            >>> # Matches on full string, drops match
            >>> t.recvuntil(b' Wor', drop=True)
            b'Hello'

            >>> # Try with regex special characters
            >>> t = tube()
            >>> t.recv_raw = lambda n: b"Hello|World"
            >>> t.recvuntil(b'|', drop=True)
            b'Hello'
        """
        ...

    def recvuntilS(self, *a, **kw):
        r"""
        Same as :meth:`recvuntil`, but returns a str, decoding the result using `context.encoding`. (note that the binary versions are way faster)
        """
        ...

    def recvuntilb(self, *a, **kw):
        r"""
        Same as :meth:`recvuntil`, but returns a bytearray
        """
        ...

    def removeHandler(self, handler):
        r"""
        removeHandler(handler)

        Remove the specified handler from the underlying logger.
        """
        ...

    def send(self, data):
        r"""
        send(data)

        Sends data.

        If log level ``DEBUG`` is enabled, also prints out the data
        received.

        If it is not possible to send anymore because of a closed
        connection, it raises ``exceptions.EOFError``

        Examples:

            >>> def p(x): print(repr(x))
            >>> t = tube()
            >>> t.send_raw = p
            >>> t.send(b'hello')
            b'hello'
        """
        ...

    def send_raw(self, data):
        r"""
        send_raw(data)

        Should not be called directly. Sends data to the tube.

        Should return ``exceptions.EOFError``, if it is unable to send any
        more, because of a close tube.
        """
        ...

    def sendafter(self, delim, data, timeout=pwnlib.timeout.Timeout.default):
        r"""
        sendafter(delim, data, timeout = default) -> str

        A combination of ``recvuntil(delim, timeout=timeout)`` and ``send(data)``.
        """
        ...

    def sendline(self, line=b''):
        r"""
        sendline(data)

        Shorthand for ``t.send(data + t.newline)``.

        Examples:

            >>> def p(x): print(repr(x))
            >>> t = tube()
            >>> t.send_raw = p
            >>> t.sendline(b'hello')
            b'hello\n'
            >>> t.newline = b'\r\n'
            >>> t.sendline(b'hello')
            b'hello\r\n'
        """
        ...

    def sendlineafter(self, delim, data, timeout=pwnlib.timeout.Timeout.default):
        r"""
        sendlineafter(delim, data, timeout = default) -> str

        A combination of ``recvuntil(delim, timeout=timeout)`` and ``sendline(data)``.
        """
        ...

    def sendlines(self, lines=[]):

        ...

    def sendlinethen(self, delim, data, timeout=pwnlib.timeout.Timeout.default):
        r"""
        sendlinethen(delim, data, timeout = default) -> str

        A combination of ``sendline(data)`` and ``recvuntil(delim, timeout=timeout)``.
        """
        ...

    def sendthen(self, delim, data, timeout=pwnlib.timeout.Timeout.default):
        r"""
        sendthen(delim, data, timeout = default) -> str

        A combination of ``send(data)`` and ``recvuntil(delim, timeout=timeout)``.
        """
        ...

    def setLevel(self, level):
        r"""
        setLevel(level)

        Set the logging level for the underlying logger.
        """
        ...

    def settimeout(self, timeout):
        r"""
        settimeout(timeout)

        Set the timeout for receiving operations. If the string "default"
        is given, then :data:`context.timeout` will be used. If None is given,
        then there will be no timeout.

        Examples:

            >>> t = tube()
            >>> t.settimeout_raw = lambda t: None
            >>> t.settimeout(3)
            >>> t.timeout == 3
            True
        """
        ...

    def settimeout_raw(self, timeout):
        r"""
        settimeout_raw(timeout)

        Should not be called directly. Sets the timeout for
        the tube.
        """
        ...

    def shutdown(self, direction='send'):
        r"""
        shutdown(direction = "send")

        Closes the tube for futher reading or writing depending on `direction`.

        Arguments:
          direction(str): Which direction to close; "in", "read" or "recv"
            closes the tube in the ingoing direction, "out", "write" or "send"
            closes it in the outgoing direction.

        Returns:
          :const:`None`

        Examples:

            >>> def p(x): print(x)
            >>> t = tube()
            >>> t.shutdown_raw = p
            >>> _=list(map(t.shutdown, ('in', 'read', 'recv', 'out', 'write', 'send')))
            recv
            recv
            recv
            send
            send
            send
            >>> t.shutdown('bad_value') #doctest: +ELLIPSIS
            Traceback (most recent call last):
            ...
            KeyError: "direction must be in ['in', 'out', 'read', 'recv', 'send', 'write']"
        """
        ...

    def shutdown_raw(self, direction):
        r"""
        shutdown_raw(direction)

        Should not be called directly.  Closes the tube for further reading or
        writing.
        """
        ...

    def spawn_process(self, *args, **kwargs):
        r"""
        Spawns a new process having this tube as stdin, stdout and stderr.

        Takes the same arguments as :class:`subprocess.Popen`.
        """
        ...

    def stream(self, line_mode=True):
        r"""
        stream()

        Receive data until the tube exits, and print it to stdout.

        Similar to :func:`interactive`, except that no input is sent.

        Similar to ``print(tube.recvall())`` except that data is printed
        as it is received, rather than after all data is received.

        Arguments:
            line_mode(bool): Whether to receive line-by-line or raw data.

        Returns:
            All data printed.
        """
        ...

    def success(self, message, *args, **kwargs):
        r"""
        success(message, *args, **kwargs)

        Logs a success message.
        """
        ...

    def timeout_change(self):
        r"""
        Informs the raw layer of the tube that the timeout has changed.

        Should not be called directly.

        Inherited from :class:`Timeout`.
        """
        ...

    def u16(self, *a, **kw):

        ...

    def u32(self, *a, **kw):

        ...

    def u64(self, *a, **kw):

        ...

    def u8(self, *a, **kw):

        ...

    def unpack(self, *a, **kw):

        ...

    def unread(self, *a, **kw):
        r"""
        Alias for :meth:`unrecv`
        """
        ...

    def unrecv(self, data):
        r"""
        unrecv(data)

        Puts the specified data back at the beginning of the receive
        buffer.

        Examples:

            >>> t = tube()
            >>> t.recv_raw = lambda n: b'hello'
            >>> t.recv()
            b'hello'
            >>> t.recv()
            b'hello'
            >>> t.unrecv(b'world')
            >>> t.recv()
            b'world'
            >>> t.recv()
            b'hello'
        """
        ...

    def wait(self, timeout=pwnlib.timeout.Timeout.default):
        r"""
        Waits until the tube is closed.
        """
        ...

    def wait_for_close(self, timeout=pwnlib.timeout.Timeout.default):
        r"""
        Waits until the tube is closed.
        """
        ...

    def waitfor(self, *args, **kwargs):
        r"""
        Alias for :meth:`progress`.
        """
        ...

    def warn(self, *args, **kwargs):
        r"""
        Alias for :meth:`warning`.
        """
        ...

    def warn_once(self, *args, **kwargs):
        r"""
        Alias for :meth:`warning_once`.
        """
        ...

    def warning(self, message, *args, **kwargs):
        r"""
        warning(message, *args, **kwargs)

        Logs a warning message.
        """
        ...

    def warning_once(self, message, *args, **kwargs):
        r"""
        warning_once(message, *args, **kwargs)

        Logs a warning message.  The same message is never printed again.
        """
        ...

    def write(self, *a, **kw):
        r"""
        Alias for :meth:`send`
        """
        ...

    def write_raw(self, *a, **kw):
        r"""
        Alias for :meth:`send_raw`
        """
        ...

    def writeafter(self, *a, **kw):
        r"""
        Alias for :meth:`sendafter`
        """
        ...

    def writeline(self, *a, **kw):
        r"""
        Alias for :meth:`sendline`
        """
        ...

    def writelineafter(self, *a, **kw):
        r"""
        Alias for :meth:`sendlineafter`
        """
        ...

    def writelines(self, *a, **kw):
        r"""
        Alias for :meth:`sendlines`
        """
        ...

    def writelinethen(self, *a, **kw):
        r"""
        Alias for :meth:`sendlinethen`
        """
        ...

    def writethen(self, *a, **kw):
        r"""
        Alias for :meth:`sendthen`
        """
        ...


import pwnlib.tubes.server

class server (pwnlib.tubes.sock.sock):
    r"""
    Creates an TCP or UDP-server to listen for connections. It supports
    both IPv4 and IPv6.

    Arguments:
        port(int): The port to connect to.
            Defaults to a port auto-selected by the operating system.
        bindaddr(str): The address to bind to.
            Defaults to ``0.0.0.0`` / `::`.
        fam: The string "any", "ipv4" or "ipv6" or an integer to pass to :func:`socket.getaddrinfo`.
        typ: The string "tcp" or "udp" or an integer to pass to :func:`socket.getaddrinfo`.
        callback: A function to be started on incoming connections. It should take a :class:`pwnlib.tubes.remote` as its only argument.

    Examples:

        >>> s = server(8888)
        >>> client_conn = remote('localhost', s.lport)
        >>> server_conn = s.next_connection()
        >>> client_conn.sendline(b'Hello')
        >>> server_conn.recvline()
        b'Hello\n'
        >>> def cb(r):
        ...     client_input = r.readline()
        ...     r.send(client_input[::-1])
        ...
        >>> t = server(8889, callback=cb)
        >>> client_conn = remote('localhost', t.lport)
        >>> client_conn.sendline(b'callback')
        >>> client_conn.recv()
        b'\nkcabllac'
    """
    def __enter__(self):
        r"""
        Permit use of 'with' to control scoping and closing sessions.

        Examples:

            >>> t = tube()
            >>> def p(x): print(x)
            >>> t.close = lambda: p("Closed!")
            >>> with t: pass
            Closed!
        """
        ...

    def __exit__(self, type, value, traceback):
        r"""
        Handles closing for 'with' statement

        See :meth:`__enter__`
        """
        ...

    def __init__(self, port=0, bindaddr='::', fam='any', typ='tcp', callback=None, blocking=False, *args, **kwargs):
        r"""
        Initialize self.  See help(type(self)) for accurate signature.
        """
        ...

    def __lshift__(self, other):
        r"""
        Shorthand for connecting multiple tubes.

        See :meth:`connect_input` for more information.

        Examples:

            The following are equivalent ::

                tube_a >> tube.b
                tube_a.connect_input(tube_b)

            This is useful when chaining multiple tubes ::

                tube_a >> tube_b >> tube_a
                tube_a.connect_input(tube_b)
                tube_b.connect_input(tube_a)
        """
        ...

    def __ne__(self, other):
        r"""
        Shorthand for connecting tubes to eachother.

        The following are equivalent ::

            a >> b >> a
            a <> b

        See :meth:`connect_input` for more information.
        """
        ...

    def __rshift__(self, other):
        r"""
        Inverse of the ``<<`` operator.  See :meth:`__lshift__`.

        See :meth:`connect_input` for more information.
        """
        ...

    def _close_msg(self):

        ...

    def _fillbuffer(self, timeout=pwnlib.timeout.Timeout.default):
        r"""
        _fillbuffer(timeout = default)

        Fills the internal buffer from the pipe, by calling
        :meth:`recv_raw` exactly once.

        Returns:

            The bytes of data received, or ``''`` if no data was received.

        Examples:

            >>> t = tube()
            >>> t.recv_raw = lambda *a: b'abc'
            >>> len(t.buffer)
            0
            >>> t._fillbuffer()
            b'abc'
            >>> len(t.buffer)
            3
        """
        ...

    def _get_timeout_seconds(self, value):

        ...

    def _getlevel(self, levelString):

        ...

    def _log(self, level, msg, args, kwargs, msgtype, progress=None):

        ...

    def _read(self, *a, **kw):
        r"""
        Alias for :meth:`_recv`
        """
        ...

    def _recv(self, numb=None, timeout=pwnlib.timeout.Timeout.default):
        r"""
        _recv(numb = 4096, timeout = default) -> str

        Receives one chunk of from the internal buffer or from the OS if the
        buffer is empty.
        """
        ...

    def addHandler(self, handler):
        r"""
        addHandler(handler)

        Add the specified handler to the underlying logger.
        """
        ...

    def can_read(self, *a, **kw):
        r"""
        Alias for :meth:`can_recv`
        """
        ...

    def can_read_raw(self, *a, **kw):
        r"""
        Alias for :meth:`can_recv_raw`
        """
        ...

    def can_recv(self, timeout=0):
        r"""
        can_recv(timeout = 0) -> bool

        Returns True, if there is data available within `timeout` seconds.

        Examples:

            >>> import time
            >>> t = tube()
            >>> t.can_recv_raw = lambda *a: False
            >>> t.can_recv()
            False
            >>> _=t.unrecv(b'data')
            >>> t.can_recv()
            True
            >>> _=t.recv()
            >>> t.can_recv()
            False
        """
        ...

    def can_recv_raw(self, timeout):
        r"""
        Tests:

            >>> l = listen()
            >>> r = remote('localhost', l.lport)
            >>> r.can_recv_raw(timeout=0)
            False
            >>> l.send(b'a')
            >>> r.can_recv_raw(timeout=1)
            True
            >>> r.recv()
            b'a'
            >>> r.can_recv_raw(timeout=0)
            False
            >>> l.close()
            >>> r.can_recv_raw(timeout=1)
            False
            >>> r.closed['recv']
            True
        """
        ...

    def clean(self, timeout=0.05):
        r"""
        clean(timeout = 0.05)

        Removes all the buffered data from a tube by calling
        :meth:`pwnlib.tubes.tube.tube.recv` with a low timeout until it fails.

        If ``timeout`` is zero, only cached data will be cleared.

        Note: If timeout is set to zero, the underlying network is
        not actually polled; only the internal buffer is cleared.

        Returns:

            All data received

        Examples:

            >>> t = tube()
            >>> t.unrecv(b'clean me up')
            >>> t.clean(0)
            b'clean me up'
            >>> len(t.buffer)
            0
        """
        ...

    def clean_and_log(self, timeout=0.05):
        r"""
        clean_and_log(timeout = 0.05)

        Works exactly as :meth:`pwnlib.tubes.tube.tube.clean`, but logs received
        data with :meth:`pwnlib.self.info`.

        Returns:

            All data received

        Examples:

            >>> def recv(n, data=[b'', b'hooray_data']):
            ...     while data: return data.pop()
            >>> t = tube()
            >>> t.recv_raw      = recv
            >>> t.connected_raw = lambda d: True
            >>> t.fileno        = lambda: 1234
            >>> with context.local(log_level='info'):
            ...     data = t.clean_and_log() #doctest: +ELLIPSIS
            [DEBUG] Received 0xb bytes:
                b'hooray_data'
            >>> data
            b'hooray_data'
            >>> context.clear()
        """
        ...

    def close(self):
        r"""
        close()

        Closes the tube.
        """
        ...

    def connect_both(self, other):
        r"""
        connect_both(other)

        Connects the both ends of this tube object with another tube object.
        """
        ...

    def connect_input(self, other):
        r"""
        connect_input(other)

        Connects the input of this tube to the output of another tube object.


        Examples:

            >>> def p(x): print(x.decode())
            >>> def recvone(n, data=[b'data']):
            ...     while data: return data.pop()
            ...     raise EOFError
            >>> a = tube()
            >>> b = tube()
            >>> a.recv_raw = recvone
            >>> b.send_raw = p
            >>> a.connected_raw = lambda d: True
            >>> b.connected_raw = lambda d: True
            >>> a.shutdown      = lambda d: True
            >>> b.shutdown      = lambda d: True
            >>> import time
            >>> _=(b.connect_input(a), time.sleep(0.1))
            data
        """
        ...

    def connect_output(self, other):
        r"""
        connect_output(other)

        Connects the output of this tube to the input of another tube object.

        Examples:

            >>> def p(x): print(repr(x))
            >>> def recvone(n, data=[b'data']):
            ...     while data: return data.pop()
            ...     raise EOFError
            >>> a = tube()
            >>> b = tube()
            >>> a.recv_raw = recvone
            >>> b.send_raw = p
            >>> a.connected_raw = lambda d: True
            >>> b.connected_raw = lambda d: True
            >>> a.shutdown      = lambda d: True
            >>> b.shutdown      = lambda d: True
            >>> _=(a.connect_output(b), time.sleep(0.1))
            b'data'
        """
        ...

    def connected(self, direction='any'):
        r"""
        connected(direction = 'any') -> bool

        Returns True if the tube is connected in the specified direction.

        Arguments:
          direction(str): Can be the string 'any', 'in', 'read', 'recv',
                          'out', 'write', 'send'.

        Doctest:

            >>> def p(x): print(x)
            >>> t = tube()
            >>> t.connected_raw = p
            >>> _=list(map(t.connected, ('any', 'in', 'read', 'recv', 'out', 'write', 'send')))
            any
            recv
            recv
            recv
            send
            send
            send
            >>> t.connected('bad_value') #doctest: +ELLIPSIS
            Traceback (most recent call last):
            ...
            KeyError: "direction must be in ['any', 'in', 'out', 'read', 'recv', 'send', 'write']"
        """
        ...

    def connected_raw(self, direction):
        r"""
        Tests:

            >>> l = listen()
            >>> r = remote('localhost', l.lport)
            >>> r.connected()
            True
            >>> l.close()
            >>> time.sleep(0.1) # Avoid race condition
            >>> r.connected()
            False
        """
        ...

    def countdown(self, timeout=pwnlib.timeout.Timeout.default):
        r"""
        Scoped timeout setter.  Sets the timeout within the scope,
        and restores it when leaving the scope.

        When accessing :attr:`timeout` within the scope, it will be
        calculated against the time when the scope was entered, in a
        countdown fashion.

        If :const:`None` is specified for ``timeout``, then the current
        timeout is used is made.  This allows :const:`None` to be specified
        as a default argument with less complexity.
        """
        ...

    def countdown_active(self):

        ...

    def critical(self, message, *args, **kwargs):
        r"""
        critical(message, *args, **kwargs)

        Logs a critical message.
        """
        ...

    def debug(self, message, *args, **kwargs):
        r"""
        debug(message, *args, **kwargs)

        Logs a debug message.
        """
        ...

    def error(self, message, *args, **kwargs):
        r"""
        error(message, *args, **kwargs)

        To be called outside an exception handler.

        Logs an error message, then raises a ``PwnlibException``.
        """
        ...

    def exception(self, message, *args, **kwargs):
        r"""
        exception(message, *args, **kwargs)

        To be called from an exception handler.

        Logs a error message, then re-raises the current exception.
        """
        ...

    def failure(self, message, *args, **kwargs):
        r"""
        failure(message, *args, **kwargs)

        Logs a failure message.
        """
        ...

    def fileno(self):
        r"""
        fileno() -> int

        Returns the file number used for reading.
        """
        ...

    def fit(self, *a, **kw):

        ...

    def flat(self, *a, **kw):

        ...

    def hexdump(self, message, *args, **kwargs):

        ...

    def indented(self, message, *args, **kwargs):
        r"""
        indented(message, *args, level = logging.INFO, **kwargs)

        Log a message but don't put a line prefix on it.

        Arguments:
            level(int): Alternate log level at which to set the indented
                        message.  Defaults to :const:`logging.INFO`.
        """
        ...

    def info(self, message, *args, **kwargs):
        r"""
        info(message, *args, **kwargs)

        Logs an info message.
        """
        ...

    def info_once(self, message, *args, **kwargs):
        r"""
        info_once(message, *args, **kwargs)

        Logs an info message.  The same message is never printed again.
        """
        ...

    def interactive(self, prompt='\x1b[1m\x1b[31m$\x1b[m '):
        r"""
        interactive(prompt = pwnlib.term.text.bold_red('$') + ' ')

        Does simultaneous reading and writing to the tube. In principle this just
        connects the tube to standard in and standard out, but in practice this
        is much more usable, since we are using :mod:`pwnlib.term` to print a
        floating prompt.

        Thus it only works in while in :data:`pwnlib.term.term_mode`.
        """
        ...

    def isEnabledFor(self, level):
        r"""
        isEnabledFor(level) -> bool

        See if the underlying logger is enabled for the specified level.
        """
        ...

    def local(self, timeout):
        r"""
        Scoped timeout setter.  Sets the timeout within the scope,
        and restores it when leaving the scope.
        """
        ...

    def log(self, level, message, *args, **kwargs):
        r"""
        log(level, message, *args, **kwargs)

        Logs a message with log level `level`.  The ``pwnlib`` formatter will
        use the default :mod:`logging` formater to format this message.
        """
        ...

    def next_connection(self):

        ...

    def p16(self, *a, **kw):

        ...

    def p32(self, *a, **kw):

        ...

    def p64(self, *a, **kw):

        ...

    def p8(self, *a, **kw):

        ...

    def pack(self, *a, **kw):

        ...

    def progress(self, message, status='', *args, **kwargs):
        r"""
        progress(message, status = '', *args, level = logging.INFO, **kwargs) -> Progress

        Creates a new progress logger which creates log records with log level
        `level`.

        Progress status can be updated using :meth:`Progress.status` and stopped
        using :meth:`Progress.success` or :meth:`Progress.failure`.

        If `term.term_mode` is enabled the progress logger will be animated.

        The progress manager also functions as a context manager.  Using context
        managers ensures that animations stop even if an exception is raised.

        .. code-block:: python

           with log.progress('Trying something...') as p:
               for i in range(10):
                   p.status("At %i" % i)
                   time.sleep(0.5)
               x = 1/0
        """
        ...

    def read(self, *a, **kw):
        r"""
        Alias for :meth:`recv`
        """
        ...

    def readS(self, *a, **kw):
        r"""
        Alias for :meth:`recvS`
        """
        ...

    def read_raw(self, *a, **kw):
        r"""
        Alias for :meth:`recv_raw`
        """
        ...

    def readall(self, *a, **kw):
        r"""
        Alias for :meth:`recvall`
        """
        ...

    def readallS(self, *a, **kw):
        r"""
        Alias for :meth:`recvallS`
        """
        ...

    def readallb(self, *a, **kw):
        r"""
        Alias for :meth:`recvallb`
        """
        ...

    def readb(self, *a, **kw):
        r"""
        Alias for :meth:`recvb`
        """
        ...

    def readline(self, *a, **kw):
        r"""
        Alias for :meth:`recvline`
        """
        ...

    def readlineS(self, *a, **kw):
        r"""
        Alias for :meth:`recvlineS`
        """
        ...

    def readline_contains(self, *a, **kw):
        r"""
        Alias for :meth:`recvline_contains`
        """
        ...

    def readline_containsS(self, *a, **kw):
        r"""
        Alias for :meth:`recvline_containsS`
        """
        ...

    def readline_containsb(self, *a, **kw):
        r"""
        Alias for :meth:`recvline_containsb`
        """
        ...

    def readline_endswith(self, *a, **kw):
        r"""
        Alias for :meth:`recvline_endswith`
        """
        ...

    def readline_endswithS(self, *a, **kw):
        r"""
        Alias for :meth:`recvline_endswithS`
        """
        ...

    def readline_endswithb(self, *a, **kw):
        r"""
        Alias for :meth:`recvline_endswithb`
        """
        ...

    def readline_pred(self, *a, **kw):
        r"""
        Alias for :meth:`recvline_pred`
        """
        ...

    def readline_regex(self, *a, **kw):
        r"""
        Alias for :meth:`recvline_regex`
        """
        ...

    def readline_regexS(self, *a, **kw):
        r"""
        Alias for :meth:`recvline_regexS`
        """
        ...

    def readline_regexb(self, *a, **kw):
        r"""
        Alias for :meth:`recvline_regexb`
        """
        ...

    def readline_startswith(self, *a, **kw):
        r"""
        Alias for :meth:`recvline_startswith`
        """
        ...

    def readline_startswithS(self, *a, **kw):
        r"""
        Alias for :meth:`recvline_startswithS`
        """
        ...

    def readline_startswithb(self, *a, **kw):
        r"""
        Alias for :meth:`recvline_startswithb`
        """
        ...

    def readlineb(self, *a, **kw):
        r"""
        Alias for :meth:`recvlineb`
        """
        ...

    def readlines(self, *a, **kw):
        r"""
        Alias for :meth:`recvlines`
        """
        ...

    def readlinesS(self, *a, **kw):
        r"""
        Alias for :meth:`recvlinesS`
        """
        ...

    def readlinesb(self, *a, **kw):
        r"""
        Alias for :meth:`recvlinesb`
        """
        ...

    def readn(self, *a, **kw):
        r"""
        Alias for :meth:`recvn`
        """
        ...

    def readnS(self, *a, **kw):
        r"""
        Alias for :meth:`recvnS`
        """
        ...

    def readnb(self, *a, **kw):
        r"""
        Alias for :meth:`recvnb`
        """
        ...

    def readpred(self, *a, **kw):
        r"""
        Alias for :meth:`recvpred`
        """
        ...

    def readpredS(self, *a, **kw):
        r"""
        Alias for :meth:`recvpredS`
        """
        ...

    def readpredb(self, *a, **kw):
        r"""
        Alias for :meth:`recvpredb`
        """
        ...

    def readregex(self, *a, **kw):
        r"""
        Alias for :meth:`recvregex`
        """
        ...

    def readregexS(self, *a, **kw):
        r"""
        Alias for :meth:`recvregexS`
        """
        ...

    def readregexb(self, *a, **kw):
        r"""
        Alias for :meth:`recvregexb`
        """
        ...

    def readrepeat(self, *a, **kw):
        r"""
        Alias for :meth:`recvrepeat`
        """
        ...

    def readrepeatS(self, *a, **kw):
        r"""
        Alias for :meth:`recvrepeatS`
        """
        ...

    def readrepeatb(self, *a, **kw):
        r"""
        Alias for :meth:`recvrepeatb`
        """
        ...

    def readuntil(self, *a, **kw):
        r"""
        Alias for :meth:`recvuntil`
        """
        ...

    def readuntilS(self, *a, **kw):
        r"""
        Alias for :meth:`recvuntilS`
        """
        ...

    def readuntilb(self, *a, **kw):
        r"""
        Alias for :meth:`recvuntilb`
        """
        ...

    def recv(self, numb=None, timeout=pwnlib.timeout.Timeout.default):
        r"""
        recv(numb = 4096, timeout = default) -> bytes

        Receives up to `numb` bytes of data from the tube, and returns
        as soon as any quantity of data is available.

        If the request is not satisfied before ``timeout`` seconds pass,
        all data is buffered and an empty string (``''``) is returned.

        Raises:
            exceptions.EOFError: The connection is closed

        Returns:
            A bytes object containing bytes received from the socket,
            or ``''`` if a timeout occurred while waiting.

        Examples:

            >>> t = tube()
            >>> # Fake a data source
            >>> t.recv_raw = lambda n: b'Hello, world'
            >>> t.recv() == b'Hello, world'
            True
            >>> t.unrecv(b'Woohoo')
            >>> t.recv() == b'Woohoo'
            True
            >>> with context.local(log_level='debug'):
            ...    _ = t.recv() # doctest: +ELLIPSIS
            [...] Received 0xc bytes:
                b'Hello, world'
        """
        ...

    def recvS(self, *a, **kw):
        r"""
        Same as :meth:`recv`, but returns a str, decoding the result using `context.encoding`. (note that the binary versions are way faster)
        """
        ...

    def recv_raw(self, numb, *a):
        r"""
        recv_raw(numb) -> str

        Should not be called directly. Receives data without using the buffer
        on the object.

        Unless there is a timeout or closed connection, this should always
        return data. In case of a timeout, it should return None, in case
        of a closed connection it should raise an ``exceptions.EOFError``.
        """
        ...

    def recvall(self, timeout=None):
        r"""
        recvall() -> str

        Receives data until the socket is closed.
        """
        ...

    def recvallS(self, *a, **kw):
        r"""
        Same as :meth:`recvall`, but returns a str, decoding the result using `context.encoding`. (note that the binary versions are way faster)
        """
        ...

    def recvallb(self, *a, **kw):
        r"""
        Same as :meth:`recvall`, but returns a bytearray
        """
        ...

    def recvb(self, *a, **kw):
        r"""
        Same as :meth:`recv`, but returns a bytearray
        """
        ...

    def recvline(self, keepends=True, timeout=pwnlib.timeout.Timeout.default):
        r"""
        recvline(keepends=True, timeout=default) -> bytes

        Receive a single line from the tube.

        A "line" is any sequence of bytes terminated by the byte sequence
        set in :attr:`newline`, which defaults to ``'\n'``.

        If the request is not satisfied before ``timeout`` seconds pass,
        all data is buffered and an empty string (``''``) is returned.

        Arguments:
            keepends(bool): Keep the line ending (:const:`True`).
            timeout(int): Timeout

        Return:
            All bytes received over the tube until the first
            newline ``'\n'`` is received.  Optionally retains
            the ending.

        Examples:

            >>> t = tube()
            >>> t.recv_raw = lambda n: b'Foo\nBar\r\nBaz\n'
            >>> t.recvline()
            b'Foo\n'
            >>> t.recvline()
            b'Bar\r\n'
            >>> t.recvline(keepends = False)
            b'Baz'
            >>> t.newline = b'\r\n'
            >>> t.recvline(keepends = False)
            b'Foo\nBar'
        """
        ...

    def recvlineS(self, *a, **kw):
        r"""
        Same as :meth:`recvline`, but returns a str, decoding the result using `context.encoding`. (note that the binary versions are way faster)
        """
        ...

    def recvline_contains(self, items, keepends=False, timeout=pwnlib.timeout.Timeout.default):
        r"""
        Receive lines until one line is found which contains at least
        one of `items`.

        Arguments:
            items(str,tuple): List of strings to search for, or a single string.
            keepends(bool): Return lines with newlines if :const:`True`
            timeout(int): Timeout, in seconds

        Examples:

            >>> t = tube()
            >>> t.recv_raw = lambda n: b"Hello\nWorld\nXylophone\n"
            >>> t.recvline_contains(b'r')
            b'World'
            >>> f = lambda n: b"cat dog bird\napple pear orange\nbicycle car train\n"
            >>> t = tube()
            >>> t.recv_raw = f
            >>> t.recvline_contains(b'pear')
            b'apple pear orange'
            >>> t = tube()
            >>> t.recv_raw = f
            >>> t.recvline_contains((b'car', b'train'))
            b'bicycle car train'
        """
        ...

    def recvline_containsS(self, *a, **kw):
        r"""
        Same as :meth:`recvline_contains`, but returns a str, decoding the result using `context.encoding`. (note that the binary versions are way faster)
        """
        ...

    def recvline_containsb(self, *a, **kw):
        r"""
        Same as :meth:`recvline_contains`, but returns a bytearray
        """
        ...

    def recvline_endswith(self, delims, keepends=False, timeout=pwnlib.timeout.Timeout.default):
        r"""
        recvline_endswith(delims, keepends=False, timeout=default) -> bytes

        Keep receiving lines until one is found that ends with one of
        `delims`.  Returns the last line received.

        If the request is not satisfied before ``timeout`` seconds pass,
        all data is buffered and an empty string (``''``) is returned.

        See :meth:`recvline_startswith` for more details.

        Examples:

            >>> t = tube()
            >>> t.recv_raw = lambda n: b'Foo\nBar\nBaz\nKaboodle\n'
            >>> t.recvline_endswith(b'r')
            b'Bar'
            >>> t.recvline_endswith((b'a',b'b',b'c',b'd',b'e'), True)
            b'Kaboodle\n'
            >>> t.recvline_endswith(b'oodle')
            b'Kaboodle'
        """
        ...

    def recvline_endswithS(self, *a, **kw):
        r"""
        Same as :meth:`recvline_endswith`, but returns a str, decoding the result using `context.encoding`. (note that the binary versions are way faster)
        """
        ...

    def recvline_endswithb(self, *a, **kw):
        r"""
        Same as :meth:`recvline_endswith`, but returns a bytearray
        """
        ...

    def recvline_pred(self, pred, keepends=False, timeout=pwnlib.timeout.Timeout.default):
        r"""
        recvline_pred(pred, keepends=False) -> bytes

        Receive data until ``pred(line)`` returns a truthy value.
        Drop all other data.

        If the request is not satisfied before ``timeout`` seconds pass,
        all data is buffered and an empty string (``''``) is returned.

        Arguments:
            pred(callable): Function to call.  Returns the line for which
                this function returns :const:`True`.

        Examples:

            >>> t = tube()
            >>> t.recv_raw = lambda n: b"Foo\nBar\nBaz\n"
            >>> t.recvline_pred(lambda line: line == b"Bar\n")
            b'Bar'
            >>> t.recvline_pred(lambda line: line == b"Bar\n", keepends=True)
            b'Bar\n'
            >>> t.recvline_pred(lambda line: line == b'Nope!', timeout=0.1)
            b''
        """
        ...

    def recvline_regex(self, regex, exact=False, keepends=False, timeout=pwnlib.timeout.Timeout.default):
        r"""
        recvline_regex(regex, exact=False, keepends=False, timeout=default) -> bytes

        Wrapper around :func:`recvline_pred`, which will return when a regex
        matches a line.

        By default :func:`re.RegexObject.search` is used, but if `exact` is
        set to True, then :func:`re.RegexObject.match` will be used instead.

        If the request is not satisfied before ``timeout`` seconds pass,
        all data is buffered and an empty string (``''``) is returned.
        """
        ...

    def recvline_regexS(self, *a, **kw):
        r"""
        Same as :meth:`recvline_regex`, but returns a str, decoding the result using `context.encoding`. (note that the binary versions are way faster)
        """
        ...

    def recvline_regexb(self, *a, **kw):
        r"""
        Same as :meth:`recvline_regex`, but returns a bytearray
        """
        ...

    def recvline_startswith(self, delims, keepends=False, timeout=pwnlib.timeout.Timeout.default):
        r"""
        recvline_startswith(delims, keepends=False, timeout=default) -> bytes

        Keep receiving lines until one is found that starts with one of
        `delims`.  Returns the last line received.

        If the request is not satisfied before ``timeout`` seconds pass,
        all data is buffered and an empty string (``''``) is returned.

        Arguments:
            delims(str,tuple): List of strings to search for, or string of single characters
            keepends(bool): Return lines with newlines if :const:`True`
            timeout(int): Timeout, in seconds

        Returns:
            The first line received which starts with a delimiter in ``delims``.

        Examples:

            >>> t = tube()
            >>> t.recv_raw = lambda n: b"Hello\nWorld\nXylophone\n"
            >>> t.recvline_startswith((b'W',b'X',b'Y',b'Z'))
            b'World'
            >>> t.recvline_startswith((b'W',b'X',b'Y',b'Z'), True)
            b'Xylophone\n'
            >>> t.recvline_startswith(b'Wo')
            b'World'
        """
        ...

    def recvline_startswithS(self, *a, **kw):
        r"""
        Same as :meth:`recvline_startswith`, but returns a str, decoding the result using `context.encoding`. (note that the binary versions are way faster)
        """
        ...

    def recvline_startswithb(self, *a, **kw):
        r"""
        Same as :meth:`recvline_startswith`, but returns a bytearray
        """
        ...

    def recvlineb(self, *a, **kw):
        r"""
        Same as :meth:`recvline`, but returns a bytearray
        """
        ...

    def recvlines(self, numlines=1048576, keepends=False, timeout=pwnlib.timeout.Timeout.default):
        r"""
        recvlines(numlines, keepends=False, timeout=default) -> list of bytes objects

        Receive up to ``numlines`` lines.

        A "line" is any sequence of bytes terminated by the byte sequence
        set by :attr:`newline`, which defaults to ``'\n'``.

        If the request is not satisfied before ``timeout`` seconds pass,
        all data is buffered and an empty string (``''``) is returned.

        Arguments:
            numlines(int): Maximum number of lines to receive
            keepends(bool): Keep newlines at the end of each line (:const:`False`).
            timeout(int): Maximum timeout

        Raises:
            exceptions.EOFError: The connection closed before the request could be satisfied

        Returns:
            A string containing bytes received from the socket,
            or ``''`` if a timeout occurred while waiting.

        Examples:

            >>> t = tube()
            >>> t.recv_raw = lambda n: b'\n'
            >>> t.recvlines(3)
            [b'', b'', b'']
            >>> t.recv_raw = lambda n: b'Foo\nBar\nBaz\n'
            >>> t.recvlines(3)
            [b'Foo', b'Bar', b'Baz']
            >>> t.recvlines(3, True)
            [b'Foo\n', b'Bar\n', b'Baz\n']
        """
        ...

    def recvlinesS(self, numlines=1048576, keepends=False, timeout=pwnlib.timeout.Timeout.default):
        r"""
        recvlinesS(numlines, keepends=False, timeout=default) -> str list

        This function is identical to :meth:`recvlines`, but decodes
        the received bytes into string using :func:`context.encoding`.
        You should use :meth:`recvlines` whenever possible for better performance.

        Examples:

            >>> t = tube()
            >>> t.recv_raw = lambda n: b'\n'
            >>> t.recvlinesS(3)
            ['', '', '']
            >>> t.recv_raw = lambda n: b'Foo\nBar\nBaz\n'
            >>> t.recvlinesS(3)
            ['Foo', 'Bar', 'Baz']
        """
        ...

    def recvlinesb(self, numlines=1048576, keepends=False, timeout=pwnlib.timeout.Timeout.default):
        r"""
        recvlinesb(numlines, keepends=False, timeout=default) -> bytearray list

        This function is identical to :meth:`recvlines`, but returns a bytearray.

        Examples:

            >>> t = tube()
            >>> t.recv_raw = lambda n: b'\n'
            >>> t.recvlinesb(3)
            [bytearray(b''), bytearray(b''), bytearray(b'')]
            >>> t.recv_raw = lambda n: b'Foo\nBar\nBaz\n'
            >>> t.recvlinesb(3)
            [bytearray(b'Foo'), bytearray(b'Bar'), bytearray(b'Baz')]
        """
        ...

    def recvn(self, numb, timeout=pwnlib.timeout.Timeout.default):
        r"""
        recvn(numb, timeout = default) -> str

        Receives exactly `n` bytes.

        If the request is not satisfied before ``timeout`` seconds pass,
        all data is buffered and an empty string (``''``) is returned.

        Raises:
            exceptions.EOFError: The connection closed before the request could be satisfied

        Returns:
            A string containing bytes received from the socket,
            or ``''`` if a timeout occurred while waiting.

        Examples:

            >>> t = tube()
            >>> data = b'hello world'
            >>> t.recv_raw = lambda *a: data
            >>> t.recvn(len(data)) == data
            True
            >>> t.recvn(len(data)+1) == data + data[:1]
            True
            >>> t.recv_raw = lambda *a: None
            >>> # The remaining data is buffered
            >>> t.recv() == data[1:]
            True
            >>> t.recv_raw = lambda *a: time.sleep(0.01) or b'a'
            >>> t.recvn(10, timeout=0.05)
            b''
            >>> t.recvn(10, timeout=0.06) # doctest: +ELLIPSIS
            b'aaaaaa...'
        """
        ...

    def recvnS(self, *a, **kw):
        r"""
        Same as :meth:`recvn`, but returns a str, decoding the result using `context.encoding`. (note that the binary versions are way faster)
        """
        ...

    def recvnb(self, *a, **kw):
        r"""
        Same as :meth:`recvn`, but returns a bytearray
        """
        ...

    def recvpred(self, pred, timeout=pwnlib.timeout.Timeout.default):
        r"""
        recvpred(pred, timeout = default) -> bytes

        Receives one byte at a time from the tube, until ``pred(all_bytes)``
        evaluates to True.

        If the request is not satisfied before ``timeout`` seconds pass,
        all data is buffered and an empty string (``''``) is returned.

        Arguments:
            pred(callable): Function to call, with the currently-accumulated data.
            timeout(int): Timeout for the operation

        Raises:
            exceptions.EOFError: The connection is closed

        Returns:
            A bytes object containing bytes received from the socket,
            or ``''`` if a timeout occurred while waiting.
        """
        ...

    def recvpredS(self, *a, **kw):
        r"""
        Same as :meth:`recvpred`, but returns a str, decoding the result using `context.encoding`. (note that the binary versions are way faster)
        """
        ...

    def recvpredb(self, *a, **kw):
        r"""
        Same as :meth:`recvpred`, but returns a bytearray
        """
        ...

    def recvregex(self, regex, exact=False, timeout=pwnlib.timeout.Timeout.default):
        r"""
        recvregex(regex, exact=False, timeout=default) -> bytes

        Wrapper around :func:`recvpred`, which will return when a regex
        matches the string in the buffer.

        By default :func:`re.RegexObject.search` is used, but if `exact` is
        set to True, then :func:`re.RegexObject.match` will be used instead.

        If the request is not satisfied before ``timeout`` seconds pass,
        all data is buffered and an empty string (``''``) is returned.
        """
        ...

    def recvregexS(self, *a, **kw):
        r"""
        Same as :meth:`recvregex`, but returns a str, decoding the result using `context.encoding`. (note that the binary versions are way faster)
        """
        ...

    def recvregexb(self, *a, **kw):
        r"""
        Same as :meth:`recvregex`, but returns a bytearray
        """
        ...

    def recvrepeat(self, timeout=pwnlib.timeout.Timeout.default):
        r"""
        recvrepeat(timeout=default) -> bytes

        Receives data until a timeout or EOF is reached.

        Examples:

            >>> data = [
            ... b'd',
            ... b'', # simulate timeout
            ... b'c',
            ... b'b',
            ... b'a',
            ... ]
            >>> def delayrecv(n, data=data):
            ...     return data.pop()
            >>> t = tube()
            >>> t.recv_raw = delayrecv
            >>> t.recvrepeat(0.2)
            b'abc'
            >>> t.recv()
            b'd'
        """
        ...

    def recvrepeatS(self, *a, **kw):
        r"""
        Same as :meth:`recvrepeat`, but returns a str, decoding the result using `context.encoding`. (note that the binary versions are way faster)
        """
        ...

    def recvrepeatb(self, *a, **kw):
        r"""
        Same as :meth:`recvrepeat`, but returns a bytearray
        """
        ...

    def recvuntil(self, delims, drop=False, timeout=pwnlib.timeout.Timeout.default):
        r"""
        recvuntil(delims, drop=False, timeout=default) -> bytes

        Receive data until one of `delims` is encountered.

        If the request is not satisfied before ``timeout`` seconds pass,
        all data is buffered and an empty string (``''``) is returned.

        arguments:
            delims(bytes,tuple): Byte-string of delimiters characters, or list of delimiter byte-strings.
            drop(bool): Drop the ending.  If :const:`True` it is removed from the end of the return value.

        Raises:
            exceptions.EOFError: The connection closed before the request could be satisfied

        Returns:
            A string containing bytes received from the socket,
            or ``''`` if a timeout occurred while waiting.

        Examples:

            >>> t = tube()
            >>> t.recv_raw = lambda n: b"Hello World!"
            >>> t.recvuntil(b' ')
            b'Hello '
            >>> _=t.clean(0)
            >>> # Matches on 'o' in 'Hello'
            >>> t.recvuntil((b' ',b'W',b'o',b'r'))
            b'Hello'
            >>> _=t.clean(0)
            >>> # Matches expressly full string
            >>> t.recvuntil(b' Wor')
            b'Hello Wor'
            >>> _=t.clean(0)
            >>> # Matches on full string, drops match
            >>> t.recvuntil(b' Wor', drop=True)
            b'Hello'

            >>> # Try with regex special characters
            >>> t = tube()
            >>> t.recv_raw = lambda n: b"Hello|World"
            >>> t.recvuntil(b'|', drop=True)
            b'Hello'
        """
        ...

    def recvuntilS(self, *a, **kw):
        r"""
        Same as :meth:`recvuntil`, but returns a str, decoding the result using `context.encoding`. (note that the binary versions are way faster)
        """
        ...

    def recvuntilb(self, *a, **kw):
        r"""
        Same as :meth:`recvuntil`, but returns a bytearray
        """
        ...

    def removeHandler(self, handler):
        r"""
        removeHandler(handler)

        Remove the specified handler from the underlying logger.
        """
        ...

    def send(self, data):
        r"""
        send(data)

        Sends data.

        If log level ``DEBUG`` is enabled, also prints out the data
        received.

        If it is not possible to send anymore because of a closed
        connection, it raises ``exceptions.EOFError``

        Examples:

            >>> def p(x): print(repr(x))
            >>> t = tube()
            >>> t.send_raw = p
            >>> t.send(b'hello')
            b'hello'
        """
        ...

    def send_raw(self, data):
        r"""
        send_raw(data)

        Should not be called directly. Sends data to the tube.

        Should return ``exceptions.EOFError``, if it is unable to send any
        more, because of a close tube.
        """
        ...

    def sendafter(self, delim, data, timeout=pwnlib.timeout.Timeout.default):
        r"""
        sendafter(delim, data, timeout = default) -> str

        A combination of ``recvuntil(delim, timeout=timeout)`` and ``send(data)``.
        """
        ...

    def sendline(self, line=b''):
        r"""
        sendline(data)

        Shorthand for ``t.send(data + t.newline)``.

        Examples:

            >>> def p(x): print(repr(x))
            >>> t = tube()
            >>> t.send_raw = p
            >>> t.sendline(b'hello')
            b'hello\n'
            >>> t.newline = b'\r\n'
            >>> t.sendline(b'hello')
            b'hello\r\n'
        """
        ...

    def sendlineafter(self, delim, data, timeout=pwnlib.timeout.Timeout.default):
        r"""
        sendlineafter(delim, data, timeout = default) -> str

        A combination of ``recvuntil(delim, timeout=timeout)`` and ``sendline(data)``.
        """
        ...

    def sendlines(self, lines=[]):

        ...

    def sendlinethen(self, delim, data, timeout=pwnlib.timeout.Timeout.default):
        r"""
        sendlinethen(delim, data, timeout = default) -> str

        A combination of ``sendline(data)`` and ``recvuntil(delim, timeout=timeout)``.
        """
        ...

    def sendthen(self, delim, data, timeout=pwnlib.timeout.Timeout.default):
        r"""
        sendthen(delim, data, timeout = default) -> str

        A combination of ``send(data)`` and ``recvuntil(delim, timeout=timeout)``.
        """
        ...

    def setLevel(self, level):
        r"""
        setLevel(level)

        Set the logging level for the underlying logger.
        """
        ...

    def settimeout(self, timeout):
        r"""
        settimeout(timeout)

        Set the timeout for receiving operations. If the string "default"
        is given, then :data:`context.timeout` will be used. If None is given,
        then there will be no timeout.

        Examples:

            >>> t = tube()
            >>> t.settimeout_raw = lambda t: None
            >>> t.settimeout(3)
            >>> t.timeout == 3
            True
        """
        ...

    def settimeout_raw(self, timeout):
        r"""
        settimeout_raw(timeout)

        Should not be called directly. Sets the timeout for
        the tube.
        """
        ...

    def shutdown(self, direction='send'):
        r"""
        shutdown(direction = "send")

        Closes the tube for futher reading or writing depending on `direction`.

        Arguments:
          direction(str): Which direction to close; "in", "read" or "recv"
            closes the tube in the ingoing direction, "out", "write" or "send"
            closes it in the outgoing direction.

        Returns:
          :const:`None`

        Examples:

            >>> def p(x): print(x)
            >>> t = tube()
            >>> t.shutdown_raw = p
            >>> _=list(map(t.shutdown, ('in', 'read', 'recv', 'out', 'write', 'send')))
            recv
            recv
            recv
            send
            send
            send
            >>> t.shutdown('bad_value') #doctest: +ELLIPSIS
            Traceback (most recent call last):
            ...
            KeyError: "direction must be in ['in', 'out', 'read', 'recv', 'send', 'write']"
        """
        ...

    def shutdown_raw(self, direction):
        r"""
        shutdown_raw(direction)

        Should not be called directly.  Closes the tube for further reading or
        writing.
        """
        ...

    def spawn_process(self, *args, **kwargs):
        r"""
        Spawns a new process having this tube as stdin, stdout and stderr.

        Takes the same arguments as :class:`subprocess.Popen`.
        """
        ...

    def stream(self, line_mode=True):
        r"""
        stream()

        Receive data until the tube exits, and print it to stdout.

        Similar to :func:`interactive`, except that no input is sent.

        Similar to ``print(tube.recvall())`` except that data is printed
        as it is received, rather than after all data is received.

        Arguments:
            line_mode(bool): Whether to receive line-by-line or raw data.

        Returns:
            All data printed.
        """
        ...

    def success(self, message, *args, **kwargs):
        r"""
        success(message, *args, **kwargs)

        Logs a success message.
        """
        ...

    def timeout_change(self):
        r"""
        Informs the raw layer of the tube that the timeout has changed.

        Should not be called directly.

        Inherited from :class:`Timeout`.
        """
        ...

    def u16(self, *a, **kw):

        ...

    def u32(self, *a, **kw):

        ...

    def u64(self, *a, **kw):

        ...

    def u8(self, *a, **kw):

        ...

    def unpack(self, *a, **kw):

        ...

    def unread(self, *a, **kw):
        r"""
        Alias for :meth:`unrecv`
        """
        ...

    def unrecv(self, data):
        r"""
        unrecv(data)

        Puts the specified data back at the beginning of the receive
        buffer.

        Examples:

            >>> t = tube()
            >>> t.recv_raw = lambda n: b'hello'
            >>> t.recv()
            b'hello'
            >>> t.recv()
            b'hello'
            >>> t.unrecv(b'world')
            >>> t.recv()
            b'world'
            >>> t.recv()
            b'hello'
        """
        ...

    def wait(self, timeout=pwnlib.timeout.Timeout.default):
        r"""
        Waits until the tube is closed.
        """
        ...

    def wait_for_close(self, timeout=pwnlib.timeout.Timeout.default):
        r"""
        Waits until the tube is closed.
        """
        ...

    def waitfor(self, *args, **kwargs):
        r"""
        Alias for :meth:`progress`.
        """
        ...

    def warn(self, *args, **kwargs):
        r"""
        Alias for :meth:`warning`.
        """
        ...

    def warn_once(self, *args, **kwargs):
        r"""
        Alias for :meth:`warning_once`.
        """
        ...

    def warning(self, message, *args, **kwargs):
        r"""
        warning(message, *args, **kwargs)

        Logs a warning message.
        """
        ...

    def warning_once(self, message, *args, **kwargs):
        r"""
        warning_once(message, *args, **kwargs)

        Logs a warning message.  The same message is never printed again.
        """
        ...

    def write(self, *a, **kw):
        r"""
        Alias for :meth:`send`
        """
        ...

    def write_raw(self, *a, **kw):
        r"""
        Alias for :meth:`send_raw`
        """
        ...

    def writeafter(self, *a, **kw):
        r"""
        Alias for :meth:`sendafter`
        """
        ...

    def writeline(self, *a, **kw):
        r"""
        Alias for :meth:`sendline`
        """
        ...

    def writelineafter(self, *a, **kw):
        r"""
        Alias for :meth:`sendlineafter`
        """
        ...

    def writelines(self, *a, **kw):
        r"""
        Alias for :meth:`sendlines`
        """
        ...

    def writelinethen(self, *a, **kw):
        r"""
        Alias for :meth:`sendlinethen`
        """
        ...

    def writethen(self, *a, **kw):
        r"""
        Alias for :meth:`sendthen`
        """
        ...


import pwnlib.tubes.ssh

class ssh (pwnlib.timeout.Timeout):
    r"""
    Implements a basic class which has a timeout, and support for
    scoped timeout countdowns.

    Valid timeout values are:

    - ``Timeout.default`` use the global default value (``context.default``)
    - ``Timeout.forever`` or :const:`None` never time out
    - Any positive float, indicates timeouts in seconds

    Example:

        >>> context.timeout = 30
        >>> t = Timeout()
        >>> t.timeout == 30
        True
        >>> t = Timeout(5)
        >>> t.timeout == 5
        True
        >>> i = 0
        >>> with t.countdown():
        ...     print(4 <= t.timeout and t.timeout <= 5)
        ...
        True
        >>> with t.countdown(0.5): # doctest: +ELLIPSIS
        ...     while t.timeout:
        ...         print(round(t.timeout,1))
        ...         time.sleep(0.1)
        0.5
        0.4
        0.3
        0.2
        0.1
        >>> print(t.timeout)
        5.0
        >>> with t.local(0.5):# doctest: +ELLIPSIS
        ...     for i in range(5):
        ...         print(round(t.timeout,1))
        ...         time.sleep(0.1)
        0.5
        0.5
        0.5
        0.5
        ...
        >>> print(t.timeout)
        5.0
    """
    def __call__(self, attr):
        r"""
        Permits function-style access to run commands over SSH

        Examples:

            >>> s =  ssh(host='example.pwnme')
            >>> print(repr(s('echo hello')))
            b'hello'
        """
        ...

    def __enter__(self, *a):

        ...

    def __exit__(self, *a, **kw):

        ...

    def __getattr__(self, attr):
        r"""
        Permits member access to run commands over SSH

        Examples:

            >>> s =  ssh(host='example.pwnme')
            >>> s.echo('hello')
            b'hello'
            >>> s.whoami()
            b'travis'
            >>> s.echo(['huh','yay','args'])
            b'huh yay args'
        """
        ...

    def __getitem__(self, attr):
        r"""
        Permits indexed access to run commands over SSH

        Examples:

            >>> s =  ssh(host='example.pwnme')
            >>> print(repr(s['echo hello']))
            b'hello'
        """
        ...

    def __init__(self, user=None, host=None, port=22, password=None, key=None, keyfile=None, proxy_command=None, proxy_sock=None, level=None, cache=True, ssh_agent=False, *a, **kw):
        r"""
        Creates a new ssh connection.

        Arguments:
            user(str): The username to log in with
            host(str): The hostname to connect to
            port(int): The port to connect to
            password(str): Try to authenticate using this password
            key(str): Try to authenticate using this private key. The string should be the actual private key.
            keyfile(str): Try to authenticate using this private key. The string should be a filename.
            proxy_command(str): Use this as a proxy command. It has approximately the same semantics as ProxyCommand from ssh(1).
            proxy_sock(str): Use this socket instead of connecting to the host.
            timeout: Timeout, in seconds
            level: Log level
            cache: Cache downloaded files (by hash/size/timestamp)
            ssh_agent: If :const:`True`, enable usage of keys via ssh-agent

        NOTE: The proxy_command and proxy_sock arguments is only available if a
        fairly new version of paramiko is used.

        Example proxying:

        .. doctest::
           :skipif: True

            >>> s1 = ssh(host='example.pwnme')
            >>> r1 = s1.remote('localhost', 22)
            >>> s2 = ssh(host='example.pwnme', proxy_sock=r1.sock)
            >>> r2 = s2.remote('localhost', 22) # and so on...
            >>> for x in r2, s2, r1, s1: x.close()
        """
        ...

    def __repr__(self):
        r"""
        Return repr(self).
        """
        ...

    def _checksec_cache(self, value=None):

        ...

    def _download_raw(self, remote, local, h):

        ...

    def _download_to_cache(self, remote, p):

        ...

    def _get_cachefile(self, fingerprint):

        ...

    def _get_fingerprint(self, remote):

        ...

    def _get_timeout_seconds(self, value):

        ...

    def _getlevel(self, levelString):

        ...

    def _init_remote_platform_info(self):
        r"""
        Fills _platform_info, e.g.:

        ::

            {'distro': 'Ubuntu\n',
             'distro_ver': '14.04\n',
             'machine': 'x86_64',
             'node': 'pwnable.kr',
             'processor': 'x86_64',
             'release': '3.11.0-12-generic',
             'system': 'linux',
             'version': '#19-ubuntu smp wed oct 9 16:20:46 utc 2013'}
        """
        ...

    def _libs_remote(self, remote):
        r"""
        Return a dictionary of the libraries used by a remote file.
        """
        ...

    def _log(self, level, msg, args, kwargs, msgtype, progress=None):

        ...

    def _verify_local_fingerprint(self, fingerprint):

        ...

    def addHandler(self, handler):
        r"""
        addHandler(handler)

        Add the specified handler to the underlying logger.
        """
        ...

    def checksec(self, banner=True):
        r"""
        checksec()

        Prints a helpful message about the remote system.

        Arguments:
            banner(bool): Whether to print the path to the ELF binary.
        """
        ...

    def close(self):
        r"""
        Close the connection.
        """
        ...

    def connect_remote(self, host, port, timeout=pwnlib.timeout.Timeout.default):
        r"""
        connect_remote(host, port, timeout = Timeout.default) -> ssh_connecter

        Connects to a host through an SSH connection. This is equivalent to
        using the ``-L`` flag on ``ssh``.

        Returns a :class:`pwnlib.tubes.ssh.ssh_connecter` object.

        Examples:
            >>> from pwn import *
            >>> l = listen()
            >>> s =  ssh(host='example.pwnme')
            >>> a = s.connect_remote(s.host, l.lport)
            >>> a=a; b = l.wait_for_connection()  # a=a; prevents hangs
            >>> a.sendline(b'Hello')
            >>> print(repr(b.recvline()))
            b'Hello\n'
        """
        ...

    def connected(self):
        r"""
        Returns True if we are connected.

        Example:

            >>> s =  ssh(host='example.pwnme')
            >>> s.connected()
            True
            >>> s.close()
            >>> s.connected()
            False
        """
        ...

    def countdown(self, timeout=pwnlib.timeout.Timeout.default):
        r"""
        Scoped timeout setter.  Sets the timeout within the scope,
        and restores it when leaving the scope.

        When accessing :attr:`timeout` within the scope, it will be
        calculated against the time when the scope was entered, in a
        countdown fashion.

        If :const:`None` is specified for ``timeout``, then the current
        timeout is used is made.  This allows :const:`None` to be specified
        as a default argument with less complexity.
        """
        ...

    def countdown_active(self):

        ...

    def critical(self, message, *args, **kwargs):
        r"""
        critical(message, *args, **kwargs)

        Logs a critical message.
        """
        ...

    def debug(self, message, *args, **kwargs):
        r"""
        debug(message, *args, **kwargs)

        Logs a debug message.
        """
        ...

    def download(self, file_or_directory, local=None):
        r"""
        download(file_or_directory, local=None)

        Download a file or directory from the remote host.

        Arguments:
            file_or_directory(str): Path to the file or directory to download.
            local(str): Local path to store the data.
                By default, uses the current directory.
        """
        ...

    def download_data(self, remote):
        r"""
        Downloads a file from the remote server and returns it as a string.

        Arguments:
            remote(str): The remote filename to download.


        Examples:
            >>> with open('/tmp/bar','w+') as f:
            ...     _ = f.write('Hello, world')
            >>> s =  ssh(host='example.pwnme',
            ...         cache=False)
            >>> s.download_data('/tmp/bar')
            b'Hello, world'
            >>> s._sftp = None
            >>> s._tried_sftp = True
            >>> s.download_data('/tmp/bar')
            b'Hello, world'
        """
        ...

    def download_dir(self, remote=None, local=None):
        r"""
        Recursively downloads a directory from the remote server

        Arguments:
            local: Local directory
            remote: Remote directory
        """
        ...

    def download_file(self, remote, local=None):
        r"""
        Downloads a file from the remote server.

        The file is cached in /tmp/pwntools-ssh-cache using a hash of the file, so
        calling the function twice has little overhead.

        Arguments:
            remote(str): The remote filename to download
            local(str): The local filename to save it to. Default is to infer it from the remote filename.
        """
        ...

    def error(self, message, *args, **kwargs):
        r"""
        error(message, *args, **kwargs)

        To be called outside an exception handler.

        Logs an error message, then raises a ``PwnlibException``.
        """
        ...

    def exception(self, message, *args, **kwargs):
        r"""
        exception(message, *args, **kwargs)

        To be called from an exception handler.

        Logs a error message, then re-raises the current exception.
        """
        ...

    def failure(self, message, *args, **kwargs):
        r"""
        failure(message, *args, **kwargs)

        Logs a failure message.
        """
        ...

    def get(self, file_or_directory, local=None):
        r"""
        download(file_or_directory, local=None)

        Download a file or directory from the remote host.

        Arguments:
            file_or_directory(str): Path to the file or directory to download.
            local(str): Local path to store the data.
                By default, uses the current directory.
        """
        ...

    def getenv(self, variable, **kwargs):
        r"""
        Retrieve the address of an environment variable on the remote
        system.

        Note:

            The exact address will differ based on what other environment
            variables are set, as well as argv[0].  In order to ensure that
            the path is *exactly* the same, it is recommended to invoke the
            process with ``argv=[]``.
        """
        ...

    def hexdump(self, message, *args, **kwargs):

        ...

    def indented(self, message, *args, **kwargs):
        r"""
        indented(message, *args, level = logging.INFO, **kwargs)

        Log a message but don't put a line prefix on it.

        Arguments:
            level(int): Alternate log level at which to set the indented
                        message.  Defaults to :const:`logging.INFO`.
        """
        ...

    def info(self, message, *args, **kwargs):
        r"""
        info(message, *args, **kwargs)

        Logs an info message.
        """
        ...

    def info_once(self, message, *args, **kwargs):
        r"""
        info_once(message, *args, **kwargs)

        Logs an info message.  The same message is never printed again.
        """
        ...

    def interactive(self, shell=None):
        r"""
        Create an interactive session.

        This is a simple wrapper for creating a new
        :class:`pwnlib.tubes.ssh.ssh_channel` object and calling
        :meth:`pwnlib.tubes.ssh.ssh_channel.interactive` on it.
        """
        ...

    def isEnabledFor(self, level):
        r"""
        isEnabledFor(level) -> bool

        See if the underlying logger is enabled for the specified level.
        """
        ...

    def libs(self, remote, directory=None):
        r"""
        Downloads the libraries referred to by a file.

        This is done by running ldd on the remote server, parsing the output
        and downloading the relevant files.

        The directory argument specified where to download the files. This defaults
        to './$HOSTNAME' where $HOSTNAME is the hostname of the remote server.
        """
        ...

    def listen(self, port=0, bind_address='', timeout=pwnlib.timeout.Timeout.default):
        r"""
        listen_remote(port = 0, bind_address = '', timeout = Timeout.default) -> ssh_connecter

        Listens remotely through an SSH connection. This is equivalent to
        using the ``-R`` flag on ``ssh``.

        Returns a :class:`pwnlib.tubes.ssh.ssh_listener` object.

        Examples:

            >>> from pwn import *
            >>> s =  ssh(host='example.pwnme')
            >>> l = s.listen_remote()
            >>> a = remote(s.host, l.port)
            >>> a=a; b = l.wait_for_connection()  # a=a; prevents hangs
            >>> a.sendline(b'Hello')
            >>> print(repr(b.recvline()))
            b'Hello\n'
        """
        ...

    def listen_remote(self, port=0, bind_address='', timeout=pwnlib.timeout.Timeout.default):
        r"""
        listen_remote(port = 0, bind_address = '', timeout = Timeout.default) -> ssh_connecter

        Listens remotely through an SSH connection. This is equivalent to
        using the ``-R`` flag on ``ssh``.

        Returns a :class:`pwnlib.tubes.ssh.ssh_listener` object.

        Examples:

            >>> from pwn import *
            >>> s =  ssh(host='example.pwnme')
            >>> l = s.listen_remote()
            >>> a = remote(s.host, l.port)
            >>> a=a; b = l.wait_for_connection()  # a=a; prevents hangs
            >>> a.sendline(b'Hello')
            >>> print(repr(b.recvline()))
            b'Hello\n'
        """
        ...

    def local(self, timeout):
        r"""
        Scoped timeout setter.  Sets the timeout within the scope,
        and restores it when leaving the scope.
        """
        ...

    def log(self, level, message, *args, **kwargs):
        r"""
        log(level, message, *args, **kwargs)

        Logs a message with log level `level`.  The ``pwnlib`` formatter will
        use the default :mod:`logging` formater to format this message.
        """
        ...

    def process(self, argv=None, executable=None, tty=True, cwd=None, env=None, timeout=pwnlib.timeout.Timeout.default, run=True, stdin=0, stdout=1, stderr=2, preexec_fn=None, preexec_args=(), raw=True, aslr=None, setuid=None, shell=False):
        r"""
        Executes a process on the remote server, in the same fashion
        as pwnlib.tubes.process.process.

        To achieve this, a Python script is created to call ``os.execve``
        with the appropriate arguments.

        As an added bonus, the ``ssh_channel`` object returned has a
        ``pid`` property for the process pid.

        Arguments:
            argv(list):
                List of arguments to pass into the process
            executable(str):
                Path to the executable to run.
                If :const:`None`, ``argv[0]`` is used.
            tty(bool):
                Request a `tty` from the server.  This usually fixes buffering problems
                by causing `libc` to write data immediately rather than buffering it.
                However, this disables interpretation of control codes (e.g. Ctrl+C)
                and breaks `.shutdown`.
            cwd(str):
                Working directory.  If :const:`None`, uses the working directory specified
                on :attr:`cwd` or set via :meth:`set_working_directory`.
            env(dict):
                Environment variables to set in the child.  If :const:`None`, inherits the
                default environment.
            timeout(int):
                Timeout to set on the `tube` created to interact with the process.
            run(bool):
                Set to :const:`True` to run the program (default).
                If :const:`False`, returns the path to an executable Python script on the
                remote server which, when executed, will do it.
            stdin(int, str):
                If an integer, replace stdin with the numbered file descriptor.
                If a string, a open a file with the specified path and replace
                stdin with its file descriptor.  May also be one of ``sys.stdin``,
                ``sys.stdout``, ``sys.stderr``.  If :const:`None`, the file descriptor is closed.
            stdout(int, str):
                See ``stdin``.
            stderr(int, str):
                See ``stdin``.
            preexec_fn(callable):
                Function which is executed on the remote side before execve().
                This **MUST** be a self-contained function -- it must perform
                all of its own imports, and cannot refer to variables outside
                its scope.
            preexec_args(object):
                Argument passed to ``preexec_fn``.
                This **MUST** only consist of native Python objects.
            raw(bool):
                If :const:`True`, disable TTY control code interpretation.
            aslr(bool):
                See :class:`pwnlib.tubes.process.process` for more information.
            setuid(bool):
                See :class:`pwnlib.tubes.process.process` for more information.
            shell(bool):
                Pass the command-line arguments to the shell.

        Returns:
            A new SSH channel, or a path to a script if ``run=False``.

        Notes:
            Requires Python on the remote server.

        Examples:
            >>> s = ssh(host='example.pwnme')
            >>> sh = s.process('/bin/sh', env={'PS1':''})
            >>> sh.sendline(b'echo Hello; exit')
            >>> sh.recvall()
            b'Hello\n'
            >>> s.process(['/bin/echo', b'\xff']).recvall()
            b'\xff\n'
            >>> s.process(['readlink', '/proc/self/exe']).recvall() # doctest: +ELLIPSIS
            b'.../bin/readlink\n'
            >>> s.process(['LOLOLOL', '/proc/self/exe'], executable='readlink').recvall() # doctest: +ELLIPSIS
            b'.../bin/readlink\n'
            >>> s.process(['LOLOLOL\x00', '/proc/self/cmdline'], executable='cat').recvall()
            b'LOLOLOL\x00/proc/self/cmdline\x00'
            >>> sh = s.process(executable='/bin/sh')
            >>> str(sh.pid).encode() in s.pidof('sh') # doctest: +SKIP
            True
            >>> s.process(['pwd'], cwd='/tmp').recvall()
            b'/tmp\n'
            >>> p = s.process(['python','-c','import os; os.write(1, os.read(2, 1024))'], stderr=0)
            >>> p.send(b'hello')
            >>> p.recv()
            b'hello'
            >>> s.process(['/bin/echo', 'hello']).recvall()
            b'hello\n'
            >>> s.process(['/bin/echo', 'hello'], stdout='/dev/null').recvall()
            b''
            >>> s.process(['/usr/bin/env'], env={}).recvall()
            b''
            >>> s.process('/usr/bin/env', env={'A':'B'}).recvall()
            b'A=B\n'

            >>> s.process('false', preexec_fn=1234)
            Traceback (most recent call last):
            ...
            PwnlibException: preexec_fn must be a function

            >>> s.process('false', preexec_fn=lambda: 1234)
            Traceback (most recent call last):
            ...
            PwnlibException: preexec_fn cannot be a lambda

            >>> def uses_globals():
            ...     foo = bar
            >>> print(s.process('false', preexec_fn=uses_globals).recvall().strip().decode()) # doctest: +ELLIPSIS
            Traceback (most recent call last):
            ...
            NameError: ... name 'bar' is not defined

            >>> s.process('echo hello', shell=True).recvall()
            b'hello\n'

            >>> io = s.process(['cat'], timeout=5)
            >>> io.recvline()
            b''
        """
        ...

    def progress(self, message, status='', *args, **kwargs):
        r"""
        progress(message, status = '', *args, level = logging.INFO, **kwargs) -> Progress

        Creates a new progress logger which creates log records with log level
        `level`.

        Progress status can be updated using :meth:`Progress.status` and stopped
        using :meth:`Progress.success` or :meth:`Progress.failure`.

        If `term.term_mode` is enabled the progress logger will be animated.

        The progress manager also functions as a context manager.  Using context
        managers ensures that animations stop even if an exception is raised.

        .. code-block:: python

           with log.progress('Trying something...') as p:
               for i in range(10):
                   p.status("At %i" % i)
                   time.sleep(0.5)
               x = 1/0
        """
        ...

    def put(self, file_or_directory, remote=None):
        r"""
        upload(file_or_directory, remote=None)

        Upload a file or directory to the remote host.

        Arguments:
            file_or_directory(str): Path to the file or directory to download.
            remote(str): Local path to store the data.
                By default, uses the working directory.
        """
        ...

    def read(self, path):
        r"""
        Wrapper around download_data to match :func:`pwnlib.util.misc.read`
        """
        ...

    def remote(self, host, port, timeout=pwnlib.timeout.Timeout.default):
        r"""
        connect_remote(host, port, timeout = Timeout.default) -> ssh_connecter

        Connects to a host through an SSH connection. This is equivalent to
        using the ``-L`` flag on ``ssh``.

        Returns a :class:`pwnlib.tubes.ssh.ssh_connecter` object.

        Examples:
            >>> from pwn import *
            >>> l = listen()
            >>> s =  ssh(host='example.pwnme')
            >>> a = s.connect_remote(s.host, l.lport)
            >>> a=a; b = l.wait_for_connection()  # a=a; prevents hangs
            >>> a.sendline(b'Hello')
            >>> print(repr(b.recvline()))
            b'Hello\n'
        """
        ...

    def removeHandler(self, handler):
        r"""
        removeHandler(handler)

        Remove the specified handler from the underlying logger.
        """
        ...

    def run(self, process, tty=True, wd=None, env=None, timeout=None, raw=True):
        r"""
        system(process, tty = True, wd = None, env = None, timeout = Timeout.default, raw = True) -> ssh_channel

        Open a new channel with a specific process inside. If `tty` is True,
        then a TTY is requested on the remote server.

        If `raw` is True, terminal control codes are ignored and input is not
        echoed back.

        Return a :class:`pwnlib.tubes.ssh.ssh_channel` object.

        Examples:
            >>> s =  ssh(host='example.pwnme')
            >>> py = s.run('python -i')
            >>> _ = py.recvuntil(b'>>> ')
            >>> py.sendline(b'print(2+2)')
            >>> py.sendline(b'exit')
            >>> print(repr(py.recvline()))
            b'4\n'
            >>> s.system('env | grep -a AAAA', env={'AAAA': b'\x90'}).recvall()
            b'AAAA=\x90\n'
        """
        ...

    def run_to_end(self, process, tty=False, wd=None, env=None):
        r"""
        run_to_end(process, tty = False, timeout = Timeout.default, env = None) -> str

        Run a command on the remote server and return a tuple with
        (data, exit_status). If `tty` is True, then the command is run inside
        a TTY on the remote server.

        Examples:
            >>> s =  ssh(host='example.pwnme')
            >>> print(s.run_to_end('echo Hello; exit 17'))
            (b'Hello\n', 17)
    
        """
        ...

    def setLevel(self, level):
        r"""
        setLevel(level)

        Set the logging level for the underlying logger.
        """
        ...

    def set_working_directory(self, wd=None, symlink=False):
        r"""
        Sets the working directory in which future commands will
        be run (via ssh.run) and to which files will be uploaded/downloaded
        from if no path is provided

        Note:
            This uses ``mktemp -d`` under the covers, sets permissions
            on the directory to ``0700``.  This means that setuid binaries
            will **not** be able to access files created in this directory.

            In order to work around this, we also ``chmod +x`` the directory.

        Arguments:
            wd(string): Working directory.  Default is to auto-generate a directory
                based on the result of running 'mktemp -d' on the remote machine.
            symlink(bool,str): Create symlinks in the new directory.

                The default value, ``False``, implies that no symlinks should be
                created.

                A string value is treated as a path that should be symlinked.
                It is passed directly to the shell on the remote end for expansion,
                so wildcards work.

                Any other value is treated as a boolean, where ``True`` indicates
                that all files in the "old" working directory should be symlinked.

        Examples:
            >>> s =  ssh(host='example.pwnme')
            >>> cwd = s.set_working_directory()
            >>> s.ls()
            b''
            >>> context._decode(s.pwd()) == cwd
            True

            >>> s =  ssh(host='example.pwnme')
            >>> homedir = s.pwd()
            >>> _=s.touch('foo')

            >>> _=s.set_working_directory()
            >>> assert s.ls() == b''

            >>> _=s.set_working_directory(homedir)
            >>> assert b'foo' in s.ls().split()

            >>> _=s.set_working_directory(symlink=True)
            >>> assert b'foo' in s.ls().split()
            >>> assert homedir != s.pwd()

            >>> symlink=os.path.join(homedir,b'*')
            >>> _=s.set_working_directory(symlink=symlink)
            >>> assert b'foo' in s.ls().split()
            >>> assert homedir != s.pwd()
        """
        ...

    def shell(self, shell=None, tty=True, timeout=pwnlib.timeout.Timeout.default):
        r"""
        shell(shell = None, tty = True, timeout = Timeout.default) -> ssh_channel

        Open a new channel with a shell inside.

        Arguments:
            shell(str): Path to the shell program to run.
                If :const:`None`, uses the default shell for the logged in user.
            tty(bool): If :const:`True`, then a TTY is requested on the remote server.

        Returns:
            Return a :class:`pwnlib.tubes.ssh.ssh_channel` object.

        Examples:
            >>> s =  ssh(host='example.pwnme')
            >>> sh = s.shell('/bin/sh')
            >>> sh.sendline(b'echo Hello; exit')
            >>> print(b'Hello' in sh.recvall())
            True
        """
        ...

    def success(self, message, *args, **kwargs):
        r"""
        success(message, *args, **kwargs)

        Logs a success message.
        """
        ...

    def system(self, process, tty=True, wd=None, env=None, timeout=None, raw=True):
        r"""
        system(process, tty = True, wd = None, env = None, timeout = Timeout.default, raw = True) -> ssh_channel

        Open a new channel with a specific process inside. If `tty` is True,
        then a TTY is requested on the remote server.

        If `raw` is True, terminal control codes are ignored and input is not
        echoed back.

        Return a :class:`pwnlib.tubes.ssh.ssh_channel` object.

        Examples:
            >>> s =  ssh(host='example.pwnme')
            >>> py = s.run('python -i')
            >>> _ = py.recvuntil(b'>>> ')
            >>> py.sendline(b'print(2+2)')
            >>> py.sendline(b'exit')
            >>> print(repr(py.recvline()))
            b'4\n'
            >>> s.system('env | grep -a AAAA', env={'AAAA': b'\x90'}).recvall()
            b'AAAA=\x90\n'
        """
        ...

    def timeout_change(self):
        r"""
        Callback for subclasses to hook a timeout change.
        """
        ...

    def unlink(self, file):
        r"""
        unlink(file)

        Delete the file on the remote host

        Arguments:
            file(str): Path to the file
        """
        ...

    def upload(self, file_or_directory, remote=None):
        r"""
        upload(file_or_directory, remote=None)

        Upload a file or directory to the remote host.

        Arguments:
            file_or_directory(str): Path to the file or directory to download.
            remote(str): Local path to store the data.
                By default, uses the working directory.
        """
        ...

    def upload_data(self, data, remote):
        r"""
        Uploads some data into a file on the remote server.

        Arguments:
            data(str): The data to upload.
            remote(str): The filename to upload it to.

        Example:
            >>> s =  ssh(host='example.pwnme')
            >>> s.upload_data(b'Hello, world', '/tmp/upload_foo')
            >>> print(open('/tmp/upload_foo').read())
            Hello, world
            >>> s._sftp = False
            >>> s._tried_sftp = True
            >>> s.upload_data(b'Hello, world', '/tmp/upload_bar')
            >>> print(open('/tmp/upload_bar').read())
            Hello, world
        """
        ...

    def upload_dir(self, local, remote=None):
        r"""
        Recursively uploads a directory onto the remote server

        Arguments:
            local: Local directory
            remote: Remote directory
        """
        ...

    def upload_file(self, filename, remote=None):
        r"""
        Uploads a file to the remote server. Returns the remote filename.

        Arguments:
        filename(str): The local filename to download
        remote(str): The remote filename to save it to. Default is to infer it from the local filename.
        """
        ...

    def waitfor(self, *args, **kwargs):
        r"""
        Alias for :meth:`progress`.
        """
        ...

    def warn(self, *args, **kwargs):
        r"""
        Alias for :meth:`warning`.
        """
        ...

    def warn_once(self, *args, **kwargs):
        r"""
        Alias for :meth:`warning_once`.
        """
        ...

    def warning(self, message, *args, **kwargs):
        r"""
        warning(message, *args, **kwargs)

        Logs a warning message.
        """
        ...

    def warning_once(self, message, *args, **kwargs):
        r"""
        warning_once(message, *args, **kwargs)

        Logs a warning message.  The same message is never printed again.
        """
        ...

    def which(self, program):
        r"""
        which(program) -> str

        Minor modification to just directly invoking ``which`` on the remote
        system which adds the current working directory to the end of ``$PATH``.
        """
        ...

    def write(self, path, data):
        r"""
        Wrapper around upload_data to match :func:`pwnlib.util.misc.write`
        """
        ...


import pwnlib.tubes.tube

class tube (pwnlib.timeout.Timeout):
    r"""
    Container of all the tube functions common to sockets, TTYs and SSH connetions.
    """
    def __enter__(self):
        r"""
        Permit use of 'with' to control scoping and closing sessions.

        Examples:

            >>> t = tube()
            >>> def p(x): print(x)
            >>> t.close = lambda: p("Closed!")
            >>> with t: pass
            Closed!
        """
        ...

    def __exit__(self, type, value, traceback):
        r"""
        Handles closing for 'with' statement

        See :meth:`__enter__`
        """
        ...

    def __init__(self, timeout=pwnlib.timeout.Timeout.default, level=None, *a, **kw):
        r"""
        Initialize self.  See help(type(self)) for accurate signature.
        """
        ...

    def __lshift__(self, other):
        r"""
        Shorthand for connecting multiple tubes.

        See :meth:`connect_input` for more information.

        Examples:

            The following are equivalent ::

                tube_a >> tube.b
                tube_a.connect_input(tube_b)

            This is useful when chaining multiple tubes ::

                tube_a >> tube_b >> tube_a
                tube_a.connect_input(tube_b)
                tube_b.connect_input(tube_a)
        """
        ...

    def __ne__(self, other):
        r"""
        Shorthand for connecting tubes to eachother.

        The following are equivalent ::

            a >> b >> a
            a <> b

        See :meth:`connect_input` for more information.
        """
        ...

    def __rshift__(self, other):
        r"""
        Inverse of the ``<<`` operator.  See :meth:`__lshift__`.

        See :meth:`connect_input` for more information.
        """
        ...

    def _fillbuffer(self, timeout=pwnlib.timeout.Timeout.default):
        r"""
        _fillbuffer(timeout = default)

        Fills the internal buffer from the pipe, by calling
        :meth:`recv_raw` exactly once.

        Returns:

            The bytes of data received, or ``''`` if no data was received.

        Examples:

            >>> t = tube()
            >>> t.recv_raw = lambda *a: b'abc'
            >>> len(t.buffer)
            0
            >>> t._fillbuffer()
            b'abc'
            >>> len(t.buffer)
            3
        """
        ...

    def _get_timeout_seconds(self, value):

        ...

    def _getlevel(self, levelString):

        ...

    def _log(self, level, msg, args, kwargs, msgtype, progress=None):

        ...

    def _read(self, *a, **kw):
        r"""
        Alias for :meth:`_recv`
        """
        ...

    def _recv(self, numb=None, timeout=pwnlib.timeout.Timeout.default):
        r"""
        _recv(numb = 4096, timeout = default) -> str

        Receives one chunk of from the internal buffer or from the OS if the
        buffer is empty.
        """
        ...

    def addHandler(self, handler):
        r"""
        addHandler(handler)

        Add the specified handler to the underlying logger.
        """
        ...

    def can_read(self, *a, **kw):
        r"""
        Alias for :meth:`can_recv`
        """
        ...

    def can_read_raw(self, *a, **kw):
        r"""
        Alias for :meth:`can_recv_raw`
        """
        ...

    def can_recv(self, timeout=0):
        r"""
        can_recv(timeout = 0) -> bool

        Returns True, if there is data available within `timeout` seconds.

        Examples:

            >>> import time
            >>> t = tube()
            >>> t.can_recv_raw = lambda *a: False
            >>> t.can_recv()
            False
            >>> _=t.unrecv(b'data')
            >>> t.can_recv()
            True
            >>> _=t.recv()
            >>> t.can_recv()
            False
        """
        ...

    def can_recv_raw(self, timeout):
        r"""
        can_recv_raw(timeout) -> bool

        Should not be called directly. Returns True, if
        there is data available within the timeout, but
        ignores the buffer on the object.
        """
        ...

    def clean(self, timeout=0.05):
        r"""
        clean(timeout = 0.05)

        Removes all the buffered data from a tube by calling
        :meth:`pwnlib.tubes.tube.tube.recv` with a low timeout until it fails.

        If ``timeout`` is zero, only cached data will be cleared.

        Note: If timeout is set to zero, the underlying network is
        not actually polled; only the internal buffer is cleared.

        Returns:

            All data received

        Examples:

            >>> t = tube()
            >>> t.unrecv(b'clean me up')
            >>> t.clean(0)
            b'clean me up'
            >>> len(t.buffer)
            0
        """
        ...

    def clean_and_log(self, timeout=0.05):
        r"""
        clean_and_log(timeout = 0.05)

        Works exactly as :meth:`pwnlib.tubes.tube.tube.clean`, but logs received
        data with :meth:`pwnlib.self.info`.

        Returns:

            All data received

        Examples:

            >>> def recv(n, data=[b'', b'hooray_data']):
            ...     while data: return data.pop()
            >>> t = tube()
            >>> t.recv_raw      = recv
            >>> t.connected_raw = lambda d: True
            >>> t.fileno        = lambda: 1234
            >>> with context.local(log_level='info'):
            ...     data = t.clean_and_log() #doctest: +ELLIPSIS
            [DEBUG] Received 0xb bytes:
                b'hooray_data'
            >>> data
            b'hooray_data'
            >>> context.clear()
        """
        ...

    def close(self):
        r"""
        close()

        Closes the tube.
        """
        ...

    def connect_both(self, other):
        r"""
        connect_both(other)

        Connects the both ends of this tube object with another tube object.
        """
        ...

    def connect_input(self, other):
        r"""
        connect_input(other)

        Connects the input of this tube to the output of another tube object.


        Examples:

            >>> def p(x): print(x.decode())
            >>> def recvone(n, data=[b'data']):
            ...     while data: return data.pop()
            ...     raise EOFError
            >>> a = tube()
            >>> b = tube()
            >>> a.recv_raw = recvone
            >>> b.send_raw = p
            >>> a.connected_raw = lambda d: True
            >>> b.connected_raw = lambda d: True
            >>> a.shutdown      = lambda d: True
            >>> b.shutdown      = lambda d: True
            >>> import time
            >>> _=(b.connect_input(a), time.sleep(0.1))
            data
        """
        ...

    def connect_output(self, other):
        r"""
        connect_output(other)

        Connects the output of this tube to the input of another tube object.

        Examples:

            >>> def p(x): print(repr(x))
            >>> def recvone(n, data=[b'data']):
            ...     while data: return data.pop()
            ...     raise EOFError
            >>> a = tube()
            >>> b = tube()
            >>> a.recv_raw = recvone
            >>> b.send_raw = p
            >>> a.connected_raw = lambda d: True
            >>> b.connected_raw = lambda d: True
            >>> a.shutdown      = lambda d: True
            >>> b.shutdown      = lambda d: True
            >>> _=(a.connect_output(b), time.sleep(0.1))
            b'data'
        """
        ...

    def connected(self, direction='any'):
        r"""
        connected(direction = 'any') -> bool

        Returns True if the tube is connected in the specified direction.

        Arguments:
          direction(str): Can be the string 'any', 'in', 'read', 'recv',
                          'out', 'write', 'send'.

        Doctest:

            >>> def p(x): print(x)
            >>> t = tube()
            >>> t.connected_raw = p
            >>> _=list(map(t.connected, ('any', 'in', 'read', 'recv', 'out', 'write', 'send')))
            any
            recv
            recv
            recv
            send
            send
            send
            >>> t.connected('bad_value') #doctest: +ELLIPSIS
            Traceback (most recent call last):
            ...
            KeyError: "direction must be in ['any', 'in', 'out', 'read', 'recv', 'send', 'write']"
        """
        ...

    def connected_raw(self, direction):
        r"""
        connected(direction = 'any') -> bool

        Should not be called directly.  Returns True iff the
        tube is connected in the given direction.
        """
        ...

    def countdown(self, timeout=pwnlib.timeout.Timeout.default):
        r"""
        Scoped timeout setter.  Sets the timeout within the scope,
        and restores it when leaving the scope.

        When accessing :attr:`timeout` within the scope, it will be
        calculated against the time when the scope was entered, in a
        countdown fashion.

        If :const:`None` is specified for ``timeout``, then the current
        timeout is used is made.  This allows :const:`None` to be specified
        as a default argument with less complexity.
        """
        ...

    def countdown_active(self):

        ...

    def critical(self, message, *args, **kwargs):
        r"""
        critical(message, *args, **kwargs)

        Logs a critical message.
        """
        ...

    def debug(self, message, *args, **kwargs):
        r"""
        debug(message, *args, **kwargs)

        Logs a debug message.
        """
        ...

    def error(self, message, *args, **kwargs):
        r"""
        error(message, *args, **kwargs)

        To be called outside an exception handler.

        Logs an error message, then raises a ``PwnlibException``.
        """
        ...

    def exception(self, message, *args, **kwargs):
        r"""
        exception(message, *args, **kwargs)

        To be called from an exception handler.

        Logs a error message, then re-raises the current exception.
        """
        ...

    def failure(self, message, *args, **kwargs):
        r"""
        failure(message, *args, **kwargs)

        Logs a failure message.
        """
        ...

    def fileno(self):
        r"""
        fileno() -> int

        Returns the file number used for reading.
        """
        ...

    def fit(self, *a, **kw):

        ...

    def flat(self, *a, **kw):

        ...

    def hexdump(self, message, *args, **kwargs):

        ...

    def indented(self, message, *args, **kwargs):
        r"""
        indented(message, *args, level = logging.INFO, **kwargs)

        Log a message but don't put a line prefix on it.

        Arguments:
            level(int): Alternate log level at which to set the indented
                        message.  Defaults to :const:`logging.INFO`.
        """
        ...

    def info(self, message, *args, **kwargs):
        r"""
        info(message, *args, **kwargs)

        Logs an info message.
        """
        ...

    def info_once(self, message, *args, **kwargs):
        r"""
        info_once(message, *args, **kwargs)

        Logs an info message.  The same message is never printed again.
        """
        ...

    def interactive(self, prompt='\x1b[1m\x1b[31m$\x1b[m '):
        r"""
        interactive(prompt = pwnlib.term.text.bold_red('$') + ' ')

        Does simultaneous reading and writing to the tube. In principle this just
        connects the tube to standard in and standard out, but in practice this
        is much more usable, since we are using :mod:`pwnlib.term` to print a
        floating prompt.

        Thus it only works in while in :data:`pwnlib.term.term_mode`.
        """
        ...

    def isEnabledFor(self, level):
        r"""
        isEnabledFor(level) -> bool

        See if the underlying logger is enabled for the specified level.
        """
        ...

    def local(self, timeout):
        r"""
        Scoped timeout setter.  Sets the timeout within the scope,
        and restores it when leaving the scope.
        """
        ...

    def log(self, level, message, *args, **kwargs):
        r"""
        log(level, message, *args, **kwargs)

        Logs a message with log level `level`.  The ``pwnlib`` formatter will
        use the default :mod:`logging` formater to format this message.
        """
        ...

    def p16(self, *a, **kw):

        ...

    def p32(self, *a, **kw):

        ...

    def p64(self, *a, **kw):

        ...

    def p8(self, *a, **kw):

        ...

    def pack(self, *a, **kw):

        ...

    def progress(self, message, status='', *args, **kwargs):
        r"""
        progress(message, status = '', *args, level = logging.INFO, **kwargs) -> Progress

        Creates a new progress logger which creates log records with log level
        `level`.

        Progress status can be updated using :meth:`Progress.status` and stopped
        using :meth:`Progress.success` or :meth:`Progress.failure`.

        If `term.term_mode` is enabled the progress logger will be animated.

        The progress manager also functions as a context manager.  Using context
        managers ensures that animations stop even if an exception is raised.

        .. code-block:: python

           with log.progress('Trying something...') as p:
               for i in range(10):
                   p.status("At %i" % i)
                   time.sleep(0.5)
               x = 1/0
        """
        ...

    def read(self, *a, **kw):
        r"""
        Alias for :meth:`recv`
        """
        ...

    def readS(self, *a, **kw):
        r"""
        Alias for :meth:`recvS`
        """
        ...

    def read_raw(self, *a, **kw):
        r"""
        Alias for :meth:`recv_raw`
        """
        ...

    def readall(self, *a, **kw):
        r"""
        Alias for :meth:`recvall`
        """
        ...

    def readallS(self, *a, **kw):
        r"""
        Alias for :meth:`recvallS`
        """
        ...

    def readallb(self, *a, **kw):
        r"""
        Alias for :meth:`recvallb`
        """
        ...

    def readb(self, *a, **kw):
        r"""
        Alias for :meth:`recvb`
        """
        ...

    def readline(self, *a, **kw):
        r"""
        Alias for :meth:`recvline`
        """
        ...

    def readlineS(self, *a, **kw):
        r"""
        Alias for :meth:`recvlineS`
        """
        ...

    def readline_contains(self, *a, **kw):
        r"""
        Alias for :meth:`recvline_contains`
        """
        ...

    def readline_containsS(self, *a, **kw):
        r"""
        Alias for :meth:`recvline_containsS`
        """
        ...

    def readline_containsb(self, *a, **kw):
        r"""
        Alias for :meth:`recvline_containsb`
        """
        ...

    def readline_endswith(self, *a, **kw):
        r"""
        Alias for :meth:`recvline_endswith`
        """
        ...

    def readline_endswithS(self, *a, **kw):
        r"""
        Alias for :meth:`recvline_endswithS`
        """
        ...

    def readline_endswithb(self, *a, **kw):
        r"""
        Alias for :meth:`recvline_endswithb`
        """
        ...

    def readline_pred(self, *a, **kw):
        r"""
        Alias for :meth:`recvline_pred`
        """
        ...

    def readline_regex(self, *a, **kw):
        r"""
        Alias for :meth:`recvline_regex`
        """
        ...

    def readline_regexS(self, *a, **kw):
        r"""
        Alias for :meth:`recvline_regexS`
        """
        ...

    def readline_regexb(self, *a, **kw):
        r"""
        Alias for :meth:`recvline_regexb`
        """
        ...

    def readline_startswith(self, *a, **kw):
        r"""
        Alias for :meth:`recvline_startswith`
        """
        ...

    def readline_startswithS(self, *a, **kw):
        r"""
        Alias for :meth:`recvline_startswithS`
        """
        ...

    def readline_startswithb(self, *a, **kw):
        r"""
        Alias for :meth:`recvline_startswithb`
        """
        ...

    def readlineb(self, *a, **kw):
        r"""
        Alias for :meth:`recvlineb`
        """
        ...

    def readlines(self, *a, **kw):
        r"""
        Alias for :meth:`recvlines`
        """
        ...

    def readlinesS(self, *a, **kw):
        r"""
        Alias for :meth:`recvlinesS`
        """
        ...

    def readlinesb(self, *a, **kw):
        r"""
        Alias for :meth:`recvlinesb`
        """
        ...

    def readn(self, *a, **kw):
        r"""
        Alias for :meth:`recvn`
        """
        ...

    def readnS(self, *a, **kw):
        r"""
        Alias for :meth:`recvnS`
        """
        ...

    def readnb(self, *a, **kw):
        r"""
        Alias for :meth:`recvnb`
        """
        ...

    def readpred(self, *a, **kw):
        r"""
        Alias for :meth:`recvpred`
        """
        ...

    def readpredS(self, *a, **kw):
        r"""
        Alias for :meth:`recvpredS`
        """
        ...

    def readpredb(self, *a, **kw):
        r"""
        Alias for :meth:`recvpredb`
        """
        ...

    def readregex(self, *a, **kw):
        r"""
        Alias for :meth:`recvregex`
        """
        ...

    def readregexS(self, *a, **kw):
        r"""
        Alias for :meth:`recvregexS`
        """
        ...

    def readregexb(self, *a, **kw):
        r"""
        Alias for :meth:`recvregexb`
        """
        ...

    def readrepeat(self, *a, **kw):
        r"""
        Alias for :meth:`recvrepeat`
        """
        ...

    def readrepeatS(self, *a, **kw):
        r"""
        Alias for :meth:`recvrepeatS`
        """
        ...

    def readrepeatb(self, *a, **kw):
        r"""
        Alias for :meth:`recvrepeatb`
        """
        ...

    def readuntil(self, *a, **kw):
        r"""
        Alias for :meth:`recvuntil`
        """
        ...

    def readuntilS(self, *a, **kw):
        r"""
        Alias for :meth:`recvuntilS`
        """
        ...

    def readuntilb(self, *a, **kw):
        r"""
        Alias for :meth:`recvuntilb`
        """
        ...

    def recv(self, numb=None, timeout=pwnlib.timeout.Timeout.default):
        r"""
        recv(numb = 4096, timeout = default) -> bytes

        Receives up to `numb` bytes of data from the tube, and returns
        as soon as any quantity of data is available.

        If the request is not satisfied before ``timeout`` seconds pass,
        all data is buffered and an empty string (``''``) is returned.

        Raises:
            exceptions.EOFError: The connection is closed

        Returns:
            A bytes object containing bytes received from the socket,
            or ``''`` if a timeout occurred while waiting.

        Examples:

            >>> t = tube()
            >>> # Fake a data source
            >>> t.recv_raw = lambda n: b'Hello, world'
            >>> t.recv() == b'Hello, world'
            True
            >>> t.unrecv(b'Woohoo')
            >>> t.recv() == b'Woohoo'
            True
            >>> with context.local(log_level='debug'):
            ...    _ = t.recv() # doctest: +ELLIPSIS
            [...] Received 0xc bytes:
                b'Hello, world'
        """
        ...

    def recvS(self, *a, **kw):
        r"""
        Same as :meth:`recv`, but returns a str, decoding the result using `context.encoding`. (note that the binary versions are way faster)
        """
        ...

    def recv_raw(self, numb):
        r"""
        recv_raw(numb) -> str

        Should not be called directly. Receives data without using the buffer
        on the object.

        Unless there is a timeout or closed connection, this should always
        return data. In case of a timeout, it should return None, in case
        of a closed connection it should raise an ``exceptions.EOFError``.
        """
        ...

    def recvall(self, timeout=None):
        r"""
        recvall() -> bytes

        Receives data until EOF is reached.
        """
        ...

    def recvallS(self, *a, **kw):
        r"""
        Same as :meth:`recvall`, but returns a str, decoding the result using `context.encoding`. (note that the binary versions are way faster)
        """
        ...

    def recvallb(self, *a, **kw):
        r"""
        Same as :meth:`recvall`, but returns a bytearray
        """
        ...

    def recvb(self, *a, **kw):
        r"""
        Same as :meth:`recv`, but returns a bytearray
        """
        ...

    def recvline(self, keepends=True, timeout=pwnlib.timeout.Timeout.default):
        r"""
        recvline(keepends=True, timeout=default) -> bytes

        Receive a single line from the tube.

        A "line" is any sequence of bytes terminated by the byte sequence
        set in :attr:`newline`, which defaults to ``'\n'``.

        If the request is not satisfied before ``timeout`` seconds pass,
        all data is buffered and an empty string (``''``) is returned.

        Arguments:
            keepends(bool): Keep the line ending (:const:`True`).
            timeout(int): Timeout

        Return:
            All bytes received over the tube until the first
            newline ``'\n'`` is received.  Optionally retains
            the ending.

        Examples:

            >>> t = tube()
            >>> t.recv_raw = lambda n: b'Foo\nBar\r\nBaz\n'
            >>> t.recvline()
            b'Foo\n'
            >>> t.recvline()
            b'Bar\r\n'
            >>> t.recvline(keepends = False)
            b'Baz'
            >>> t.newline = b'\r\n'
            >>> t.recvline(keepends = False)
            b'Foo\nBar'
        """
        ...

    def recvlineS(self, *a, **kw):
        r"""
        Same as :meth:`recvline`, but returns a str, decoding the result using `context.encoding`. (note that the binary versions are way faster)
        """
        ...

    def recvline_contains(self, items, keepends=False, timeout=pwnlib.timeout.Timeout.default):
        r"""
        Receive lines until one line is found which contains at least
        one of `items`.

        Arguments:
            items(str,tuple): List of strings to search for, or a single string.
            keepends(bool): Return lines with newlines if :const:`True`
            timeout(int): Timeout, in seconds

        Examples:

            >>> t = tube()
            >>> t.recv_raw = lambda n: b"Hello\nWorld\nXylophone\n"
            >>> t.recvline_contains(b'r')
            b'World'
            >>> f = lambda n: b"cat dog bird\napple pear orange\nbicycle car train\n"
            >>> t = tube()
            >>> t.recv_raw = f
            >>> t.recvline_contains(b'pear')
            b'apple pear orange'
            >>> t = tube()
            >>> t.recv_raw = f
            >>> t.recvline_contains((b'car', b'train'))
            b'bicycle car train'
        """
        ...

    def recvline_containsS(self, *a, **kw):
        r"""
        Same as :meth:`recvline_contains`, but returns a str, decoding the result using `context.encoding`. (note that the binary versions are way faster)
        """
        ...

    def recvline_containsb(self, *a, **kw):
        r"""
        Same as :meth:`recvline_contains`, but returns a bytearray
        """
        ...

    def recvline_endswith(self, delims, keepends=False, timeout=pwnlib.timeout.Timeout.default):
        r"""
        recvline_endswith(delims, keepends=False, timeout=default) -> bytes

        Keep receiving lines until one is found that ends with one of
        `delims`.  Returns the last line received.

        If the request is not satisfied before ``timeout`` seconds pass,
        all data is buffered and an empty string (``''``) is returned.

        See :meth:`recvline_startswith` for more details.

        Examples:

            >>> t = tube()
            >>> t.recv_raw = lambda n: b'Foo\nBar\nBaz\nKaboodle\n'
            >>> t.recvline_endswith(b'r')
            b'Bar'
            >>> t.recvline_endswith((b'a',b'b',b'c',b'd',b'e'), True)
            b'Kaboodle\n'
            >>> t.recvline_endswith(b'oodle')
            b'Kaboodle'
        """
        ...

    def recvline_endswithS(self, *a, **kw):
        r"""
        Same as :meth:`recvline_endswith`, but returns a str, decoding the result using `context.encoding`. (note that the binary versions are way faster)
        """
        ...

    def recvline_endswithb(self, *a, **kw):
        r"""
        Same as :meth:`recvline_endswith`, but returns a bytearray
        """
        ...

    def recvline_pred(self, pred, keepends=False, timeout=pwnlib.timeout.Timeout.default):
        r"""
        recvline_pred(pred, keepends=False) -> bytes

        Receive data until ``pred(line)`` returns a truthy value.
        Drop all other data.

        If the request is not satisfied before ``timeout`` seconds pass,
        all data is buffered and an empty string (``''``) is returned.

        Arguments:
            pred(callable): Function to call.  Returns the line for which
                this function returns :const:`True`.

        Examples:

            >>> t = tube()
            >>> t.recv_raw = lambda n: b"Foo\nBar\nBaz\n"
            >>> t.recvline_pred(lambda line: line == b"Bar\n")
            b'Bar'
            >>> t.recvline_pred(lambda line: line == b"Bar\n", keepends=True)
            b'Bar\n'
            >>> t.recvline_pred(lambda line: line == b'Nope!', timeout=0.1)
            b''
        """
        ...

    def recvline_regex(self, regex, exact=False, keepends=False, timeout=pwnlib.timeout.Timeout.default):
        r"""
        recvline_regex(regex, exact=False, keepends=False, timeout=default) -> bytes

        Wrapper around :func:`recvline_pred`, which will return when a regex
        matches a line.

        By default :func:`re.RegexObject.search` is used, but if `exact` is
        set to True, then :func:`re.RegexObject.match` will be used instead.

        If the request is not satisfied before ``timeout`` seconds pass,
        all data is buffered and an empty string (``''``) is returned.
        """
        ...

    def recvline_regexS(self, *a, **kw):
        r"""
        Same as :meth:`recvline_regex`, but returns a str, decoding the result using `context.encoding`. (note that the binary versions are way faster)
        """
        ...

    def recvline_regexb(self, *a, **kw):
        r"""
        Same as :meth:`recvline_regex`, but returns a bytearray
        """
        ...

    def recvline_startswith(self, delims, keepends=False, timeout=pwnlib.timeout.Timeout.default):
        r"""
        recvline_startswith(delims, keepends=False, timeout=default) -> bytes

        Keep receiving lines until one is found that starts with one of
        `delims`.  Returns the last line received.

        If the request is not satisfied before ``timeout`` seconds pass,
        all data is buffered and an empty string (``''``) is returned.

        Arguments:
            delims(str,tuple): List of strings to search for, or string of single characters
            keepends(bool): Return lines with newlines if :const:`True`
            timeout(int): Timeout, in seconds

        Returns:
            The first line received which starts with a delimiter in ``delims``.

        Examples:

            >>> t = tube()
            >>> t.recv_raw = lambda n: b"Hello\nWorld\nXylophone\n"
            >>> t.recvline_startswith((b'W',b'X',b'Y',b'Z'))
            b'World'
            >>> t.recvline_startswith((b'W',b'X',b'Y',b'Z'), True)
            b'Xylophone\n'
            >>> t.recvline_startswith(b'Wo')
            b'World'
        """
        ...

    def recvline_startswithS(self, *a, **kw):
        r"""
        Same as :meth:`recvline_startswith`, but returns a str, decoding the result using `context.encoding`. (note that the binary versions are way faster)
        """
        ...

    def recvline_startswithb(self, *a, **kw):
        r"""
        Same as :meth:`recvline_startswith`, but returns a bytearray
        """
        ...

    def recvlineb(self, *a, **kw):
        r"""
        Same as :meth:`recvline`, but returns a bytearray
        """
        ...

    def recvlines(self, numlines=1048576, keepends=False, timeout=pwnlib.timeout.Timeout.default):
        r"""
        recvlines(numlines, keepends=False, timeout=default) -> list of bytes objects

        Receive up to ``numlines`` lines.

        A "line" is any sequence of bytes terminated by the byte sequence
        set by :attr:`newline`, which defaults to ``'\n'``.

        If the request is not satisfied before ``timeout`` seconds pass,
        all data is buffered and an empty string (``''``) is returned.

        Arguments:
            numlines(int): Maximum number of lines to receive
            keepends(bool): Keep newlines at the end of each line (:const:`False`).
            timeout(int): Maximum timeout

        Raises:
            exceptions.EOFError: The connection closed before the request could be satisfied

        Returns:
            A string containing bytes received from the socket,
            or ``''`` if a timeout occurred while waiting.

        Examples:

            >>> t = tube()
            >>> t.recv_raw = lambda n: b'\n'
            >>> t.recvlines(3)
            [b'', b'', b'']
            >>> t.recv_raw = lambda n: b'Foo\nBar\nBaz\n'
            >>> t.recvlines(3)
            [b'Foo', b'Bar', b'Baz']
            >>> t.recvlines(3, True)
            [b'Foo\n', b'Bar\n', b'Baz\n']
        """
        ...

    def recvlinesS(self, numlines=1048576, keepends=False, timeout=pwnlib.timeout.Timeout.default):
        r"""
        recvlinesS(numlines, keepends=False, timeout=default) -> str list

        This function is identical to :meth:`recvlines`, but decodes
        the received bytes into string using :func:`context.encoding`.
        You should use :meth:`recvlines` whenever possible for better performance.

        Examples:

            >>> t = tube()
            >>> t.recv_raw = lambda n: b'\n'
            >>> t.recvlinesS(3)
            ['', '', '']
            >>> t.recv_raw = lambda n: b'Foo\nBar\nBaz\n'
            >>> t.recvlinesS(3)
            ['Foo', 'Bar', 'Baz']
        """
        ...

    def recvlinesb(self, numlines=1048576, keepends=False, timeout=pwnlib.timeout.Timeout.default):
        r"""
        recvlinesb(numlines, keepends=False, timeout=default) -> bytearray list

        This function is identical to :meth:`recvlines`, but returns a bytearray.

        Examples:

            >>> t = tube()
            >>> t.recv_raw = lambda n: b'\n'
            >>> t.recvlinesb(3)
            [bytearray(b''), bytearray(b''), bytearray(b'')]
            >>> t.recv_raw = lambda n: b'Foo\nBar\nBaz\n'
            >>> t.recvlinesb(3)
            [bytearray(b'Foo'), bytearray(b'Bar'), bytearray(b'Baz')]
        """
        ...

    def recvn(self, numb, timeout=pwnlib.timeout.Timeout.default):
        r"""
        recvn(numb, timeout = default) -> str

        Receives exactly `n` bytes.

        If the request is not satisfied before ``timeout`` seconds pass,
        all data is buffered and an empty string (``''``) is returned.

        Raises:
            exceptions.EOFError: The connection closed before the request could be satisfied

        Returns:
            A string containing bytes received from the socket,
            or ``''`` if a timeout occurred while waiting.

        Examples:

            >>> t = tube()
            >>> data = b'hello world'
            >>> t.recv_raw = lambda *a: data
            >>> t.recvn(len(data)) == data
            True
            >>> t.recvn(len(data)+1) == data + data[:1]
            True
            >>> t.recv_raw = lambda *a: None
            >>> # The remaining data is buffered
            >>> t.recv() == data[1:]
            True
            >>> t.recv_raw = lambda *a: time.sleep(0.01) or b'a'
            >>> t.recvn(10, timeout=0.05)
            b''
            >>> t.recvn(10, timeout=0.06) # doctest: +ELLIPSIS
            b'aaaaaa...'
        """
        ...

    def recvnS(self, *a, **kw):
        r"""
        Same as :meth:`recvn`, but returns a str, decoding the result using `context.encoding`. (note that the binary versions are way faster)
        """
        ...

    def recvnb(self, *a, **kw):
        r"""
        Same as :meth:`recvn`, but returns a bytearray
        """
        ...

    def recvpred(self, pred, timeout=pwnlib.timeout.Timeout.default):
        r"""
        recvpred(pred, timeout = default) -> bytes

        Receives one byte at a time from the tube, until ``pred(all_bytes)``
        evaluates to True.

        If the request is not satisfied before ``timeout`` seconds pass,
        all data is buffered and an empty string (``''``) is returned.

        Arguments:
            pred(callable): Function to call, with the currently-accumulated data.
            timeout(int): Timeout for the operation

        Raises:
            exceptions.EOFError: The connection is closed

        Returns:
            A bytes object containing bytes received from the socket,
            or ``''`` if a timeout occurred while waiting.
        """
        ...

    def recvpredS(self, *a, **kw):
        r"""
        Same as :meth:`recvpred`, but returns a str, decoding the result using `context.encoding`. (note that the binary versions are way faster)
        """
        ...

    def recvpredb(self, *a, **kw):
        r"""
        Same as :meth:`recvpred`, but returns a bytearray
        """
        ...

    def recvregex(self, regex, exact=False, timeout=pwnlib.timeout.Timeout.default):
        r"""
        recvregex(regex, exact=False, timeout=default) -> bytes

        Wrapper around :func:`recvpred`, which will return when a regex
        matches the string in the buffer.

        By default :func:`re.RegexObject.search` is used, but if `exact` is
        set to True, then :func:`re.RegexObject.match` will be used instead.

        If the request is not satisfied before ``timeout`` seconds pass,
        all data is buffered and an empty string (``''``) is returned.
        """
        ...

    def recvregexS(self, *a, **kw):
        r"""
        Same as :meth:`recvregex`, but returns a str, decoding the result using `context.encoding`. (note that the binary versions are way faster)
        """
        ...

    def recvregexb(self, *a, **kw):
        r"""
        Same as :meth:`recvregex`, but returns a bytearray
        """
        ...

    def recvrepeat(self, timeout=pwnlib.timeout.Timeout.default):
        r"""
        recvrepeat(timeout=default) -> bytes

        Receives data until a timeout or EOF is reached.

        Examples:

            >>> data = [
            ... b'd',
            ... b'', # simulate timeout
            ... b'c',
            ... b'b',
            ... b'a',
            ... ]
            >>> def delayrecv(n, data=data):
            ...     return data.pop()
            >>> t = tube()
            >>> t.recv_raw = delayrecv
            >>> t.recvrepeat(0.2)
            b'abc'
            >>> t.recv()
            b'd'
        """
        ...

    def recvrepeatS(self, *a, **kw):
        r"""
        Same as :meth:`recvrepeat`, but returns a str, decoding the result using `context.encoding`. (note that the binary versions are way faster)
        """
        ...

    def recvrepeatb(self, *a, **kw):
        r"""
        Same as :meth:`recvrepeat`, but returns a bytearray
        """
        ...

    def recvuntil(self, delims, drop=False, timeout=pwnlib.timeout.Timeout.default):
        r"""
        recvuntil(delims, drop=False, timeout=default) -> bytes

        Receive data until one of `delims` is encountered.

        If the request is not satisfied before ``timeout`` seconds pass,
        all data is buffered and an empty string (``''``) is returned.

        arguments:
            delims(bytes,tuple): Byte-string of delimiters characters, or list of delimiter byte-strings.
            drop(bool): Drop the ending.  If :const:`True` it is removed from the end of the return value.

        Raises:
            exceptions.EOFError: The connection closed before the request could be satisfied

        Returns:
            A string containing bytes received from the socket,
            or ``''`` if a timeout occurred while waiting.

        Examples:

            >>> t = tube()
            >>> t.recv_raw = lambda n: b"Hello World!"
            >>> t.recvuntil(b' ')
            b'Hello '
            >>> _=t.clean(0)
            >>> # Matches on 'o' in 'Hello'
            >>> t.recvuntil((b' ',b'W',b'o',b'r'))
            b'Hello'
            >>> _=t.clean(0)
            >>> # Matches expressly full string
            >>> t.recvuntil(b' Wor')
            b'Hello Wor'
            >>> _=t.clean(0)
            >>> # Matches on full string, drops match
            >>> t.recvuntil(b' Wor', drop=True)
            b'Hello'

            >>> # Try with regex special characters
            >>> t = tube()
            >>> t.recv_raw = lambda n: b"Hello|World"
            >>> t.recvuntil(b'|', drop=True)
            b'Hello'
        """
        ...

    def recvuntilS(self, *a, **kw):
        r"""
        Same as :meth:`recvuntil`, but returns a str, decoding the result using `context.encoding`. (note that the binary versions are way faster)
        """
        ...

    def recvuntilb(self, *a, **kw):
        r"""
        Same as :meth:`recvuntil`, but returns a bytearray
        """
        ...

    def removeHandler(self, handler):
        r"""
        removeHandler(handler)

        Remove the specified handler from the underlying logger.
        """
        ...

    def send(self, data):
        r"""
        send(data)

        Sends data.

        If log level ``DEBUG`` is enabled, also prints out the data
        received.

        If it is not possible to send anymore because of a closed
        connection, it raises ``exceptions.EOFError``

        Examples:

            >>> def p(x): print(repr(x))
            >>> t = tube()
            >>> t.send_raw = p
            >>> t.send(b'hello')
            b'hello'
        """
        ...

    def send_raw(self, data):
        r"""
        send_raw(data)

        Should not be called directly. Sends data to the tube.

        Should return ``exceptions.EOFError``, if it is unable to send any
        more, because of a close tube.
        """
        ...

    def sendafter(self, delim, data, timeout=pwnlib.timeout.Timeout.default):
        r"""
        sendafter(delim, data, timeout = default) -> str

        A combination of ``recvuntil(delim, timeout=timeout)`` and ``send(data)``.
        """
        ...

    def sendline(self, line=b''):
        r"""
        sendline(data)

        Shorthand for ``t.send(data + t.newline)``.

        Examples:

            >>> def p(x): print(repr(x))
            >>> t = tube()
            >>> t.send_raw = p
            >>> t.sendline(b'hello')
            b'hello\n'
            >>> t.newline = b'\r\n'
            >>> t.sendline(b'hello')
            b'hello\r\n'
        """
        ...

    def sendlineafter(self, delim, data, timeout=pwnlib.timeout.Timeout.default):
        r"""
        sendlineafter(delim, data, timeout = default) -> str

        A combination of ``recvuntil(delim, timeout=timeout)`` and ``sendline(data)``.
        """
        ...

    def sendlines(self, lines=[]):

        ...

    def sendlinethen(self, delim, data, timeout=pwnlib.timeout.Timeout.default):
        r"""
        sendlinethen(delim, data, timeout = default) -> str

        A combination of ``sendline(data)`` and ``recvuntil(delim, timeout=timeout)``.
        """
        ...

    def sendthen(self, delim, data, timeout=pwnlib.timeout.Timeout.default):
        r"""
        sendthen(delim, data, timeout = default) -> str

        A combination of ``send(data)`` and ``recvuntil(delim, timeout=timeout)``.
        """
        ...

    def setLevel(self, level):
        r"""
        setLevel(level)

        Set the logging level for the underlying logger.
        """
        ...

    def settimeout(self, timeout):
        r"""
        settimeout(timeout)

        Set the timeout for receiving operations. If the string "default"
        is given, then :data:`context.timeout` will be used. If None is given,
        then there will be no timeout.

        Examples:

            >>> t = tube()
            >>> t.settimeout_raw = lambda t: None
            >>> t.settimeout(3)
            >>> t.timeout == 3
            True
        """
        ...

    def settimeout_raw(self, timeout):
        r"""
        settimeout_raw(timeout)

        Should not be called directly. Sets the timeout for
        the tube.
        """
        ...

    def shutdown(self, direction='send'):
        r"""
        shutdown(direction = "send")

        Closes the tube for futher reading or writing depending on `direction`.

        Arguments:
          direction(str): Which direction to close; "in", "read" or "recv"
            closes the tube in the ingoing direction, "out", "write" or "send"
            closes it in the outgoing direction.

        Returns:
          :const:`None`

        Examples:

            >>> def p(x): print(x)
            >>> t = tube()
            >>> t.shutdown_raw = p
            >>> _=list(map(t.shutdown, ('in', 'read', 'recv', 'out', 'write', 'send')))
            recv
            recv
            recv
            send
            send
            send
            >>> t.shutdown('bad_value') #doctest: +ELLIPSIS
            Traceback (most recent call last):
            ...
            KeyError: "direction must be in ['in', 'out', 'read', 'recv', 'send', 'write']"
        """
        ...

    def shutdown_raw(self, direction):
        r"""
        shutdown_raw(direction)

        Should not be called directly.  Closes the tube for further reading or
        writing.
        """
        ...

    def spawn_process(self, *args, **kwargs):
        r"""
        Spawns a new process having this tube as stdin, stdout and stderr.

        Takes the same arguments as :class:`subprocess.Popen`.
        """
        ...

    def stream(self, line_mode=True):
        r"""
        stream()

        Receive data until the tube exits, and print it to stdout.

        Similar to :func:`interactive`, except that no input is sent.

        Similar to ``print(tube.recvall())`` except that data is printed
        as it is received, rather than after all data is received.

        Arguments:
            line_mode(bool): Whether to receive line-by-line or raw data.

        Returns:
            All data printed.
        """
        ...

    def success(self, message, *args, **kwargs):
        r"""
        success(message, *args, **kwargs)

        Logs a success message.
        """
        ...

    def timeout_change(self):
        r"""
        Informs the raw layer of the tube that the timeout has changed.

        Should not be called directly.

        Inherited from :class:`Timeout`.
        """
        ...

    def u16(self, *a, **kw):

        ...

    def u32(self, *a, **kw):

        ...

    def u64(self, *a, **kw):

        ...

    def u8(self, *a, **kw):

        ...

    def unpack(self, *a, **kw):

        ...

    def unread(self, *a, **kw):
        r"""
        Alias for :meth:`unrecv`
        """
        ...

    def unrecv(self, data):
        r"""
        unrecv(data)

        Puts the specified data back at the beginning of the receive
        buffer.

        Examples:

            >>> t = tube()
            >>> t.recv_raw = lambda n: b'hello'
            >>> t.recv()
            b'hello'
            >>> t.recv()
            b'hello'
            >>> t.unrecv(b'world')
            >>> t.recv()
            b'world'
            >>> t.recv()
            b'hello'
        """
        ...

    def wait(self, timeout=pwnlib.timeout.Timeout.default):
        r"""
        Waits until the tube is closed.
        """
        ...

    def wait_for_close(self, timeout=pwnlib.timeout.Timeout.default):
        r"""
        Waits until the tube is closed.
        """
        ...

    def waitfor(self, *args, **kwargs):
        r"""
        Alias for :meth:`progress`.
        """
        ...

    def warn(self, *args, **kwargs):
        r"""
        Alias for :meth:`warning`.
        """
        ...

    def warn_once(self, *args, **kwargs):
        r"""
        Alias for :meth:`warning_once`.
        """
        ...

    def warning(self, message, *args, **kwargs):
        r"""
        warning(message, *args, **kwargs)

        Logs a warning message.
        """
        ...

    def warning_once(self, message, *args, **kwargs):
        r"""
        warning_once(message, *args, **kwargs)

        Logs a warning message.  The same message is never printed again.
        """
        ...

    def write(self, *a, **kw):
        r"""
        Alias for :meth:`send`
        """
        ...

    def write_raw(self, *a, **kw):
        r"""
        Alias for :meth:`send_raw`
        """
        ...

    def writeafter(self, *a, **kw):
        r"""
        Alias for :meth:`sendafter`
        """
        ...

    def writeline(self, *a, **kw):
        r"""
        Alias for :meth:`sendline`
        """
        ...

    def writelineafter(self, *a, **kw):
        r"""
        Alias for :meth:`sendlineafter`
        """
        ...

    def writelines(self, *a, **kw):
        r"""
        Alias for :meth:`sendlines`
        """
        ...

    def writelinethen(self, *a, **kw):
        r"""
        Alias for :meth:`sendlinethen`
        """
        ...

    def writethen(self, *a, **kw):
        r"""
        Alias for :meth:`sendthen`
        """
        ...


import pwnlib.ui

def more(text):
    r"""
    more(text)

    Shows text like the command line tool ``more``.

    It not in term_mode, just prints the data to the screen.

    Arguments:
      text(str):  The text to show.

    Returns:
      :const:`None`

    Tests:

    .. doctest::
       :skipif: branch_dev
   
        >>> more("text")
        text
        >>> p = testpwnproc("more('text\\n' * (term.height + 2))")
        >>> p.send(b"x")
        >>> data = p.recvall()
        >>> b"text" in data or data
        True
    """
    ...

def options(prompt, opts, default=None):
    r"""
    Presents the user with a prompt (typically in the
    form of a question) and a number of options.

    Arguments:
      prompt (str): The prompt to show
      opts (list): The options to show to the user
      default: The default option to choose

    Returns:
      The users choice in the form of an integer.

    Examples:

    .. doctest::
       :skipif: branch_dev

        >>> options("Select a color", ("red", "green", "blue"), "green")
        Traceback (most recent call last):
        ...
        ValueError: options(): default must be a number or None

    Tests:

    .. doctest::
       :skipif: branch_dev

        >>> p = testpwnproc("print(options('select a color', ('red', 'green', 'blue')))")
        >>> p.sendline(b"\33[C\33[A\33[A\33[B\33[1;5A\33[1;5B 0310")
        >>> _ = p.recvall()
        >>> saved_stdin = sys.stdin
        >>> try:
        ...     sys.stdin = io.TextIOWrapper(io.BytesIO(b"\n4\n\n3\n"))
        ...     with context.local(log_level="INFO"):
        ...         options("select a color A", ("red", "green", "blue"), 0)
        ...         options("select a color B", ("red", "green", "blue"))
        ... finally:
        ...     sys.stdin = saved_stdin
         [?] select a color A
               1) red
               2) green
               3) blue
             Choice [1] 0
         [?] select a color B
               1) red
               2) green
               3) blue
             Choice  [?] select a color B
               1) red
               2) green
               3) blue
             Choice  [?] select a color B
               1) red
               2) green
               3) blue
             Choice 2
    """
    ...

def pause(n=None):
    r"""
    Waits for either user input or a specific number of seconds.

    Examples:

    .. doctest::
       :skipif: branch_dev

        >>> with context.local(log_level="INFO"):
        ...     pause(1)
        [x] Waiting
        [x] Waiting: 1...
        [+] Waiting: Done
        >>> pause("whatever")
        Traceback (most recent call last):
        ...
        ValueError: pause(): n must be a number or None

    Tests:

    .. doctest::
       :skipif: branch_dev

        >>> saved_stdin = sys.stdin
        >>> try:
        ...     sys.stdin = io.TextIOWrapper(io.BytesIO(b"\n"))
        ...     with context.local(log_level="INFO"):
        ...         pause()
        ... finally:
        ...     sys.stdin = saved_stdin
        [*] Paused (press enter to continue)
        >>> p = testpwnproc("pause()")
        >>> b"Paused" in p.recvuntil(b"press any")
        True
        >>> p.send(b"x")
        >>> _ = p.recvall()
    """
    ...

def testpwnproc(cmd):

    ...

def yesno(prompt, default=None):
    r"""
    Presents the user with prompt (typically in the form of question)
    which the user must answer yes or no.

    Arguments:
      prompt (str): The prompt to show
      default: The default option;  `True` means "yes"

    Returns:
      `True` if the answer was "yes", `False` if "no"

    Examples:

    .. doctest::
       :skipif: branch_dev

        >>> yesno("A number:", 20)
        Traceback (most recent call last):
        ...
        ValueError: yesno(): default must be a boolean or None
        >>> saved_stdin = sys.stdin
        >>> try:
        ...     sys.stdin = io.TextIOWrapper(io.BytesIO(b"x\nyes\nno\n\n"))
        ...     yesno("is it good 1")
        ...     yesno("is it good 2", True)
        ...     yesno("is it good 3", False)
        ... finally:
        ...     sys.stdin = saved_stdin
         [?] is it good 1 [yes/no] Please answer yes or no
         [?] is it good 1 [yes/no] True
         [?] is it good 2 [Yes/no] False
         [?] is it good 3 [yes/No] False

    Tests:

    .. doctest::
       :skipif: branch_dev

        >>> p = testpwnproc("print(yesno('is it ok??'))")
        >>> b"is it ok" in p.recvuntil("??")
        True
        >>> p.sendline(b"x\nny")
        >>> b"True" in p.recvall()
        True
    """
    ...


import pwnlib.update


import pwnlib.useragents


import pwnlib.util


import pwnlib.util.crc

class BitPolynom:
    r"""
    Class for representing GF(2)[X], i.e. the field of polynomials over
    GF(2).

    In practice the polynomials are represented as numbers such that `x**n`
    corresponds to `1 << n`. In this representation calculations are easy: Just
    do everything as normal, but forget about everything the carries.

    Addition becomes xor and multiplication becomes carry-less multiplication.

    Examples:

        >>> p1 = BitPolynom("x**3 + x + 1")
        >>> p1
        BitPolynom('x**3 + x + 1')
        >>> int(p1)
        11
        >>> p1 == BitPolynom(11)
        True
        >>> p2 = BitPolynom("x**2 + x + 1")
        >>> p1 + p2
        BitPolynom('x**3 + x**2')
        >>> p1 * p2
        BitPolynom('x**5 + x**4 + 1')
        >>> p1 // p2
        BitPolynom('x + 1')
        >>> p1 % p2
        BitPolynom('x')
        >>> d, r = divmod(p1, p2)
        >>> d * p2 + r == p1
        True
        >>> BitPolynom(-1)
        Traceback (most recent call last):
            ...
        ValueError: Polynomials cannot be negative: -1
        >>> BitPolynom('y')
        Traceback (most recent call last):
            ...
        ValueError: Not a valid polynomial: y
    """
    def __add__(self, other):

        ...

    def __and__(self, other):

        ...

    def __cmp__(self, other):

        ...

    def __div__(self, other):

        ...

    def __divmod__(self, other):

        ...

    def __eq__(self, other):
        r"""
        Return self==value.
        """
        ...

    def __floordiv__(self, other):

        ...

    def __hash__(self):
        r"""
        Return hash(self).
        """
        ...

    def __init__(self, n):
        r"""
        Initialize self.  See help(type(self)) for accurate signature.
        """
        ...

    def __int__(self):

        ...

    def __lshift__(self, other):

        ...

    def __mod__(self, other):

        ...

    def __mul__(self, other):

        ...

    def __or__(self, other):

        ...

    def __pow__(self, other):

        ...

    def __radd__(self, other):

        ...

    def __rand__(self, other):

        ...

    def __rdiv__(self, other):

        ...

    def __rdivmod__(self, other):

        ...

    def __repr__(self):
        r"""
        Return repr(self).
        """
        ...

    def __rfloordiv__(self, other):

        ...

    def __rlshift__(self, other):

        ...

    def __rmod__(self, other):

        ...

    def __rmul__(self, other):

        ...

    def __ror__(self, other):

        ...

    def __rrshift__(self, other):

        ...

    def __rshift__(self, other):

        ...

    def __rsub__(self, other):

        ...

    def __rxor__(self, other):

        ...

    def __sub__(self, other):

        ...

    def __xor__(self, other):

        ...

    def degree(self):
        r"""
        Returns the degree of the polynomial.

        Examples:

            >>> BitPolynom(0).degree()
            0
            >>> BitPolynom(1).degree()
            0
            >>> BitPolynom(2).degree()
            1
            >>> BitPolynom(7).degree()
            2
            >>> BitPolynom((1 << 10) - 1).degree()
            9
            >>> BitPolynom(1 << 10).degree()
            10
        """
        ...


import pwnlib.util.cyclic

def cyclic(length=None, alphabet=None, n=None):
    r"""
    cyclic(length = None, alphabet = None, n = None) -> list/str

    A simple wrapper over :func:`de_bruijn`. This function returns at most
    `length` elements.

    If the given alphabet is a string, a string is returned from this function. Otherwise
    a list is returned.

    Arguments:
        length: The desired length of the list or None if the entire sequence is desired.
        alphabet: List or string to generate the sequence over.
        n(int): The length of subsequences that should be unique.

    Notes:
        The maximum length is `len(alphabet)**n`.

        The default values for `alphabet` and `n` restrict the total space to ~446KB.

        If you need to generate a longer cyclic pattern, provide a longer `alphabet`,
        or if possible a larger `n`.

    Example:

        Cyclic patterns are usually generated by providing a specific `length`.

        >>> cyclic(20)
        b'aaaabaaacaaadaaaeaaa'

        >>> cyclic(32)
        b'aaaabaaacaaadaaaeaaafaaagaaahaaa'

        The `alphabet` and `n` arguments will control the actual output of the pattern

        >>> cyclic(20, alphabet=string.ascii_uppercase)
        'AAAABAAACAAADAAAEAAA'

        >>> cyclic(20, n=8)
        b'aaaaaaaabaaaaaaacaaa'

        >>> cyclic(20, n=2)
        b'aabacadaeafagahaiaja'

        The size of `n` and `alphabet` limit the maximum length that can be generated.
        Without providing `length`, the entire possible cyclic space is generated.

        >>> cyclic(alphabet = "ABC", n = 3)
        'AAABAACABBABCACBACCBBBCBCCC'

        >>> cyclic(length=512, alphabet = "ABC", n = 3)
        Traceback (most recent call last):
        ...
        PwnlibException: Can't create a pattern length=512 with len(alphabet)==3 and n==3

        The `alphabet` can be set in `context`, which is useful for circumstances
        when certain characters are not allowed.  See :obj:`.context.cyclic_alphabet`.

        >>> context.cyclic_alphabet = "ABC"
        >>> cyclic(10)
        b'AAAABAAACA'

        The original values can always be restored with:

        >>> context.clear()

        The following just a test to make sure the length is correct.

        >>> alphabet, n = range(30), 3
        >>> len(alphabet)**n, len(cyclic(alphabet = alphabet, n = n))
        (27000, 27000)
    """
    ...

def cyclic_find(subseq, alphabet=None, n=None):
    r"""
    cyclic_find(subseq, alphabet = None, n = None) -> int

    Calculates the position of a substring into a De Bruijn sequence.

    .. todo:

       "Calculates" is an overstatement. It simply traverses the list.

       There exists better algorithms for this, but they depend on generating
       the De Bruijn sequence in another fashion. Somebody should look at it:

       https://www.sciencedirect.com/science/article/pii/S0012365X00001175

    Arguments:
        subseq: The subsequence to look for. This can be a string, a list or an
                integer. If an integer is provided it will be packed as a
                little endian integer.
        alphabet: List or string to generate the sequence over.
                  By default, uses :obj:`.context.cyclic_alphabet`.
        n(int): The length of subsequences that should be unique.
                By default, uses :obj:`.context.cyclic_size`.

    Examples:

        Let's generate an example cyclic pattern.

        >>> cyclic(16)
        b'aaaabaaacaaadaaa'

        Note that 'baaa' starts at offset 4.  The `cyclic_find` routine shows us this:

        >>> cyclic_find(b'baaa')
        4

        The *default* length of a subsequence generated by `cyclic` is `4`.
        If a longer value is submitted, it is automatically truncated to four bytes.

        >>> cyclic_find(b'baaacaaa')
        4

        If you provided e.g. `n=8` to `cyclic` to generate larger subsequences,
        you must explicitly provide that argument.

        >>> cyclic_find(b'baaacaaa', n=8)
        3515208

        We can generate a large cyclic pattern, and grab a subset of it to
        check a deeper offset.

        >>> cyclic_find(cyclic(1000)[514:518])
        514

        Instead of passing in the byte representation of the pattern, you can
        also pass in the integer value.  Note that this is sensitive to the
        selected endianness via `context.endian`.

        >>> cyclic_find(0x61616162)
        4
        >>> cyclic_find(0x61616162, endian='big')
        1

        You can use anything for the cyclic pattern, including non-printable
        characters.

        >>> cyclic_find(0x00000000, alphabet=unhex('DEADBEEF00'))
        621
    """
    ...

class cyclic_gen:
    r"""
    Creates a stateful cyclic generator which can generate sequential chunks of de Bruijn sequences.

    >>> g = cyclic_gen() # Create a generator
    >>> g.get(4) # Get a chunk of length 4
    b'aaaa'
    >>> g.get(4) # Get a chunk of length 4
    b'baaa'
    >>> g.get(8) # Get a chunk of length 8
    b'caaadaaa'
    >>> g.get(4) # Get a chunk of length 4
    b'eaaa'
    >>> g.find(b'caaa') # Position 8, which is in chunk 2 at index 0
    (8, 2, 0)
    >>> g.find(b'aaaa') # Position 0, which is in chunk 0 at index 0
    (0, 0, 0)
    >>> g.find(b'baaa') # Position 4, which is in chunk 1 at index 0
    (4, 1, 0)
    >>> g.find(b'aaad') # Position 9, which is in chunk 2 at index 1
    (9, 2, 1)
    >>> g.find(b'aada') # Position 10, which is in chunk 2 at index 2
    (10, 2, 2)
    >>> g.get() # Get the rest of the sequence
    b'faaagaaahaaaiaaajaaa...yyxzyzxzzyxzzzyyyyzyyzzyzyzzzz'
    >>> g.find(b'racz') # Position 7760, which is in chunk 4 at index 7740
    (7760, 4, 7740)
    >>> g.get(12) # Generator is exhausted
    Traceback (most recent call last):
      ...
    StopIteration

    >>> g = cyclic_gen(string.ascii_uppercase, n=8) # Custom alphabet and item size
    >>> g.get(12) # Get a chunk of length 12
    'AAAAAAAABAAA'
    >>> g.get(18) # Get a chunk of length 18
    'AAAACAAAAAAADAAAAA'
    >>> g.find('CAAAAAAA') # Position 16, which is in chunk 1 at index 4
    (16, 1, 4)
    """
    def __init__(self, alphabet=None, n=None):
        r"""
        Initialize self.  See help(type(self)) for accurate signature.
        """
        ...

    def find(self, subseq):
        r"""
        Find a chunk and subindex from all the generates de Bruijn sequences.

        >>> g = cyclic_gen()
        >>> g.get(4)
        b'aaaa'
        >>> g.get(4)
        b'baaa'
        >>> g.get(8)
        b'caaadaaa'
        >>> g.get(4)
        b'eaaa'
        >>> g.find(b'caaa') # Position 8, which is in chunk 2 at index 0
        (8, 2, 0)
        """
        ...

    def get(self, length=None):
        r"""
        Get the next de Bruijn sequence from this generator.

        >>> g = cyclic_gen()
        >>> g.get(4) # Get a chunk of length 4
        b'aaaa'
        >>> g.get(4) # Get a chunk of length 4
        b'baaa'
        >>> g.get(8) # Get a chunk of length 8
        b'caaadaaa'
        >>> g.get(4) # Get a chunk of length 4
        b'eaaa'
        >>> g.get() # Get the rest of the sequence
        b'faaagaaahaaaiaaajaaa...yyxzyzxzzyxzzzyyyyzyyzzyzyzzzz'
        >>> g.get(12) # Generator is exhausted
        Traceback (most recent call last):
          ...
        StopIteration
        """
        ...

def cyclic_metasploit(length=None, sets=None):
    r"""
    cyclic_metasploit(length = None, sets = [ string.ascii_uppercase, string.ascii_lowercase, string.digits ]) -> str

    A simple wrapper over :func:`metasploit_pattern`. This function returns a
    string of length `length`.

    Arguments:
        length: The desired length of the string or None if the entire sequence is desired.
        sets: List of strings to generate the sequence over.

    Example:
        >>> cyclic_metasploit(32)
        b'Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab'
        >>> cyclic_metasploit(sets = [b"AB",b"ab",b"12"])
        b'Aa1Aa2Ab1Ab2Ba1Ba2Bb1Bb2'
        >>> cyclic_metasploit()[1337:1341]
        b'5Bs6'
        >>> len(cyclic_metasploit())
        20280
    """
    ...

def cyclic_metasploit_find(subseq, sets=None):
    r"""
    cyclic_metasploit_find(subseq, sets = [ string.ascii_uppercase, string.ascii_lowercase, string.digits ]) -> int

    Calculates the position of a substring into a Metasploit Pattern sequence.

    Arguments:
        subseq: The subsequence to look for. This can be a string or an
                integer. If an integer is provided it will be packed as a
                little endian integer.
        sets: List of strings to generate the sequence over.

    Examples:

        >>> cyclic_metasploit_find(cyclic_metasploit(1000)[514:518])
        514
        >>> cyclic_metasploit_find(0x61413161)
        4
    """
    ...

def de_bruijn(alphabet=None, n=None):
    r"""
    de_bruijn(alphabet = None, n = None) -> generator

    Generator for a sequence of unique substrings of length `n`. This is implemented using a
    De Bruijn Sequence over the given `alphabet`.

    The returned generator will yield up to ``len(alphabet)**n`` elements.

    Arguments:
        alphabet: List or string to generate the sequence over.
        n(int): The length of subsequences that should be unique.
    """
    ...

def metasploit_pattern(sets=None):
    r"""
    metasploit_pattern(sets = [ string.ascii_uppercase, string.ascii_lowercase, string.digits ]) -> generator

    Generator for a sequence of characters as per Metasploit Framework's
    `Rex::Text.pattern_create` (aka `pattern_create.rb`).

    The returned generator will yield up to
    ``len(sets) * reduce(lambda x,y: x*y, map(len, sets))`` elements.

    Arguments:
        sets: List of strings to generate the sequence over.
    """
    ...


import pwnlib.util.fiddling

def b64d(s):
    r"""
    b64d(s) -> str

    Base64 decodes a string

    Example:

       >>> b64d('dGVzdA==')
       b'test'
    """
    ...

def b64e(s):
    r"""
    b64e(s) -> str

    Base64 encodes a string

    Example:

       >>> b64e(b"test")
       'dGVzdA=='
   
    """
    ...

def bits(s, endian='big', zero=0, one=1):
    r"""
    bits(s, endian = 'big', zero = 0, one = 1) -> list

    Converts the argument into a list of bits.

    Arguments:
        s: A string or number to be converted into bits.
        endian (str): The binary endian, default 'big'.
        zero: The representing a 0-bit.
        one: The representing a 1-bit.

    Returns:
        A list consisting of the values specified in `zero` and `one`.

    Examples:

        >>> bits(511, zero = "+", one = "-")
        ['+', '+', '+', '+', '+', '+', '+', '-', '-', '-', '-', '-', '-', '-', '-', '-']
        >>> sum(bits(b"test"))
        17
        >>> bits(0)
        [0, 0, 0, 0, 0, 0, 0, 0]
    """
    ...

def bits_str(s, endian='big', zero='0', one='1'):
    r"""
    bits_str(s, endian = 'big', zero = '0', one = '1') -> str

    A wrapper around :func:`bits`, which converts the output into a string.

    Examples:

       >>> bits_str(511)
       '0000000111111111'
       >>> bits_str(b"bits_str", endian = "little")
       '0100011010010110001011101100111011111010110011100010111001001110'
    """
    ...

def bitswap(s):
    r"""
    bitswap(s) -> str

    Reverses the bits in every byte of a given string.

    Example:
        >>> bitswap(b"1234")
        b'\x8cL\xcc,'
    """
    ...

def bitswap_int(n, width):
    r"""
    bitswap_int(n) -> int

    Reverses the bits of a numbers and returns the result as a new number.

    Arguments:
        n (int): The number to swap.
        width (int): The width of the integer

    Examples:
        >>> hex(bitswap_int(0x1234, 8))
        '0x2c'
        >>> hex(bitswap_int(0x1234, 16))
        '0x2c48'
        >>> hex(bitswap_int(0x1234, 24))
        '0x2c4800'
        >>> hex(bitswap_int(0x1234, 25))
        '0x589000'
    """
    ...

def bnot(value, width=None):
    r"""
    Returns the binary inverse of 'value'.
    """
    ...

def enhex(x):
    r"""
    enhex(x) -> str

    Hex-encodes a string.

    Example:

        >>> enhex(b"test")
        '74657374'
    """
    ...

def hexdump(s, width=16, skip=True, hexii=False, begin=0, style=None, highlight=None, cyclic=False, groupsize=4, total=True):
    r"""
    hexdump(s, width = 16, skip = True, hexii = False, begin = 0, style = None,
                highlight = None, cyclic = False, groupsize=4, total = True) -> str

    Return a hexdump-dump of a string.

    Arguments:
        s(str): The data to hexdump.
        width(int): The number of characters per line
        groupsize(int): The number of characters per group
        skip(bool): Set to True, if repeated lines should be replaced by a "*"
        hexii(bool): Set to True, if a hexii-dump should be returned instead of a hexdump.
        begin(int):  Offset of the first byte to print in the left column
        style(dict): Color scheme to use.
        highlight(iterable): Byte values to highlight.
        cyclic(bool): Attempt to skip consecutive, unmodified cyclic lines
        total(bool): Set to True, if total bytes should be printed

    Returns:
        A hexdump-dump in the form of a string.

    Examples:

        >>> print(hexdump(b"abc"))
        00000000  61 62 63                                            │abc│
        00000003

        >>> print(hexdump(b'A'*32))
        00000000  41 41 41 41  41 41 41 41  41 41 41 41  41 41 41 41  │AAAA│AAAA│AAAA│AAAA│
        *
        00000020

        >>> print(hexdump(b'A'*32, width=8))
        00000000  41 41 41 41  41 41 41 41  │AAAA│AAAA│
        *
        00000020

        >>> print(hexdump(cyclic(32), width=8, begin=0xdead0000, hexii=True))
        dead0000  .a  .a  .a  .a   .b  .a  .a  .a  │
        dead0008  .c  .a  .a  .a   .d  .a  .a  .a  │
        dead0010  .e  .a  .a  .a   .f  .a  .a  .a  │
        dead0018  .g  .a  .a  .a   .h  .a  .a  .a  │
        dead0020

        >>> import struct
        >>> print(hexdump(list(map(struct.Struct("B").pack, range(256)))))
        00000000  00 01 02 03  04 05 06 07  08 09 0a 0b  0c 0d 0e 0f  │····│····│····│····│
        00000010  10 11 12 13  14 15 16 17  18 19 1a 1b  1c 1d 1e 1f  │····│····│····│····│
        00000020  20 21 22 23  24 25 26 27  28 29 2a 2b  2c 2d 2e 2f  │ !"#│$%&'│()*+│,-./│
        00000030  30 31 32 33  34 35 36 37  38 39 3a 3b  3c 3d 3e 3f  │0123│4567│89:;│<=>?│
        00000040  40 41 42 43  44 45 46 47  48 49 4a 4b  4c 4d 4e 4f  │@ABC│DEFG│HIJK│LMNO│
        00000050  50 51 52 53  54 55 56 57  58 59 5a 5b  5c 5d 5e 5f  │PQRS│TUVW│XYZ[│\]^_│
        00000060  60 61 62 63  64 65 66 67  68 69 6a 6b  6c 6d 6e 6f  │`abc│defg│hijk│lmno│
        00000070  70 71 72 73  74 75 76 77  78 79 7a 7b  7c 7d 7e 7f  │pqrs│tuvw│xyz{│|}~·│
        00000080  80 81 82 83  84 85 86 87  88 89 8a 8b  8c 8d 8e 8f  │····│····│····│····│
        00000090  90 91 92 93  94 95 96 97  98 99 9a 9b  9c 9d 9e 9f  │····│····│····│····│
        000000a0  a0 a1 a2 a3  a4 a5 a6 a7  a8 a9 aa ab  ac ad ae af  │····│····│····│····│
        000000b0  b0 b1 b2 b3  b4 b5 b6 b7  b8 b9 ba bb  bc bd be bf  │····│····│····│····│
        000000c0  c0 c1 c2 c3  c4 c5 c6 c7  c8 c9 ca cb  cc cd ce cf  │····│····│····│····│
        000000d0  d0 d1 d2 d3  d4 d5 d6 d7  d8 d9 da db  dc dd de df  │····│····│····│····│
        000000e0  e0 e1 e2 e3  e4 e5 e6 e7  e8 e9 ea eb  ec ed ee ef  │····│····│····│····│
        000000f0  f0 f1 f2 f3  f4 f5 f6 f7  f8 f9 fa fb  fc fd fe ff  │····│····│····│····│
        00000100

        >>> print(hexdump(list(map(struct.Struct("B").pack, range(256))), hexii=True))
        00000000      01  02  03   04  05  06  07   08  09  0a  0b   0c  0d  0e  0f  │
        00000010  10  11  12  13   14  15  16  17   18  19  1a  1b   1c  1d  1e  1f  │
        00000020  20  .!  ."  .#   .$  .%  .&  .'   .(  .)  .*  .+   .,  .-  ..  ./  │
        00000030  .0  .1  .2  .3   .4  .5  .6  .7   .8  .9  .:  .;   .<  .=  .>  .?  │
        00000040  .@  .A  .B  .C   .D  .E  .F  .G   .H  .I  .J  .K   .L  .M  .N  .O  │
        00000050  .P  .Q  .R  .S   .T  .U  .V  .W   .X  .Y  .Z  .[   .\  .]  .^  ._  │
        00000060  .`  .a  .b  .c   .d  .e  .f  .g   .h  .i  .j  .k   .l  .m  .n  .o  │
        00000070  .p  .q  .r  .s   .t  .u  .v  .w   .x  .y  .z  .{   .|  .}  .~  7f  │
        00000080  80  81  82  83   84  85  86  87   88  89  8a  8b   8c  8d  8e  8f  │
        00000090  90  91  92  93   94  95  96  97   98  99  9a  9b   9c  9d  9e  9f  │
        000000a0  a0  a1  a2  a3   a4  a5  a6  a7   a8  a9  aa  ab   ac  ad  ae  af  │
        000000b0  b0  b1  b2  b3   b4  b5  b6  b7   b8  b9  ba  bb   bc  bd  be  bf  │
        000000c0  c0  c1  c2  c3   c4  c5  c6  c7   c8  c9  ca  cb   cc  cd  ce  cf  │
        000000d0  d0  d1  d2  d3   d4  d5  d6  d7   d8  d9  da  db   dc  dd  de  df  │
        000000e0  e0  e1  e2  e3   e4  e5  e6  e7   e8  e9  ea  eb   ec  ed  ee  ef  │
        000000f0  f0  f1  f2  f3   f4  f5  f6  f7   f8  f9  fa  fb   fc  fd  fe  ##  │
        00000100

        >>> print(hexdump(b'X' * 64))
        00000000  58 58 58 58  58 58 58 58  58 58 58 58  58 58 58 58  │XXXX│XXXX│XXXX│XXXX│
        *
        00000040

        >>> print(hexdump(b'X' * 64, skip=False))
        00000000  58 58 58 58  58 58 58 58  58 58 58 58  58 58 58 58  │XXXX│XXXX│XXXX│XXXX│
        00000010  58 58 58 58  58 58 58 58  58 58 58 58  58 58 58 58  │XXXX│XXXX│XXXX│XXXX│
        00000020  58 58 58 58  58 58 58 58  58 58 58 58  58 58 58 58  │XXXX│XXXX│XXXX│XXXX│
        00000030  58 58 58 58  58 58 58 58  58 58 58 58  58 58 58 58  │XXXX│XXXX│XXXX│XXXX│
        00000040

        >>> print(hexdump(fit({0x10: b'X'*0x20, 0x50-1: b'\xff'*20}, length=0xc0) + b'\x00'*32))
        00000000  61 61 61 61  62 61 61 61  63 61 61 61  64 61 61 61  │aaaa│baaa│caaa│daaa│
        00000010  58 58 58 58  58 58 58 58  58 58 58 58  58 58 58 58  │XXXX│XXXX│XXXX│XXXX│
        *
        00000030  6d 61 61 61  6e 61 61 61  6f 61 61 61  70 61 61 61  │maaa│naaa│oaaa│paaa│
        00000040  71 61 61 61  72 61 61 61  73 61 61 61  74 61 61 ff  │qaaa│raaa│saaa│taa·│
        00000050  ff ff ff ff  ff ff ff ff  ff ff ff ff  ff ff ff ff  │····│····│····│····│
        00000060  ff ff ff 61  7a 61 61 62  62 61 61 62  63 61 61 62  │···a│zaab│baab│caab│
        00000070  64 61 61 62  65 61 61 62  66 61 61 62  67 61 61 62  │daab│eaab│faab│gaab│
        00000080  68 61 61 62  69 61 61 62  6a 61 61 62  6b 61 61 62  │haab│iaab│jaab│kaab│
        00000090  6c 61 61 62  6d 61 61 62  6e 61 61 62  6f 61 61 62  │laab│maab│naab│oaab│
        000000a0  70 61 61 62  71 61 61 62  72 61 61 62  73 61 61 62  │paab│qaab│raab│saab│
        000000b0  74 61 61 62  75 61 61 62  76 61 61 62  77 61 61 62  │taab│uaab│vaab│waab│
        000000c0  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  │····│····│····│····│
        *
        000000e0

        >>> print(hexdump(fit({0x10: b'X'*0x20, 0x50-1: b'\xff'*20}, length=0xc0) + b'\x00'*32, cyclic=1))
        00000000  61 61 61 61  62 61 61 61  63 61 61 61  64 61 61 61  │aaaa│baaa│caaa│daaa│
        00000010  58 58 58 58  58 58 58 58  58 58 58 58  58 58 58 58  │XXXX│XXXX│XXXX│XXXX│
        *
        00000030  6d 61 61 61  6e 61 61 61  6f 61 61 61  70 61 61 61  │maaa│naaa│oaaa│paaa│
        00000040  71 61 61 61  72 61 61 61  73 61 61 61  74 61 61 ff  │qaaa│raaa│saaa│taa·│
        00000050  ff ff ff ff  ff ff ff ff  ff ff ff ff  ff ff ff ff  │····│····│····│····│
        00000060  ff ff ff 61  7a 61 61 62  62 61 61 62  63 61 61 62  │···a│zaab│baab│caab│
        00000070  64 61 61 62  65 61 61 62  66 61 61 62  67 61 61 62  │daab│eaab│faab│gaab│
        *
        000000c0  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  │····│····│····│····│
        *
        000000e0

        >>> print(hexdump(fit({0x10: b'X'*0x20, 0x50-1: b'\xff'*20}, length=0xc0) + b'\x00'*32, cyclic=1, hexii=1))
        00000000  .a  .a  .a  .a   .b  .a  .a  .a   .c  .a  .a  .a   .d  .a  .a  .a  │
        00000010  .X  .X  .X  .X   .X  .X  .X  .X   .X  .X  .X  .X   .X  .X  .X  .X  │
        *
        00000030  .m  .a  .a  .a   .n  .a  .a  .a   .o  .a  .a  .a   .p  .a  .a  .a  │
        00000040  .q  .a  .a  .a   .r  .a  .a  .a   .s  .a  .a  .a   .t  .a  .a  ##  │
        00000050  ##  ##  ##  ##   ##  ##  ##  ##   ##  ##  ##  ##   ##  ##  ##  ##  │
        00000060  ##  ##  ##  .a   .z  .a  .a  .b   .b  .a  .a  .b   .c  .a  .a  .b  │
        00000070  .d  .a  .a  .b   .e  .a  .a  .b   .f  .a  .a  .b   .g  .a  .a  .b  │
        *
        000000c0                                                                     │
        *
        000000e0

        >>> print(hexdump(b'A'*16, width=9))
        00000000  41 41 41 41  41 41 41 41  41  │AAAA│AAAA│A│
        00000009  41 41 41 41  41 41 41         │AAAA│AAA│
        00000010
        >>> print(hexdump(b'A'*16, width=10))
        00000000  41 41 41 41  41 41 41 41  41 41  │AAAA│AAAA│AA│
        0000000a  41 41 41 41  41 41               │AAAA│AA│
        00000010
        >>> print(hexdump(b'A'*16, width=11))
        00000000  41 41 41 41  41 41 41 41  41 41 41  │AAAA│AAAA│AAA│
        0000000b  41 41 41 41  41                     │AAAA│A│
        00000010
        >>> print(hexdump(b'A'*16, width=12))
        00000000  41 41 41 41  41 41 41 41  41 41 41 41  │AAAA│AAAA│AAAA│
        0000000c  41 41 41 41                            │AAAA│
        00000010
        >>> print(hexdump(b'A'*16, width=13))
        00000000  41 41 41 41  41 41 41 41  41 41 41 41  41  │AAAA│AAAA│AAAA│A│
        0000000d  41 41 41                                   │AAA│
        00000010
        >>> print(hexdump(b'A'*16, width=14))
        00000000  41 41 41 41  41 41 41 41  41 41 41 41  41 41  │AAAA│AAAA│AAAA│AA│
        0000000e  41 41                                         │AA│
        00000010
        >>> print(hexdump(b'A'*16, width=15))
        00000000  41 41 41 41  41 41 41 41  41 41 41 41  41 41 41  │AAAA│AAAA│AAAA│AAA│
        0000000f  41                                               │A│
        00000010

        >>> print(hexdump(b'A'*24, width=16, groupsize=8))
        00000000  41 41 41 41 41 41 41 41  41 41 41 41 41 41 41 41  │AAAAAAAA│AAAAAAAA│
        00000010  41 41 41 41 41 41 41 41                           │AAAAAAAA│
        00000018
        >>> print(hexdump(b'A'*24, width=16, groupsize=-1))
        00000000  41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41  │AAAAAAAAAAAAAAAA│
        00000010  41 41 41 41 41 41 41 41                          │AAAAAAAA│
        00000018

        >>> print(hexdump('A'*24, width=16, total=False))
        00000000  41 41 41 41  41 41 41 41  41 41 41 41  41 41 41 41  │AAAA│AAAA│AAAA│AAAA│
        00000010  41 41 41 41  41 41 41 41                            │AAAA│AAAA│
        >>> print(hexdump('A'*24, width=16, groupsize=8, total=False))
        00000000  41 41 41 41 41 41 41 41  41 41 41 41 41 41 41 41  │AAAAAAAA│AAAAAAAA│
        00000010  41 41 41 41 41 41 41 41                           │AAAAAAAA│
    """
    ...

def hexdump_iter(fd, width=16, skip=True, hexii=False, begin=0, style=None, highlight=None, cyclic=False, groupsize=4, total=True):
    r"""
    hexdump_iter(s, width = 16, skip = True, hexii = False, begin = 0, style = None,
                    highlight = None, cyclic = False, groupsize=4, total = True) -> str generator

    Return a hexdump-dump of a string as a generator of lines.  Unless you have
    massive amounts of data you probably want to use :meth:`hexdump`.

    Arguments:
        fd(file): File object to dump.  Use :meth:`StringIO.StringIO` or :meth:`hexdump` to dump a string.
        width(int): The number of characters per line
        groupsize(int): The number of characters per group
        skip(bool): Set to True, if repeated lines should be replaced by a "*"
        hexii(bool): Set to True, if a hexii-dump should be returned instead of a hexdump.
        begin(int):  Offset of the first byte to print in the left column
        style(dict): Color scheme to use.
        highlight(iterable): Byte values to highlight.
        cyclic(bool): Attempt to skip consecutive, unmodified cyclic lines
        total(bool): Set to True, if total bytes should be printed

    Returns:
        A generator producing the hexdump-dump one line at a time.

    Example:

        >>> tmp = tempfile.NamedTemporaryFile()
        >>> _ = tmp.write(b'XXXXHELLO, WORLD')
        >>> tmp.flush()
        >>> _ = tmp.seek(4)
        >>> print('\n'.join(hexdump_iter(tmp)))
        00000000  48 45 4c 4c  4f 2c 20 57  4f 52 4c 44               │HELL│O, W│ORLD│
        0000000c

        >>> t = tube()
        >>> t.unrecv(b'I know kung fu')
        >>> print('\n'.join(hexdump_iter(t)))
        00000000  49 20 6b 6e  6f 77 20 6b  75 6e 67 20  66 75        │I kn│ow k│ung │fu│
        0000000e
    """
    ...

def hexii(s, width=16, skip=True):
    r"""
    hexii(s, width = 16, skip = True) -> str

    Return a HEXII-dump of a string.

    Arguments:
        s(str): The string to dump
        width(int): The number of characters per line
        skip(bool): Should repeated lines be replaced by a "*"

    Returns:
        A HEXII-dump in the form of a string.
    """
    ...

def isprint(c):
    r"""
    isprint(c) -> bool

    Return True if a character is printable
    """
    ...

def naf(n):
    r"""
    naf(int) -> int generator

    Returns a generator for the non-adjacent form (NAF[1]) of a number, `n`.  If
    `naf(n)` generates `z_0, z_1, ...`, then `n == z_0 + z_1 * 2 + z_2 * 2**2,
    ...`.

    [1] https://en.wikipedia.org/wiki/Non-adjacent_form

    Example:

      >>> n = 45
      >>> m = 0
      >>> x = 1
      >>> for z in naf(n):
      ...     m += x * z
      ...     x *= 2
      >>> n == m
      True
    """
    ...

def negate(value, width=None):
    r"""
    Returns the two's complement of 'value'.
    """
    ...

def randoms(count, alphabet='abcdefghijklmnopqrstuvwxyz'):
    r"""
    randoms(count, alphabet = string.ascii_lowercase) -> str

    Returns a random string of a given length using only the specified alphabet.

    Arguments:
        count (int): The length of the desired string.
        alphabet: The alphabet of allowed characters. Defaults to all lowercase characters.

    Returns:
        A random string.

    Example:

        >>> randoms(10) #doctest: +SKIP
        'evafjilupm'
    """
    ...

def rol(n, k, word_size=None):
    r"""
    Returns a rotation by `k` of `n`.

    When `n` is a number, then means ``((n << k) | (n >> (word_size - k)))`` truncated to `word_size` bits.

    When `n` is a list, tuple or string, this is ``n[k % len(n):] + n[:k % len(n)]``.

    Arguments:
        n: The value to rotate.
        k(int): The rotation amount. Can be a positive or negative number.
        word_size(int): If `n` is a number, then this is the assumed bitsize of `n`.  Defaults to :data:`pwnlib.context.word_size` if `None` .

    Example:

        >>> rol('abcdefg', 2)
        'cdefgab'
        >>> rol('abcdefg', -2)
        'fgabcde'
        >>> hex(rol(0x86, 3, 8))
        '0x34'
        >>> hex(rol(0x86, -3, 8))
        '0xd0'
    """
    ...

def ror(n, k, word_size=None):
    r"""
    A simple wrapper around :func:`rol`, which negates the values of `k`.
    """
    ...

def sequential_lines(a, b):

    ...

def unbits(s, endian='big'):
    r"""
    unbits(s, endian = 'big') -> str

    Converts an iterable of bits into a string.

    Arguments:
       s: Iterable of bits
       endian (str):  The string "little" or "big", which specifies the bits endianness.

    Returns:
       A string of the decoded bits.

    Example:
       >>> unbits([1])
       b'\x80'
       >>> unbits([1], endian = 'little')
       b'\x01'
       >>> unbits(bits(b'hello'), endian = 'little')
       b'\x16\xa666\xf6'
    """
    ...

def unhex(s):
    r"""
    unhex(s) -> str

    Hex-decodes a string.

    Example:

        >>> unhex("74657374")
        b'test'
        >>> unhex("F\n")
        b'\x0f'
    """
    ...

def update_cyclic_pregenerated(size):

    ...

def urldecode(s, ignore_invalid=False):
    r"""
    urldecode(s, ignore_invalid = False) -> str

    URL-decodes a string.

    Example:

        >>> urldecode("test%20%41")
        'test A'
        >>> urldecode("%qq")
        Traceback (most recent call last):
        ...
        ValueError: Invalid input to urldecode
        >>> urldecode("%qq", ignore_invalid = True)
        '%qq'
    """
    ...

def urlencode(s):
    r"""
    urlencode(s) -> str

    URL-encodes a string.

    Example:

        >>> urlencode("test")
        '%74%65%73%74'
    """
    ...

def xor(*args, **kwargs):
    r"""
    xor(*args, cut = 'max') -> str

    Flattens its arguments using :func:`pwnlib.util.packing.flat` and
    then xors them together. If the end of a string is reached, it wraps
    around in the string.

    Arguments:
       args: The arguments to be xor'ed together.
       cut: How long a string should be returned.
            Can be either 'min'/'max'/'left'/'right' or a number.

    Returns:
       The string of the arguments xor'ed together.

    Example:
       >>> xor(b'lol', b'hello', 42)
       b'. ***'
    """
    ...

def xor_key(data, avoid=b'\x00\n', size=None):
    r"""
    xor_key(data, size=None, avoid='\x00\n') -> None or (int, str)

    Finds a ``size``-width value that can be XORed with a string
    to produce ``data``, while neither the XOR value or XOR string
    contain any bytes in ``avoid``.

    Arguments:
        data (str): The desired string.
        avoid: The list of disallowed characters. Defaults to nulls and newlines.
        size (int): Size of the desired output value, default is word size.

    Returns:
        A tuple containing two strings; the XOR key and the XOR string.
        If no such pair exists, None is returned.

    Example:

        >>> xor_key(b"Hello, world")
        (b'\x01\x01\x01\x01', b'Idmmn-!vnsme')
    """
    ...

def xor_pair(data, avoid=b'\x00\n'):
    r"""
    xor_pair(data, avoid = '\x00\n') -> None or (str, str)

    Finds two strings that will xor into a given string, while only
    using a given alphabet.

    Arguments:
        data (str): The desired string.
        avoid: The list of disallowed characters. Defaults to nulls and newlines.

    Returns:
        Two strings which will xor to the given string. If no such two strings exist, then None is returned.

    Example:

        >>> xor_pair(b"test")
        (b'\x01\x01\x01\x01', b'udru')
    """
    ...


import pwnlib.util.getdents

def dirents(buf):
    r"""
    unpack_dents(buf) -> list

    Extracts data from a buffer emitted by getdents()

    Arguments:
        buf(str): Byte array

    Returns:
        A list of filenames.

    Example:

        >>> data = '5ade6d010100000010002e0000000004010000000200000010002e2e006e3d04092b6d010300000010007461736b00045bde6d010400000010006664003b3504'
        >>> data = unhex(data)
        >>> print(dirents(data))
        ['.', '..', 'fd', 'task']
    """
    ...

class linux_dirent:

    def __init__(self, buf):
        r"""
        Initialize self.  See help(type(self)) for accurate signature.
        """
        ...

    def __len__(self):

        ...

    def __str__(self):
        r"""
        Return str(self).
        """
        ...


import pwnlib.util.hashes

def blake2bfile(x):
    r"""
    Calculates the blake2b sum of a file
    """
    ...

def blake2bfilehex(x):
    r"""
    Calculates the blake2b sum of a file; returns hex-encoded
    """
    ...

def blake2bsum(x):
    r"""
    Calculates the blake2b sum of a string
    """
    ...

def blake2bsumhex(x):
    r"""
    Calculates the blake2b sum of a string; returns hex-encoded
    """
    ...

def blake2sfile(x):
    r"""
    Calculates the blake2s sum of a file
    """
    ...

def blake2sfilehex(x):
    r"""
    Calculates the blake2s sum of a file; returns hex-encoded
    """
    ...

def blake2ssum(x):
    r"""
    Calculates the blake2s sum of a string
    """
    ...

def blake2ssumhex(x):
    r"""
    Calculates the blake2s sum of a string; returns hex-encoded
    """
    ...

def md5file(x):
    r"""
    Calculates the md5 sum of a file
    """
    ...

def md5filehex(x):
    r"""
    Calculates the md5 sum of a file; returns hex-encoded
    """
    ...

def md5sum(x):
    r"""
    Calculates the md5 sum of a string
    """
    ...

def md5sumhex(x):
    r"""
    Calculates the md5 sum of a string; returns hex-encoded
    """
    ...

def sha1file(x):
    r"""
    Calculates the sha1 sum of a file
    """
    ...

def sha1filehex(x):
    r"""
    Calculates the sha1 sum of a file; returns hex-encoded
    """
    ...

def sha1sum(x):
    r"""
    Calculates the sha1 sum of a string
    """
    ...

def sha1sumhex(x):
    r"""
    Calculates the sha1 sum of a string; returns hex-encoded
    """
    ...

def sha224file(x):
    r"""
    Calculates the sha224 sum of a file
    """
    ...

def sha224filehex(x):
    r"""
    Calculates the sha224 sum of a file; returns hex-encoded
    """
    ...

def sha224sum(x):
    r"""
    Calculates the sha224 sum of a string
    """
    ...

def sha224sumhex(x):
    r"""
    Calculates the sha224 sum of a string; returns hex-encoded
    """
    ...

def sha256file(x):
    r"""
    Calculates the sha256 sum of a file
    """
    ...

def sha256filehex(x):
    r"""
    Calculates the sha256 sum of a file; returns hex-encoded
    """
    ...

def sha256sum(x):
    r"""
    Calculates the sha256 sum of a string
    """
    ...

def sha256sumhex(x):
    r"""
    Calculates the sha256 sum of a string; returns hex-encoded
    """
    ...

def sha384file(x):
    r"""
    Calculates the sha384 sum of a file
    """
    ...

def sha384filehex(x):
    r"""
    Calculates the sha384 sum of a file; returns hex-encoded
    """
    ...

def sha384sum(x):
    r"""
    Calculates the sha384 sum of a string
    """
    ...

def sha384sumhex(x):
    r"""
    Calculates the sha384 sum of a string; returns hex-encoded
    """
    ...

def sha3_224file(x):
    r"""
    Calculates the sha3_224 sum of a file
    """
    ...

def sha3_224filehex(x):
    r"""
    Calculates the sha3_224 sum of a file; returns hex-encoded
    """
    ...

def sha3_224sum(x):
    r"""
    Calculates the sha3_224 sum of a string
    """
    ...

def sha3_224sumhex(x):
    r"""
    Calculates the sha3_224 sum of a string; returns hex-encoded
    """
    ...

def sha3_256file(x):
    r"""
    Calculates the sha3_256 sum of a file
    """
    ...

def sha3_256filehex(x):
    r"""
    Calculates the sha3_256 sum of a file; returns hex-encoded
    """
    ...

def sha3_256sum(x):
    r"""
    Calculates the sha3_256 sum of a string
    """
    ...

def sha3_256sumhex(x):
    r"""
    Calculates the sha3_256 sum of a string; returns hex-encoded
    """
    ...

def sha3_384file(x):
    r"""
    Calculates the sha3_384 sum of a file
    """
    ...

def sha3_384filehex(x):
    r"""
    Calculates the sha3_384 sum of a file; returns hex-encoded
    """
    ...

def sha3_384sum(x):
    r"""
    Calculates the sha3_384 sum of a string
    """
    ...

def sha3_384sumhex(x):
    r"""
    Calculates the sha3_384 sum of a string; returns hex-encoded
    """
    ...

def sha3_512file(x):
    r"""
    Calculates the sha3_512 sum of a file
    """
    ...

def sha3_512filehex(x):
    r"""
    Calculates the sha3_512 sum of a file; returns hex-encoded
    """
    ...

def sha3_512sum(x):
    r"""
    Calculates the sha3_512 sum of a string
    """
    ...

def sha3_512sumhex(x):
    r"""
    Calculates the sha3_512 sum of a string; returns hex-encoded
    """
    ...

def sha512file(x):
    r"""
    Calculates the sha512 sum of a file
    """
    ...

def sha512filehex(x):
    r"""
    Calculates the sha512 sum of a file; returns hex-encoded
    """
    ...

def sha512sum(x):
    r"""
    Calculates the sha512 sum of a string
    """
    ...

def sha512sumhex(x):
    r"""
    Calculates the sha512 sum of a string; returns hex-encoded
    """
    ...

def shake_128file(x):
    r"""
    Calculates the shake_128 sum of a file
    """
    ...

def shake_128filehex(x):
    r"""
    Calculates the shake_128 sum of a file; returns hex-encoded
    """
    ...

def shake_128sum(x):
    r"""
    Calculates the shake_128 sum of a string
    """
    ...

def shake_128sumhex(x):
    r"""
    Calculates the shake_128 sum of a string; returns hex-encoded
    """
    ...

def shake_256file(x):
    r"""
    Calculates the shake_256 sum of a file
    """
    ...

def shake_256filehex(x):
    r"""
    Calculates the shake_256 sum of a file; returns hex-encoded
    """
    ...

def shake_256sum(x):
    r"""
    Calculates the shake_256 sum of a string
    """
    ...

def shake_256sumhex(x):
    r"""
    Calculates the shake_256 sum of a string; returns hex-encoded
    """
    ...


import pwnlib.util.iters


import pwnlib.util.lists

def concat(l):
    r"""
    concat(l) -> list

    Concats a list of lists into a list.

    Example:

      >>> concat([[1, 2], [3]])
      [1, 2, 3]
    """
    ...

def concat_all(*args):
    r"""
    concat_all(*args) -> list

    Concats all the arguments together.

    Example:
       >>> concat_all(0, [1, (2, 3)], [([[4, 5, 6]])])
       [0, 1, 2, 3, 4, 5, 6]
    """
    ...

def findall(haystack, needle):
    r"""
    findall(l, e) -> l

    Generate all indices of needle in haystack, using the
    Knuth-Morris-Pratt algorithm.

    Example:
      >>> foo = findall([1,2,3,4,4,3,4,2,1], 4)
      >>> next(foo)
      3
      >>> next(foo)
      4
      >>> next(foo)
      6
      >>> list(foo) # no more appearances
      []
      >>> list(findall("aaabaaabc", "aab"))
      [1, 5]
    """
    ...

def group(n, lst, underfull_action='ignore', fill_value=None):
    r"""
    group(n, lst, underfull_action = 'ignore', fill_value = None) -> list

    Split sequence into subsequences of given size. If the values cannot be
    evenly distributed among into groups, then the last group will either be
    returned as is, thrown out or padded with the value specified in fill_value.

    Arguments:
      n (int): The size of resulting groups
      lst: The list, tuple or string to group
      underfull_action (str): The action to take in case of an underfull group at the end. Possible values are 'ignore', 'drop' or 'fill'.
      fill_value: The value to fill into an underfull remaining group.

    Returns:
      A list containing the grouped values.

    Example:
      >>> group(3, "ABCDEFG")
      ['ABC', 'DEF', 'G']
      >>> group(3, 'ABCDEFG', 'drop')
      ['ABC', 'DEF']
      >>> group(3, 'ABCDEFG', 'fill', 'Z')
      ['ABC', 'DEF', 'GZZ']
      >>> group(3, list('ABCDEFG'), 'fill')
      [['A', 'B', 'C'], ['D', 'E', 'F'], ['G', None, None]]
      >>> group(2, tuple('1234'), 'fill')
      [('1', '2'), ('3', '4')]
    """
    ...

def ordlist(s):
    r"""
    ordlist(s) -> list

    Turns a string into a list of the corresponding ascii values.

    Example:
      >>> ordlist("hello")
      [104, 101, 108, 108, 111]
    """
    ...

def partition(lst, f, save_keys=False):
    r"""
    partition(lst, f, save_keys = False) -> list

    Partitions an iterable into sublists using a function to specify which
    group they belong to.

    It works by calling `f` on every element and saving the results into
    an :class:`collections.OrderedDict`.

    Arguments:
      lst: The iterable to partition
      f(function): The function to use as the partitioner.
      save_keys(bool): Set this to True, if you want the OrderedDict
                       returned instead of just the values

    Example:
      >>> partition([1,2,3,4,5], lambda x: x&1)
      [[1, 3, 5], [2, 4]]
      >>> partition([1,2,3,4,5], lambda x: x%3, save_keys=True)
      OrderedDict([(1, [1, 4]), (2, [2, 5]), (0, [3])])
    """
    ...

def unordlist(cs):
    r"""
    unordlist(cs) -> str

    Takes a list of ascii values and returns the corresponding string.

    Example:
      >>> unordlist([104, 101, 108, 108, 111])
      'hello'
    """
    ...


import pwnlib.util.misc

def align(alignment, x):
    r"""
    align(alignment, x) -> int

    Rounds `x` up to nearest multiple of the `alignment`.

    Example:
      >>> [align(5, n) for n in range(15)]
      [0, 5, 5, 5, 5, 5, 10, 10, 10, 10, 10, 15, 15, 15, 15]
    """
    ...

def align_down(alignment, x):
    r"""
    align_down(alignment, x) -> int

    Rounds `x` down to nearest multiple of the `alignment`.

    Example:
        >>> [align_down(5, n) for n in range(15)]
        [0, 0, 0, 0, 0, 5, 5, 5, 5, 5, 10, 10, 10, 10, 10]
    """
    ...

def binary_ip(host):
    r"""
    binary_ip(host) -> str

    Resolve host and return IP as four byte string.

    Example:
        >>> binary_ip("127.0.0.1")
        b'\x7f\x00\x00\x01'
    """
    ...

def dealarm_shell(tube):
    r"""
    Given a tube which is a shell, dealarm it.
    
    """
    ...

def mkdir_p(path):
    r"""
    Emulates the behavior of ``mkdir -p``.
    """
    ...

def parse_ldd_output(output):
    r"""
    Parses the output from a run of 'ldd' on a binary.
    Returns a dictionary of {path: address} for
    each library required by the specified binary.

    Arguments:
      output(str): The output to parse

    Example:
        >>> sorted(parse_ldd_output('''
        ...     linux-vdso.so.1 =>  (0x00007fffbf5fe000)
        ...     libtinfo.so.5 => /lib/x86_64-linux-gnu/libtinfo.so.5 (0x00007fe28117f000)
        ...     libdl.so.2 => /lib/x86_64-linux-gnu/libdl.so.2 (0x00007fe280f7b000)
        ...     libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fe280bb4000)
        ...     /lib64/ld-linux-x86-64.so.2 (0x00007fe2813dd000)
        ... ''').keys())
        ['/lib/x86_64-linux-gnu/libc.so.6', '/lib/x86_64-linux-gnu/libdl.so.2', '/lib/x86_64-linux-gnu/libtinfo.so.5', '/lib64/ld-linux-x86-64.so.2']
    """
    ...

def python_2_bytes_compatible(klass):
    r"""
    A class decorator that defines __str__ methods under Python 2.
    Under Python 3 it does nothing.
    """
    ...

def read(path, count=-1, skip=0):
    r"""
    read(path, count=-1, skip=0) -> str

    Open file, return content.

    Examples:
        >>> read('/proc/self/exe')[:4]
        b'\x7fELF'
    """
    ...

def register_sizes(regs, in_sizes):
    r"""
    Create dictionaries over register sizes and relations

    Given a list of lists of overlapping register names (e.g. ['eax','ax','al','ah']) and a list of input sizes,
    it returns the following:

    * all_regs    : list of all valid registers
    * sizes[reg]  : the size of reg in bits
    * bigger[reg] : list of overlapping registers bigger than reg
    * smaller[reg]: list of overlapping registers smaller than reg

    Used in i386/AMD64 shellcode, e.g. the mov-shellcode.

    Example:
        >>> regs = [['eax', 'ax', 'al', 'ah'],['ebx', 'bx', 'bl', 'bh'],
        ... ['ecx', 'cx', 'cl', 'ch'],
        ... ['edx', 'dx', 'dl', 'dh'],
        ... ['edi', 'di'],
        ... ['esi', 'si'],
        ... ['ebp', 'bp'],
        ... ['esp', 'sp'],
        ... ]
        >>> all_regs, sizes, bigger, smaller = register_sizes(regs, [32, 16, 8, 8])
        >>> all_regs
        ['eax', 'ax', 'al', 'ah', 'ebx', 'bx', 'bl', 'bh', 'ecx', 'cx', 'cl', 'ch', 'edx', 'dx', 'dl', 'dh', 'edi', 'di', 'esi', 'si', 'ebp', 'bp', 'esp', 'sp']
        >>> pprint(sizes)
        {'ah': 8,
         'al': 8,
         'ax': 16,
         'bh': 8,
         'bl': 8,
         'bp': 16,
         'bx': 16,
         'ch': 8,
         'cl': 8,
         'cx': 16,
         'dh': 8,
         'di': 16,
         'dl': 8,
         'dx': 16,
         'eax': 32,
         'ebp': 32,
         'ebx': 32,
         'ecx': 32,
         'edi': 32,
         'edx': 32,
         'esi': 32,
         'esp': 32,
         'si': 16,
         'sp': 16}
        >>> pprint(bigger)
        {'ah': ['eax', 'ax', 'ah'],
         'al': ['eax', 'ax', 'al'],
         'ax': ['eax', 'ax'],
         'bh': ['ebx', 'bx', 'bh'],
         'bl': ['ebx', 'bx', 'bl'],
         'bp': ['ebp', 'bp'],
         'bx': ['ebx', 'bx'],
         'ch': ['ecx', 'cx', 'ch'],
         'cl': ['ecx', 'cx', 'cl'],
         'cx': ['ecx', 'cx'],
         'dh': ['edx', 'dx', 'dh'],
         'di': ['edi', 'di'],
         'dl': ['edx', 'dx', 'dl'],
         'dx': ['edx', 'dx'],
         'eax': ['eax'],
         'ebp': ['ebp'],
         'ebx': ['ebx'],
         'ecx': ['ecx'],
         'edi': ['edi'],
         'edx': ['edx'],
         'esi': ['esi'],
         'esp': ['esp'],
         'si': ['esi', 'si'],
         'sp': ['esp', 'sp']}
        >>> pprint(smaller)
        {'ah': [],
         'al': [],
         'ax': ['al', 'ah'],
         'bh': [],
         'bl': [],
         'bp': [],
         'bx': ['bl', 'bh'],
         'ch': [],
         'cl': [],
         'cx': ['cl', 'ch'],
         'dh': [],
         'di': [],
         'dl': [],
         'dx': ['dl', 'dh'],
         'eax': ['ax', 'al', 'ah'],
         'ebp': ['bp'],
         'ebx': ['bx', 'bl', 'bh'],
         'ecx': ['cx', 'cl', 'ch'],
         'edi': ['di'],
         'edx': ['dx', 'dl', 'dh'],
         'esi': ['si'],
         'esp': ['sp'],
         'si': [],
         'sp': []}
    """
    ...

def run_in_new_terminal(command, terminal=None, args=None, kill_at_exit=True, preexec_fn=None):
    r"""
    run_in_new_terminal(command, terminal=None, args=None, kill_at_exit=True, preexec_fn=None) -> int

    Run a command in a new terminal.

    When ``terminal`` is not set:
        - If ``context.terminal`` is set it will be used.
          If it is an iterable then ``context.terminal[1:]`` are default arguments.
        - If a ``pwntools-terminal`` command exists in ``$PATH``, it is used
        - If tmux is detected (by the presence of the ``$TMUX`` environment
          variable), a new pane will be opened.
        - If GNU Screen is detected (by the presence of the ``$STY`` environment
          variable), a new screen will be opened.
        - If ``$TERM_PROGRAM`` is set, that is used.
        - If X11 is detected (by the presence of the ``$DISPLAY`` environment
          variable), ``x-terminal-emulator`` is used.
        - If WSL (Windows Subsystem for Linux) is detected (by the presence of
          a ``wsl.exe`` binary in the ``$PATH`` and ``/proc/sys/kernel/osrelease``
          containing ``Microsoft``), a new ``cmd.exe`` window will be opened.

    If `kill_at_exit` is :const:`True`, try to close the command/terminal when the
    current process exits. This may not work for all terminal types.

    Arguments:
        command (str): The command to run.
        terminal (str): Which terminal to use.
        args (list): Arguments to pass to the terminal
        kill_at_exit (bool): Whether to close the command/terminal on process exit.
        preexec_fn (callable): Callable to invoke before exec().

    Note:
        The command is opened with ``/dev/null`` for stdin, stdout, stderr.

    Returns:
      PID of the new terminal process
    """
    ...

def size(n, abbrev='B', si=False):
    r"""
    size(n, abbrev = 'B', si = False) -> str

    Convert the length of a bytestream to human readable form.

    Arguments:
      n(int,iterable): The length to convert to human readable form,
        or an object which can have ``len()`` called on it.
      abbrev(str): String appended to the size, defaults to ``'B'``.

    Example:
        >>> size(451)
        '451B'
        >>> size(1000)
        '1000B'
        >>> size(1024)
        '1.00KB'
        >>> size(1024, ' bytes')
        '1.00K bytes'
        >>> size(1024, si = True)
        '1.02KB'
        >>> [size(1024 ** n) for n in range(7)]
        ['1B', '1.00KB', '1.00MB', '1.00GB', '1.00TB', '1.00PB', '1024.00PB']
        >>> size([])
        '0B'
        >>> size([1,2,3])
        '3B'
    """
    ...

def which(name, all=False, path=None):
    r"""
    which(name, flags = os.X_OK, all = False) -> str or str set

    Works as the system command ``which``; searches $PATH for ``name`` and
    returns a full path if found.

    If `all` is :const:`True` the set of all found locations is returned, else
    the first occurrence or :const:`None` is returned.

    Arguments:
      `name` (str): The file to search for.
      `all` (bool):  Whether to return all locations where `name` was found.

    Returns:
      If `all` is :const:`True` the set of all locations where `name` was found,
      else the first location or :const:`None` if not found.

    Example:

        >>> which('sh') # doctest: +ELLIPSIS
        '.../bin/sh'
    """
    ...

def write(path, data=b'', create_dir=False, mode='w'):
    r"""
    Create new file or truncate existing to zero length and write data.
    """
    ...


import pwnlib.util.net


import pwnlib.util.packing

def dd(dst, src, count=0, skip=0, seek=0, truncate=False):
    r"""
    dd(dst, src, count = 0, skip = 0, seek = 0, truncate = False) -> dst

    Inspired by the command line tool ``dd``, this function copies `count` byte
    values from offset `seek` in `src` to offset `skip` in `dst`.  If `count` is
    0, all of ``src[seek:]`` is copied.

    If `dst` is a mutable type it will be updated.  Otherwise a new instance of
    the same type will be created.  In either case the result is returned.

    `src` can be an iterable of characters or integers, a unicode string or a
    file object.  If it is an iterable of integers, each integer must be in the
    range [0;255].  If it is a unicode string, its UTF-8 encoding will be used.

    The seek offset of file objects will be preserved.

    Arguments:
        dst: Supported types are :class:`file`, :class:`list`, :class:`tuple`,
             :class:`str`, :class:`bytearray` and :class:`unicode`.
        src: An iterable of byte values (characters or integers), a unicode
             string or a file object.
        count (int): How many bytes to copy.  If `count` is 0 or larger than
                     ``len(src[seek:])``, all bytes until the end of `src` are
                     copied.
        skip (int): Offset in `dst` to copy to.
        seek (int): Offset in `src` to copy from.
        truncate (bool): If :const:`True`, `dst` is truncated at the last copied
                         byte.

    Returns:
        A modified version of `dst`.  If `dst` is a mutable type it will be
        modified in-place.

    Examples:
        >>> dd(tuple('Hello!'), b'?', skip = 5)
        ('H', 'e', 'l', 'l', 'o', b'?')
        >>> dd(list('Hello!'), (63,), skip = 5)
        ['H', 'e', 'l', 'l', 'o', b'?']
        >>> _ = open('/tmp/foo', 'w').write('A' * 10)
        >>> dd(open('/tmp/foo'), open('/dev/zero'), skip = 3, count = 4).read()
        'AAA\x00\x00\x00\x00AAA'
        >>> _ = open('/tmp/foo', 'w').write('A' * 10)
        >>> dd(open('/tmp/foo'), open('/dev/zero'), skip = 3, count = 4, truncate = True).read()
        'AAA\x00\x00\x00\x00'
    """
    ...

def fit(*args, **kwargs):
    r"""
    Legacy alias for :func:`flat`
    """
    ...

def flat(*args, **kwargs):
    r"""
    flat(\*args, preprocessor = None, length = None, filler = de_bruijn(),
     word_size = None, endianness = None, sign = None) -> str

    Flattens the arguments into a string.

    This function takes an arbitrary number of arbitrarily nested lists, tuples
    and dictionaries.  It will then find every string and number inside those
    and flatten them out.  Strings are inserted directly while numbers are
    packed using the :func:`pack` function.  Unicode strings are UTF-8 encoded.

    Dictionary keys give offsets at which to place the corresponding values
    (which are recursively flattened).  Offsets are relative to where the
    flattened dictionary occurs in the output (i.e. ``{0: 'foo'}`` is equivalent
    to ``'foo'``).  Offsets can be integers, unicode strings or regular strings.
    Integer offsets >= ``2**(word_size-8)`` are converted to a string using
    :func:`pack`.  Unicode strings are UTF-8 encoded.  After these conversions
    offsets are either integers or strings.  In the latter case, the offset will
    be the lowest index at which the string occurs in `filler`.  See examples
    below.

    Space between pieces of data is filled out using the iterable `filler`.  The
    `n`'th byte in the output will be byte at index ``n % len(iterable)`` byte
    in `filler` if it has finite length or the byte at index `n` otherwise.

    If `length` is given, the output will be padded with bytes from `filler` to
    be this size.  If the output is longer than `length`, a :py:exc:`ValueError`
    exception is raised.

    The three kwargs `word_size`, `endianness` and `sign` will default to using
    values in :mod:`pwnlib.context` if not specified as an argument.

    Arguments:
      args: Values to flatten
      preprocessor (function): Gets called on every element to optionally
         transform the element before flattening. If :const:`None` is
         returned, then the original value is used.
      length: The length of the output.
      filler: Iterable to use for padding.
      word_size (int): Word size of the converted integer.
      endianness (str): Endianness of the converted integer ("little"/"big").
      sign (str): Signedness of the converted integer (False/True)

    Examples:

        (Test setup, please ignore)

        >>> context.clear()

        Basic usage of :meth:`flat` works similar to the pack() routines.

        >>> flat(4)
        b'\x04\x00\x00\x00'

        :meth:`flat` works with strings, bytes, lists, and dictionaries.

        >>> flat(b'X')
        b'X'
        >>> flat([1,2,3])
        b'\x01\x00\x00\x00\x02\x00\x00\x00\x03\x00\x00\x00'
        >>> flat({4:'X'})
        b'aaaaX'

        :meth:`.flat` flattens all of the values provided, and allows nested lists
        and dictionaries.

        >>> flat([{4:'X'}] * 2)
        b'aaaaXaaacX'
        >>> flat([[[[[[[[[1]]]], 2]]]]])
        b'\x01\x00\x00\x00\x02\x00\x00\x00'

        You can also provide additional arguments like endianness, word-size, and
        whether the values are treated as signed or not.

        >>> flat(1, "test", [[["AB"]*2]*3], endianness = 'little', word_size = 16, sign = False)
        b'\x01\x00testABABABABABAB'

        A preprocessor function can be provided in order to modify the values in-flight.
        This example converts increments each value by 1, then converts to a string.

        >>> flat([1, [2, 3]], preprocessor = lambda x: str(x+1))
        b'234'

        Using dictionaries is a fast way to get specific values at specific offsets,
        without having to do ``data += "foo"`` repeatedly.

        >>> flat({12: 0x41414141,
        ...       24: 'Hello',
        ...      })
        b'aaaabaaacaaaAAAAeaaafaaaHello'

        Dictionary usage permits directly using values derived from :func:`.cyclic`.
        See :func:`.cyclic`, :function:`pwnlib.context.context.cyclic_alphabet`, and :data:`.context.cyclic_size`
        for more options.  

        The cyclic pattern can be provided as either the text or hexadecimal offset.

        >>> flat({ 0x61616162: 'X'})
        b'aaaaX'
        >>> flat({'baaa': 'X'})
        b'aaaaX'

        Fields do not have to be in linear order, and can be freely mixed.
        This also works with cyclic offsets.

        >>> flat({2: 'A', 0:'B'})
        b'BaA'
        >>> flat({0x61616161:'x', 0x61616162:'y'})
        b'xaaay'
        >>> flat({0x61616162:'y', 0x61616161:'x'})
        b'xaaay'

        Fields do not have to be in order, and can be freely mixed.

        >>> flat({'caaa': 'XXXX', 16: '\x41', 20: 0xdeadbeef})
        b'aaaabaaaXXXXdaaaAaaa\xef\xbe\xad\xde'
        >>> flat({ 8: [0x41414141, 0x42424242], 20: 'CCCC'})
        b'aaaabaaaAAAABBBBeaaaCCCC'
        >>> fit({
        ...     0x61616161: 'a',
        ...     1: 'b',
        ...     0x61616161+2: 'c',
        ...     3: 'd',
        ... })
        b'abadbaaac'

        By default, gaps in the data are filled in with the :meth:`.cyclic` pattern.
        You can customize this by providing an iterable or method for the ``filler``
        argument.

        >>> flat({12: 'XXXX'}, filler = b'_', length = 20)
        b'____________XXXX____'
        >>> flat({12: 'XXXX'}, filler = b'AB', length = 20)
        b'ABABABABABABXXXXABAB'

        Nested dictionaries also work as expected.

        >>> flat({4: {0: 'X', 4: 'Y'}})
        b'aaaaXaaaY'
        >>> fit({4: {4: 'XXXX'}})
        b'aaaabaaaXXXX'

        Negative indices are also supported, though this only works for integer
        keys.

        >>> flat({-4: 'x', -1: 'A', 0: '0', 4:'y'})
        b'xaaA0aaay'
    """
    ...

def make_multi(op, size):

    ...

def make_packer(word_size=None, sign=None, **kwargs):
    r"""
    make_packer(word_size = None, endianness = None, sign = None) -> number → str

    Creates a packer by "freezing" the given arguments.

    Semantically calling ``make_packer(w, e, s)(data)`` is equivalent to calling
    ``pack(data, w, e, s)``. If word_size is one of 8, 16, 32 or 64, it is however
    faster to call this function, since it will then use a specialized version.

    Arguments:
        word_size (int): The word size to be baked into the returned packer or the string all (in bits).
        endianness (str): The endianness to be baked into the returned packer. ("little"/"big")
        sign (str): The signness to be baked into the returned packer. ("unsigned"/"signed")
        kwargs: Additional context flags, for setting by alias (e.g. ``endian=`` rather than index)

    Returns:
        A function, which takes a single argument in the form of a number and returns a string
        of that number in a packed form.

    Examples:
        >>> p = make_packer(32, endian='little', sign='unsigned')
        >>> p
        <function _p32lu at 0x...>
        >>> p(42)
        b'*\x00\x00\x00'
        >>> p(-1)
        Traceback (most recent call last):
            ...
        error: integer out of range for 'I' format code
        >>> make_packer(33, endian='little', sign='unsigned')
        <function ...<lambda> at 0x...>
    """
    ...

def make_single(op, size, end, sign):

    ...

def make_unpacker(word_size=None, endianness=None, sign=None, **kwargs):
    r"""
    make_unpacker(word_size = None, endianness = None, sign = None,  **kwargs) -> str → number

    Creates a unpacker by "freezing" the given arguments.

    Semantically calling ``make_unpacker(w, e, s)(data)`` is equivalent to calling
    ``unpack(data, w, e, s)``. If word_size is one of 8, 16, 32 or 64, it is however
    faster to call this function, since it will then use a specialized version.

    Arguments:
        word_size (int): The word size to be baked into the returned packer (in bits).
        endianness (str): The endianness to be baked into the returned packer. ("little"/"big")
        sign (str): The signness to be baked into the returned packer. ("unsigned"/"signed")
        kwargs: Additional context flags, for setting by alias (e.g. ``endian=`` rather than index)

    Returns:
        A function, which takes a single argument in the form of a string and returns a number
        of that string in an unpacked form.

    Examples:
        >>> u = make_unpacker(32, endian='little', sign='unsigned')
        >>> u
        <function _u32lu at 0x...>
        >>> hex(u('/bin'))
        '0x6e69622f'
        >>> u('abcde')
        Traceback (most recent call last):
            ...
        error: unpack requires a string argument of length 4
        >>> make_unpacker(33, endian='little', sign='unsigned')
        <function ...<lambda> at 0x...>
    """
    ...

def p16(number):
    r"""
    p16(number, sign, endian, ...) -> str

    Packs an 16-bit integer

    Arguments:
        number (int): Number to convert
        endianness (str): Endianness of the converted integer ("little"/"big")
        sign (str): Signedness of the converted integer ("unsigned"/"signed")
        kwargs (dict): Arguments passed to context.local(), such as
            ``endian`` or ``signed``.

    Returns:
        The packed number as a string
    """
    ...

def p32(number):
    r"""
    p32(number, sign, endian, ...) -> str

    Packs an 32-bit integer

    Arguments:
        number (int): Number to convert
        endianness (str): Endianness of the converted integer ("little"/"big")
        sign (str): Signedness of the converted integer ("unsigned"/"signed")
        kwargs (dict): Arguments passed to context.local(), such as
            ``endian`` or ``signed``.

    Returns:
        The packed number as a string
    """
    ...

def p64(number):
    r"""
    p64(number, sign, endian, ...) -> str

    Packs an 64-bit integer

    Arguments:
        number (int): Number to convert
        endianness (str): Endianness of the converted integer ("little"/"big")
        sign (str): Signedness of the converted integer ("unsigned"/"signed")
        kwargs (dict): Arguments passed to context.local(), such as
            ``endian`` or ``signed``.

    Returns:
        The packed number as a string
    """
    ...

def p8(number):
    r"""
    p8(number, sign, endian, ...) -> str

    Packs an 8-bit integer

    Arguments:
        number (int): Number to convert
        endianness (str): Endianness of the converted integer ("little"/"big")
        sign (str): Signedness of the converted integer ("unsigned"/"signed")
        kwargs (dict): Arguments passed to context.local(), such as
            ``endian`` or ``signed``.

    Returns:
        The packed number as a string
    """
    ...

def pack(number, word_size=None, endianness=None, sign=None, **kwargs):
    r"""
    pack(number, word_size = None, endianness = None, sign = None, **kwargs) -> str

    Packs arbitrary-sized integer.

    Word-size, endianness and signedness is done according to context.

    `word_size` can be any positive number or the string "all". Choosing the
    string "all" will output a string long enough to contain all the significant
    bits and thus be decodable by :func:`unpack`.

    `word_size` can be any positive number. The output will contain word_size/8
    rounded up number of bytes. If word_size is not a multiple of 8, it will be
    padded with zeroes up to a byte boundary.

    Arguments:
        number (int): Number to convert
        word_size (int): Word size of the converted integer or the string 'all' (in bits).
        endianness (str): Endianness of the converted integer ("little"/"big")
        sign (str): Signedness of the converted integer (False/True)
        kwargs: Anything that can be passed to context.local

    Returns:
        The packed number as a string.

    Examples:
        >>> pack(0x414243, 24, 'big', True)
        b'ABC'
        >>> pack(0x414243, 24, 'little', True)
        b'CBA'
        >>> pack(0x814243, 24, 'big', False)
        b'\x81BC'
        >>> pack(0x814243, 24, 'big', True)
        Traceback (most recent call last):
           ...
        ValueError: pack(): number does not fit within word_size
        >>> pack(0x814243, 25, 'big', True)
        b'\x00\x81BC'
        >>> pack(-1, 'all', 'little', True)
        b'\xff'
        >>> pack(-256, 'all', 'big', True)
        b'\xff\x00'
        >>> pack(0x0102030405, 'all', 'little', True)
        b'\x05\x04\x03\x02\x01'
        >>> pack(-1)
        b'\xff\xff\xff\xff'
        >>> pack(0x80000000, 'all', 'big', True)
        b'\x00\x80\x00\x00\x00'
    """
    ...

def signed(integer):

    ...

def u16(number):
    r"""
    u16(number, sign, endian, ...) -> int

    Unpacks an 16-bit integer

    Arguments:
        data (str): String to convert
        endianness (str): Endianness of the converted integer ("little"/"big")
        sign (str): Signedness of the converted integer ("unsigned"/"signed")
        kwargs (dict): Arguments passed to context.local(), such as
            ``endian`` or ``signed``.

    Returns:
        The unpacked number
    """
    ...

def u32(number):
    r"""
    u32(number, sign, endian, ...) -> int

    Unpacks an 32-bit integer

    Arguments:
        data (str): String to convert
        endianness (str): Endianness of the converted integer ("little"/"big")
        sign (str): Signedness of the converted integer ("unsigned"/"signed")
        kwargs (dict): Arguments passed to context.local(), such as
            ``endian`` or ``signed``.

    Returns:
        The unpacked number
    """
    ...

def u64(number):
    r"""
    u64(number, sign, endian, ...) -> int

    Unpacks an 64-bit integer

    Arguments:
        data (str): String to convert
        endianness (str): Endianness of the converted integer ("little"/"big")
        sign (str): Signedness of the converted integer ("unsigned"/"signed")
        kwargs (dict): Arguments passed to context.local(), such as
            ``endian`` or ``signed``.

    Returns:
        The unpacked number
    """
    ...

def u8(number):
    r"""
    u8(number, sign, endian, ...) -> int

    Unpacks an 8-bit integer

    Arguments:
        data (str): String to convert
        endianness (str): Endianness of the converted integer ("little"/"big")
        sign (str): Signedness of the converted integer ("unsigned"/"signed")
        kwargs (dict): Arguments passed to context.local(), such as
            ``endian`` or ``signed``.

    Returns:
        The unpacked number
    """
    ...

def unpack(data, word_size=None):
    r"""
    unpack(data, word_size = None, endianness = None, sign = None, **kwargs) -> int

    Packs arbitrary-sized integer.

    Word-size, endianness and signedness is done according to context.

    `word_size` can be any positive number or the string "all". Choosing the
    string "all" is equivalent to ``len(data)*8``.

    If `word_size` is not a multiple of 8, then the bits used for padding
    are discarded.

    Arguments:
        number (int): String to convert
        word_size (int): Word size of the converted integer or the string "all" (in bits).
        endianness (str): Endianness of the converted integer ("little"/"big")
        sign (str): Signedness of the converted integer (False/True)
        kwargs: Anything that can be passed to context.local

    Returns:
        The unpacked number.

    Examples:
        >>> hex(unpack(b'\xaa\x55', 16, endian='little', sign=False))
        '0x55aa'
        >>> hex(unpack(b'\xaa\x55', 16, endian='big', sign=False))
        '0xaa55'
        >>> hex(unpack(b'\xaa\x55', 16, endian='big', sign=True))
        '-0x55ab'
        >>> hex(unpack(b'\xaa\x55', 15, endian='big', sign=True))
        '0x2a55'
        >>> hex(unpack(b'\xff\x02\x03', 'all', endian='little', sign=True))
        '0x302ff'
        >>> hex(unpack(b'\xff\x02\x03', 'all', endian='big', sign=True))
        '-0xfdfd'
    """
    ...

def unpack_many(data, word_size=None):
    r"""
    unpack(data, word_size = None, endianness = None, sign = None) -> int list

    Splits `data` into groups of ``word_size//8`` bytes and calls :func:`unpack` on each group.  Returns a list of the results.

    `word_size` must be a multiple of `8` or the string "all".  In the latter case a singleton list will always be returned.

    Args
        number (int): String to convert
        word_size (int): Word size of the converted integers or the string "all" (in bits).
        endianness (str): Endianness of the converted integer ("little"/"big")
        sign (str): Signedness of the converted integer (False/True)
        kwargs: Anything that can be passed to context.local

    Returns:
        The unpacked numbers.

    Examples:
        >>> list(map(hex, unpack_many(b'\xaa\x55\xcc\x33', 16, endian='little', sign=False)))
        ['0x55aa', '0x33cc']
        >>> list(map(hex, unpack_many(b'\xaa\x55\xcc\x33', 16, endian='big', sign=False)))
        ['0xaa55', '0xcc33']
        >>> list(map(hex, unpack_many(b'\xaa\x55\xcc\x33', 16, endian='big', sign=True)))
        ['-0x55ab', '-0x33cd']
        >>> list(map(hex, unpack_many(b'\xff\x02\x03', 'all', endian='little', sign=True)))
        ['0x302ff']
        >>> list(map(hex, unpack_many(b'\xff\x02\x03', 'all', endian='big', sign=True)))
        ['-0xfdfd']
    """
    ...

def unsigned(integer):

    ...


import pwnlib.util.proc

def pidof(target):
    r"""
    pidof(target) -> int list

    Get PID(s) of `target`.  The returned PID(s) depends on the type of `target`:

    - :class:`str`: PIDs of all processes with a name matching `target`.
    - :class:`pwnlib.tubes.process.process`: singleton list of the PID of `target`.
    - :class:`pwnlib.tubes.sock.sock`: singleton list of the PID at the
      remote end of `target` if it is running on the host.  Otherwise an
      empty list.

    Arguments:
        target(object):  The target whose PID(s) to find.

    Returns:
        A list of found PIDs.

    Example:
        >>> l = tubes.listen.listen()
        >>> p = process(['curl', '-s', 'http://127.0.0.1:%d'%l.lport])
        >>> pidof(p) == pidof(l) == pidof(('127.0.0.1', l.lport))
        True
    """
    ...


import pwnlib.util.safeeval


import pwnlib.util.sh_string

def sh_command_with(f, *args):
    r"""
    sh_command_with(f, arg0, ..., argN) -> command

    Returns a command create by evaluating `f(new_arg0, ..., new_argN)`
    whenever `f` is a function and `f % (new_arg0, ..., new_argN)` otherwise.

    If the arguments are purely alphanumeric, then they are simply passed to
    function. If they are simple to escape, they will be escaped and passed to
    the function.

    If the arguments contain trailing newlines, then it is hard to use them
    directly because of a limitation in the posix shell. In this case the
    output from `f` is prepended with a bit of code to create the variables.

    Examples:

        >>> sh_command_with(lambda: "echo hello")
        'echo hello'
        >>> sh_command_with(lambda x: "echo " + x, "hello")
        'echo hello'
        >>> sh_command_with(lambda x: "/bin/echo " + x, "\\x01")
        "/bin/echo '\\x01'"
        >>> sh_command_with(lambda x: "/bin/echo " + x, "\\x01\\n")
        "/bin/echo '\\x01\\n'"
        >>> sh_command_with("/bin/echo %s", "\\x01\\n")
        "/bin/echo '\\x01\\n'"
    """
    ...

def sh_prepare(variables, export=False):
    r"""
    Outputs a posix compliant shell command that will put the data specified
    by the dictionary into the environment.

    It is assumed that the keys in the dictionary are valid variable names that
    does not need any escaping.

    Arguments:
      variables(dict): The variables to set.
      export(bool): Should the variables be exported or only stored in the shell environment?
      output(str): A valid posix shell command that will set the given variables.

    It is assumed that `var` is a valid name for a variable in the shell.

    Examples:

        >>> sh_prepare({'X': 'foobar'})
        'X=foobar'
        >>> r = sh_prepare({'X': 'foobar', 'Y': 'cookies'})
        >>> r == 'X=foobar;Y=cookies' or r == 'Y=cookies;X=foobar'
        True
        >>> sh_prepare({'X': 'foo bar'})
        "X='foo bar'"
        >>> sh_prepare({'X': "foo'bar"})
        "X='foo'\\''bar'"
        >>> sh_prepare({'X': "foo\\\\bar"})
        "X='foo\\\\bar'"
        >>> sh_prepare({'X': "foo\\\\'bar"})
        "X='foo\\\\'\\''bar'"
        >>> sh_prepare({'X': "foo\\x01'bar"})
        "X='foo\\x01'\\''bar'"
        >>> sh_prepare({'X': "foo\\x01'bar"}, export = True)
        "export X='foo\\x01'\\''bar'"
        >>> sh_prepare({'X': "foo\\x01'bar\\n"})
        "X='foo\\x01'\\''bar\\n'"
        >>> sh_prepare({'X': "foo\\x01'bar\\n"})
        "X='foo\\x01'\\''bar\\n'"
        >>> sh_prepare({'X': "foo\\x01'bar\\n"}, export = True)
        "export X='foo\\x01'\\''bar\\n'"
    """
    ...

def sh_string(s):
    r"""
    Outputs a string in a format that will be understood by /bin/sh.

    If the string does not contain any bad characters, it will simply be
    returned, possibly with quotes. If it contains bad characters, it will
    be escaped in a way which is compatible with most known systems.

    Warning:
        This does not play along well with the shell's built-in "echo".
        It works exactly as expected to set environment variables and
        arguments, **unless** it's the shell-builtin echo.

    Argument:
        s(str): String to escape.

    Examples:

        >>> sh_string('foobar')
        'foobar'
        >>> sh_string('foo bar')
        "'foo bar'"
        >>> sh_string("foo'bar")
        "'foo'\\''bar'"
        >>> sh_string("foo\\\\bar")
        "'foo\\\\bar'"
        >>> sh_string("foo\\\\'bar")
        "'foo\\\\'\\''bar'"
        >>> sh_string("foo\\x01'bar")
        "'foo\\x01'\\''bar'"
    """
    ...


import pwnlib.util.splash

def splash():
    r"""
    Put this at the beginning of your exploit to create the illusion that
    your sploit is enterprisey and top notch quality
    """
    ...


import pwnlib.util.web

def wget(url, save=None, timeout=5, **kwargs):
    r"""
    wget(url, save=None, timeout=5) -> str

    Downloads a file via HTTP/HTTPS.

    Arguments:
      url (str): URL to download
      save (str or bool): Name to save as.  Any truthy value
            will auto-generate a name based on the URL.
      timeout (int): Timeout, in seconds

    Example:

      >>> url    = 'https://httpbin.org/robots.txt'
      >>> result = wget(url, timeout=60)
      >>> result
      b'User-agent: *\nDisallow: /deny\n'

      >>> filename = tempfile.mktemp()
      >>> result2 = wget(url, filename, timeout=60)
      >>> result == open(filename, 'rb').read()
      True
    """
    ...


