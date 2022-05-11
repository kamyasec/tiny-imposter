# tiny-imposter

A small project re-creating well-known techniques in PE-infection, because I couldn't find any I liked to use. Also because I wanted to explore PEs and shellcoding a little. There are many ways to extend the program to get better evasion.

Inspiration:
* Idea (I love you VXUG).
    * https://papers.vx-underground.org/papers/Windows/Infection/Another%20detailed%20guide%20to%20PE%20infection.txt
    * https://papers.vx-underground.org/papers/Windows/Infection/Detailed%20Guide%20to%20PE%20Infection.txt
    * https://papers.vx-underground.org/papers/Windows/Infection/PE%20Infection%20-%20Add%20a%20PE%20section%20-%20with%20code.txt
* Shellter-project
* Shellcode-launcher: https://www.exploit-db.com/exploits/49819

Dependencies:
* The wonderful and brilliant pefile project: https://github.com/erocarrera/pefile

## Usage:

```bash
$ python3 tiny-imposter.py legit.exe shellcode.bin
```

It works by adding a new section to the PE, creating a jump pad in .text by replacing null-bytes and changing the entrypoint. The jump pad calls a wrapper in the added section which calls CreateThread on the supplied shellcode before jumping back to the original entrypoint.

Normal PE:
```
PE => entrypoint
```

impostered PE:
```
PE => jump pad => added section launcher => shellcode
                                => entrypoint
```


No clue if this works with DLLs. Wont work with managed code.
