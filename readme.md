# Xor Nt Shellcode Runner

This payload uses the XOR cipher to decrypt and execute shellcode using NT API calls. It's a shellcode runner that executes the shellcode within the address space of itself.

## Instructions

1. Encrypt your shellcode using the XOR algorithm.

2. Populate the following variables at lines 13 & 14 with your encryption key and encrypted shellcode, in [main.c](/main.c).

```
unsigned char			ucEncryptionKey[]	= "";
unsigned char			ucShellCode[]		= {};
```

> [!Note]
> Your shellcode should be using raw bytes in hex, not strings.  
> Correct: 0x00  
> Incorrect: "\x00"  

3. Compile and detonate :)

## Mitre | ATT&CK

| Tactic | Technique | ID |
|-|-|-|
| [Execution](https://attack.mitre.org/tactics/TA0002/) | Native API | [T1106](https://attack.mitre.org/techniques/T1106/)
| [Defense Evasion](https://attack.mitre.org/tactics/TA0005/) | Obfuscated Files or Information | [T1027](https://attack.mitre.org/techniques/T1027/)