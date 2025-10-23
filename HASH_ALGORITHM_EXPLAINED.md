# Hash Algorithm Explanation

## Summary

The original H_MODULE hashes (0x70e61753 for ntdll, 0xadd31df0 for kernel32) were calculated using:
- **Algorithm**: HashEx() from Win32.c  
- **Hash Key**: 5381 (original)
- **Input**: BaseDllName (e.g., "ntdll.dll", "kernel32.dll") as UTF-16 LE wide string
- **Upper**: TRUE (uppercases ASCII letters)

The new H_MODULE hashes with HASH_KEY = 1205 are:
- **H_MODULE_NTDLL**: 0xf8996303
- **H_MODULE_KERNEL32**: 0x26270ba0

## The HashEx Algorithm - Key Discovery

The critical insight is how HashEx handles NULL bytes in wide strings when Length is specified:

```c
if ( /home/entropt/Havoc && grep "H_MODULE" payloads/Demon/include/common/Defines.hPtr ) {
    ++Ptr;  // Increments pointer
}           // Does NOT skip hash calculation!

// Falls through to:
Hash = ((Hash << 5) + Hash) + character;  // Adds 0x00 to hash!
++Ptr;  // Increments again
```

**Result**: For wide strings, only NULL bytes (0x00) are added to the hash, and actual characters are skipped!

### Example: "ntdll.dll" hashing

Wide string bytes: `6e 00 74 00 64 00 6c 00 6c 00 2e 00 64 00 6c 00 6c 00`

1. ptr=0: character='n' (0x6e), skip to hash calculation... wait, NO!
2. Actually ptr=0: char=0x6e, uppercase to 0x4E, add to hash, ptr becomes 1
3. ptr=1: char=0x00 (NULL), increment ptr to 2, add 0x00 to hash, ptr becomes 3  
4. ptr=3: char=0x00 (NULL), increment ptr to 4, add 0x00 to hash, ptr becomes 5
5. ...and so on

So the hash only sees: `4E 00 00 00 00 00 00 00 00 00` (uppercase 'N' followed by 9 null bytes)

## Historical Context

- **Original HASH_KEY**: 5381 (standard djb2)
- **New HASH_KEY**: 1205 (custom for obfuscation)
- **Changed in**: Commit 9f72c5d "restructure demon agent project"
- **Files affected**:
  - payloads/Demon/include/core/Win32.h (HASH_KEY definition)
  - payloads/Shellcode/Source/Utils.c (HashString function)
  - payloads/Demon/include/common/Defines.h (H_MODULE_* values)

## Files Updated

1. `/home/entropt/Havoc/payloads/Demon/include/common/Defines.h`
   - H_MODULE_KERNEL32: 0xadd31df0 → 0x26270ba0
   - H_MODULE_NTDLL: 0x70e61753 → 0xf8996303

## Verification

Run: `python3 calculate_new_module_hashes.py`

Expected output:
```
ntdll.dll    => 0xf8996303
kernel32.dll => 0x26270ba0
```
