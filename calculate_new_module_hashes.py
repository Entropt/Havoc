#!/usr/bin/env python3

def hashex_correct(string, hash_key=1205, upper=True):
    """
    CORRECT implementation of HashEx from Win32.c
    
    The trick: When encountering NULL byte with length:
    - Increments ptr (line 42)
    - Does NOT skip hash calculation!  
    - Adds 0x00 to hash (line 48)
    - Increments ptr again (line 51)
    
    So ptr advances by 2, but 0x00 is added to hash.
    """
    wide_bytes = bytearray(string.encode('utf-16-le'))
    length = len(wide_bytes)
    hash_value = hash_key
    ptr = 0
    
    while True:
        if ptr >= len(wide_bytes):
            break
            
        character = wide_bytes[ptr]
        
        # Check if we've reached the length
        if ptr >= length:
            break
        
        # If null byte, increment ptr (but still process the character!)
        if character == 0:
            ptr += 1
        
        # Uppercase if requested
        if upper and character >= ord('a'):
            character -= 0x20
        
        # Add to hash
        hash_value = ((hash_value << 5) + hash_value) + character
        hash_value &= 0xFFFFFFFF
        
        # Always increment ptr
        ptr += 1
    
    return hash_value


print("=" * 80)
print("VERIFICATION WITH ORIGINAL HASH_KEY = 5381")
print("=" * 80)

ntdll_5381 = hashex_correct("ntdll.dll", 5381)
kernel32_5381 = hashex_correct("kernel32.dll", 5381)

print(f"ntdll.dll    => 0x{ntdll_5381:08x}  (expected: 0x70e61753) {'✓ MATCH!' if ntdll_5381 == 0x70e61753 else '✗ MISMATCH'}")
print(f"kernel32.dll => 0x{kernel32_5381:08x}  (expected: 0xadd31df0) {'✓ MATCH!' if kernel32_5381 == 0xadd31df0 else '✗ MISMATCH'}")

print("\n" + "=" * 80)
print("NEW HASHES WITH HASH_KEY = 1205")
print("=" * 80)

ntdll_1205 = hashex_correct("ntdll.dll", 1205)
kernel32_1205 = hashex_correct("kernel32.dll", 1205)

print(f"ntdll.dll    => 0x{ntdll_1205:08x}")
print(f"kernel32.dll => 0x{kernel32_1205:08x}")

print("\n" + "=" * 80)
print("UPDATE DEFINES.H WITH THESE VALUES:")
print("=" * 80)
print(f"#define H_MODULE_KERNEL32                           0x{kernel32_1205:08x}")
print(f"#define H_MODULE_NTDLL                              0x{ntdll_1205:08x}")
