#!/usr/bin/env python3

def hashex_trace(string, hash_key, length, upper=True):
    """
    Exact implementation of HashEx from Win32.c with detailed tracing.
    """
    wide_bytes = bytearray(string.encode('utf-16-le'))
    hash_value = hash_key
    ptr = 0
    
    print(f"\nHashing '{string}' with key {hash_key}, length={length}, upper={upper}")
    print(f"Wide bytes ({len(wide_bytes)}): {' '.join(f'{b:02x}' for b in wide_bytes)}")
    print(f"\nInitial hash: 0x{hash_value:08x}")
    print("\nByte-by-byte processing:")
    
    iteration = 0
    while True:
        if ptr >= len(wide_bytes):
            print(f"\n[{iteration:3d}] ptr={ptr} >= len={len(wide_bytes)}, breaking (end of buffer)")
            break
        
        character = wide_bytes[ptr]
        
        # Check termination conditions
        if length == 0:
            if character == 0:
                print(f"\n[{iteration:3d}] ptr={ptr}, char=0x{character:02x}, no length and null byte, breaking")
                break
        else:
            # Check if we've reached the length
            if ptr >= length:
                print(f"\n[{iteration:3d}] ptr={ptr} >= length={length}, breaking")
                break
            
            # If null byte with length, increment ptr but CONTINUE processing!
            if character == 0:
                print(f"[{iteration:3d}] ptr={ptr:2d}, char=0x{character:02x} (NULL), incrementing ptr", end="")
                ptr += 1
                print(f" => ptr={ptr}", end="")
                # NOTE: Does NOT continue! Falls through to add 0x00 to hash!
        
        # Uppercase if requested
        orig_char = character
        if upper and character >= ord('a'):
            character -= 0x20
            if orig_char != 0:
                print(f", uppercased 0x{orig_char:02x}=>0x{character:02x}", end="")
        
        # Add to hash
        old_hash = hash_value
        hash_value = ((hash_value << 5) + hash_value) + character
        hash_value &= 0xFFFFFFFF
        
        if orig_char == 0:
            print(f", hash: 0x{old_hash:08x} + 0x00 => 0x{hash_value:08x}")
        else:
            char_display = chr(orig_char) if 32 <= orig_char < 127 else '?'
            print(f" [{iteration:3d}] ptr={ptr:2d}, char=0x{character:02x} '{char_display}', hash: 0x{old_hash:08x} => 0x{hash_value:08x}")
        
        # Always increment ptr
        ptr += 1
        iteration += 1
    
    print(f"\nFinal hash: 0x{hash_value:08x}")
    return hash_value


# Test with original hash key
print("=" * 80)
print("TESTING WITH ORIGINAL HASH_KEY = 5381")
print("=" * 80)

result_ntdll = hashex_trace("ntdll.dll", 5381, 18, True)
print(f"\n{'='*80}")
print(f"Expected: 0x70e61753")
print(f"Got:      0x{result_ntdll:08x}")
print(f"Match:    {result_ntdll == 0x70e61753}")

print("\n\n" + "=" * 80)

result_kernel32 = hashex_trace("kernel32.dll", 5381, 24, True)
print(f"\n{'='*80}")
print(f"Expected: 0xadd31df0")
print(f"Got:      0x{result_kernel32:08x}")
print(f"Match:    {result_kernel32 == 0xadd31df0}")
