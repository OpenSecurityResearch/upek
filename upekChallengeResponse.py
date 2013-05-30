#!/usr/bin/env python
#
# UPEK USB Protocol Challenge/Response Algo
# brad.antoniewicz@foundstone.com
#


# Verbosity
v=0;

def generateChalResp(bytes,resp):
    bytes = [bytes[i:i+2] for i in range(0,len(bytes),2)]
    x = 0;      # This value gets XOR'ed against the byte

    m = 0x0fdf; # Modifier value is constant for the first two
                # bytes then changes for bytes 3-18 depending 
                # on the message type (challenge or response)

    c = 0;      # Counter
    r = [];     # Store result here

    for b in bytes:
        b = int(b, 16);
        if c == 2: 
            # In the response, the first two decoded values are
            # used as the modifier for bytes 3-18 
            if resp: m = ( r[0] << 8) | r[1];
            else: m = int(''.join(bytes[0:2]),16); 
        for i in range(8):
            if m & 1:
                m >>= 1;
                m ^= 0xecfc;
                m |= 0x8000;
                x |= 1;
            else:
                m >>= 1;
            x <<= 1;
        t = (b ^ x) & 0xff;
        r.append(t);
        c += 1; 
    return r;


'''

For testing purposes, this is a valid challenge/response
sniffed between the reader and bsapi.dll (via BioEnroll.exe)

Challenge Value:
84 00 00 00 32 02 00 0D 00 3D 00 3D 00 CD FF 02 00 FD
FD FD FD FD FD E9 18 3C 1B 1A 7B 1C 1D C8 7C 34 6A 51
50 B7 9B 14 09 FD FD FD FD FD FD FD FD FD FD FD FD FD
FD 00 7C 48 94 07 C3 60 94 07 

Response Value:
04 9A 4F 3A ED 16 F1 90 44 CC EE 57 96 EB 41 CE D7 03
FD FD FD FD FD 33 FA 9A 4F 3A ED 16 F1 90 44 CC EE 57
96 EB 41 CE D7 FD FD FD FD FD FD FD FD FD FD FD FD FD
FD 00 7C 48 94 07 C3 60 94 07

'''
print "Response:"
# This is the value found in the response from the reader
print "33 FA 9A 4F 3A ED 16 F1 90 44 CC EE 57 96 EB 41 CE D7 [Confirmed]"
# This is the value we compute from the challenge (should match the above line)
for i in generateChalResp("E9183C1B1A7B1C1DC87C346A5150B79B1409",True):
    print "%02x"%i,;

print "\n\nChallenge:"
# This is the value found in the challenge from the system
print "E9 18 3C 1B 1A 7B 1C 1D C8 7C 34 6A 51 50 B7 9B 14 09 [Confirmed]"
# For good measure, this is just to confirm we can get the challenge value 
# from the response
for i in generateChalResp("33FA9A4F3AED16F19044CCEE5796EB41CED7",False):
    print "%02x"%i,;

