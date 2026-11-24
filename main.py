import binascii, zlib

frags = {
    0x00: "6aab57c4ec21eee5f6a840fd91e85fc98eb01054687b417a72ccdc25",
    0x01: "7e561046db954397892f09c898aa678617a816fc447798127c7dc249",
    0x02: "5e76f4c8e1b7aa7c50b6e82ca1bc8a8560826d5abf15c63440b0ba48",
    0x03: "cc9ec64935565c05f9f755721379147b32716c09c70828f6064539ab",
    0x04: "2a37863af7afd652810cb41338fa17b3ea84e5f34b311d430f413484",
    0x05: "1f3e05ca93e762866906a9b71380ce09d2b1fcaf5dcab0726af37768",
    0x06: "691e4e4aa4240a61e8cb3a096ae724a15dfba823fa5b6cf392e85ce6",
    0x07: "96638ea1d397fda1bc14006e9d5f874b1d1d180b61fff6564edad562",
    0x08: "ca14f2ec4c4ab4a330cde36a74cd08349f39dd8ffa8b3c8b51eb8448",
    0x09: "2a7321245b5c28d8213caad95c867278d4d9456c17482e13275b2f1f",
    0x0a: "0a29b04f82df6d57aa500b087107f4e343c7fa7907e908e5da92166d",
    0x0b: "41e171060afbc11f7be5940095be13da",
}

def rc4(key, data):
    S = list(range(256)); j = 0; key = key.encode()
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    i = j = 0; out = bytearray()
    for b in data:
        i = (i+1)%256; j = (j+S[i])%256; S[i],S[j] = S[j],S[i]
        out.append(b ^ S[(S[i]+S[j])%256])
    return bytes(out)

cipher = b"".join(binascii.unhexlify(frags[k])[:-4] for k in sorted(frags))
plain = rc4("test", cipher)
open("stolen.zip", "wb").write(plain)
print("stolen.zip écrit :", len(plain), "octets")
