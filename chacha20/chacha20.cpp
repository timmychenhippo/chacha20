#include"chacha20.h"

// Generic left rotate.
#define leftRotate(a, bits) ((a << (bits)) | (a >> (32 - (bits))))

// Perform a ChaCha quarter round operation.
#define quarterRound(a, b, c, d) (     \
    a += b,  d ^= a,  d = leftRotate(d,16),	\
	c += d,  b ^= c,  b = leftRotate(b,12),	\
	a += b,  d ^= a,  d = leftRotate(d, 8),	\
	c += d,  b ^= c,  b = leftRotate(b, 7))

void clean(void* dest, size_t size)
{
    // Force the use of volatile so that we actually clear the memory.
    // Otherwise the compiler might optimise the entire contents of this
    // function away, which will not be secure.
    volatile uint8_t* d = (volatile uint8_t*)dest;
    while (size > 0) {
        *d++ = 0;
        --size;
    }
}

static inline void u32t8le(uint32_t v, uint8_t p[4]) {
    p[0] = v & 0xff;
    p[1] = (v >> 8) & 0xff;
    p[2] = (v >> 16) & 0xff;
    p[3] = (v >> 24) & 0xff;
}

static inline uint32_t u8t32le(uint8_t p[4]) {
    uint32_t value = p[3];

    value = (value << 8) | p[2];
    value = (value << 8) | p[1];
    value = (value << 8) | p[0];

    return value;
}

/**
* \20 Round for Algorithm.
* \64-byte(512-bit) for Block position
*/
ChaCha20::ChaCha20(uint8_t numRounds):round(numRounds) 
{
    memset(block, 0, 64);
    memset(stream, 0, 64); //uit32_t will be change uint8_t
                           //16 elements should be 64
                           //numRounds:20

}
ChaCha20::~ChaCha20()
{
    clean(block,64);
    clean(stream, sizeof(uint32_t)*16);
}
size_t ChaCha20::KeySize() const
{
    // Default Key size is 256-bit(32-byte)
    return 32;
}
size_t ChaCha20::IVSize() const
{
    // Default IV size is 96-bit(12-byte)
    return 12;
}

bool ChaCha20::setKey(const Ktools* tools)
{
    static const uint8_t cons_str[] = "expand 32-byte k";
    if (tools->keySize==32)
    {
        memcpy(block, cons_str, 16);
        memcpy(block + 16, tools->key, tools->keySize);
        return true;
    }
    else
    {
        return false;
    }
}
bool ChaCha20::setIV(const Ktools* tools)
{
    if (tools->ivSize == 12)
    {
        memset(block+48, 0, 4);
        memcpy(block + 52, tools->iv, tools->ivSize);
        return true;
    }
    else
    {
        return false;
    }
}
/**
*This function must be called after setIV() and before the first call
* to encrypt().It is used to specify a different starting value than
* zero for the counter portion of the hash input.
*/
bool ChaCha20::setCounter(const Ktools* tool)
{
    uint8_t counter[4];
    u32t8le(tool->counter, counter);
    if (tool->counterSize == 4 ) 
    {
        memcpy(block + 48, counter, tool->counterSize);
        return true;
    }
    else {
        return false;
    }
}

bool ChaCha20::initBlock()
{
    return setKey(&(tool)) && setIV(&(tool)) && setCounter(&(tool));
}
void ChaCha20::encrypt(uint8_t* output, const uint8_t* input, uint8_t len)
{
    initBlock();
    //uint8_t templen = len;
    for (uint8_t i = 0; i < len; i += 64)
    {
        hashCore(stream, block);
        uint8_t stream8[64];
        memcpy(stream8, stream, 64);
        uint16_t temp = 1;
        uint8_t index = 48;
        while (index < 56) {
            temp += block[index];
            block[index] = (uint8_t)temp;
            temp >>= 8;
            ++index;
        }
        for (uint8_t posn = i; posn < i + 64; posn++) 
        {
            if (posn >= len) 
            {
                break;
            }
            output[posn] = input[posn] ^ stream8[posn - i];
        }
    }

}

void ChaCha20::hashCore(uint32_t* output, uint8_t* input)
{
    uint8_t posn;
    uint32_t input32[16];
    // Copy the input buffer to the output prior to the first round
    // and convert from little-endian to host byte order.
    memcpy(output, input, sizeof(uint32_t) * 16);
    memcpy(input32, input, sizeof(uint32_t) * 16);
    // Perform the ChaCha rounds in sets of two.
    for (uint8_t numround= numRounds(); numround >= 2; numround -= 2) {

        // Column round.
        quarterRound(output[0], output[4], output[8], output[12]);
        quarterRound(output[1], output[5], output[9], output[13]);
        quarterRound(output[2], output[6], output[10], output[14]);
        quarterRound(output[3], output[7], output[11], output[15]);

        // Diagonal round.
        quarterRound(output[0], output[5], output[10], output[15]);
        quarterRound(output[1], output[6], output[11], output[12]);
        quarterRound(output[2], output[7], output[8], output[13]);
        quarterRound(output[3], output[4], output[9], output[14]);
    }

    // Add the original input to the final output, convert back to
    // little-endian, and return the result.
    for (posn = 0; posn < 16; ++posn)
    {
        output[posn] = (output[posn] + input32[posn]);
    }
}

void ChaCha20::decrypt(uint8_t* output, const uint8_t* input, uint8_t len)
{
    encrypt(output, input, len);
}
