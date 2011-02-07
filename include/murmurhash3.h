#include <stdint.h>    // for _rotl
#include <stdlib.h>    // for _rotl

//-----------------------------------------------------------------------------
// Block read - if your platform needs to do endian-swapping or can only
// handle aligned reads, do the conversion here

static inline uint32_t getblock ( const uint32_t * p, int i )
{
	return p[i];
}

//----------
// Finalization mix - force all bits of a hash block to avalanche

// avalanches all bits to within 0.25% bias

static inline uint32_t fmix32 ( uint32_t h )
{
	h ^= h >> 16;
	h *= 0x85ebca6b;
	h ^= h >> 13;
	h *= 0xc2b2ae35;
	h ^= h >> 16;

	return h;
}

static inline unsigned int _rotl(uint32_t value, int shift) {
    if ((shift &= 31) == 0)
      return value;
    return (value << shift) | (value >> (32 - shift));
}

//-----------------------------------------------------------------------------

static inline void bmix32 ( uint32_t *h1, uint32_t *k1, uint32_t *c1, uint32_t *c2 )
{
	*k1 *= *c1; 
	*k1  = _rotl(*k1,11); 
	*k1 *= *c2;
	*h1 ^= *k1;

	*h1 = *h1*3+0x52dce729;

	*c1 = *c1*5+0x7b7d159c;
	*c2 = *c2*5+0x6bce6396;
}

//----------

static inline void MurmurHash3_x86_32 ( const void * key, int len, uint32_t seed, void * out )
{
	const uint8_t * data = (const uint8_t*)key;
	const int nblocks = len / 4;

	uint32_t h1 = 0x971e137b ^ seed;

	uint32_t c1 = 0x95543787;
	uint32_t c2 = 0x2ad7eb25;
	int i;

	//----------
	// body

	const uint32_t * blocks = (const uint32_t *)(data + nblocks*4);

	for(i = -nblocks; i; i++)
	{
		uint32_t k1 = getblock(blocks,i);

		bmix32(&h1,&k1,&c1,&c2);
	}

	//----------
	// tail

	const uint8_t * tail = (const uint8_t*)(data + nblocks*4);

	uint32_t k1 = 0;

	switch(len & 3)
	{
		case 3: k1 ^= tail[2] << 16;
		case 2: k1 ^= tail[1] << 8;
		case 1: k1 ^= tail[0];
			bmix32(&h1,&k1,&c1,&c2);
	};

	//----------
	// finalization

	h1 ^= len;

	h1 = fmix32(h1);

	*(uint32_t*)out = h1;
} 
