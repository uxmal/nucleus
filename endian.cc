#include "endian.h"

/* Detect host endianness */
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define NUCLEUS_HOST_LE
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define NUCLEUS_HOST_BE
#endif

/* Endian swap */
#define SWAP_16(x) ( \
  (((x) >> 8) & 0x00FF) | (((x) << 8) & 0xFF00) \
)
#define SWAP_32(x) ( \
  (((x) >> 24) & 0x000000FF) | (((x) >>  8) & 0x0000FF00) | \
  (((x) <<  8) & 0x00FF0000) | (((x) << 24) & 0xFF000000)   \
)
#define SWAP_64(x) ( \
  (((x) >> 56) & 0x00000000000000FF) | (((x) >> 40) & 0x000000000000FF00) | \
  (((x) >> 24) & 0x0000000000FF0000) | (((x) >>  8) & 0x00000000FF000000) | \
  (((x) <<  8) & 0x000000FF00000000) | (((x) << 24) & 0x0000FF0000000000) | \
  (((x) << 40) & 0x00FF000000000000) | (((x) << 56) & 0xFF00000000000000)   \
)


/* Little-Endian reads */
uint16_t read_le_i16(const uint16_t* data)
{
  uint16_t value = *data;
#if defined(NUCLEUS_HOST_LE)
  return value;
#elif defined(NUCLEUS_HOST_BE)
  return SWAP_16(value);
#endif
}

uint32_t read_le_i32(const uint32_t* data)
{
  uint32_t value = *data;
#if defined(NUCLEUS_HOST_LE)
  return value;
#elif defined(NUCLEUS_HOST_BE)
  return SWAP_32(value);
#endif
}

uint64_t read_le_i64(const uint64_t* data)
{
  uint64_t value = *data;
#if defined(NUCLEUS_HOST_LE)
  return value;
#elif defined(NUCLEUS_HOST_BE)
  return SWAP_64(value);
#endif
}


/* Big-Endian reads */
uint16_t read_be_i16(const uint16_t* data)
{
  uint16_t value = *data;
#if defined(NUCLEUS_HOST_BE)
  return value;
#elif defined(NUCLEUS_HOST_LE)
  return SWAP_16(value);
#endif
}

uint32_t read_be_i32(const uint32_t* data)
{
  uint32_t value = *data;
#if defined(NUCLEUS_HOST_BE)
  return value;
#elif defined(NUCLEUS_HOST_LE)
  return SWAP_32(value);
#endif
}

uint64_t read_be_i64(const uint64_t* data)
{
  uint64_t value = *data;
#if defined(NUCLEUS_HOST_BE)
  return value;
#elif defined(NUCLEUS_HOST_LE)
  return SWAP_64(value);
#endif
}
