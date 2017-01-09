#include <time.h>
#include <limits.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <libgen.h>

#include <string>
#include <random>


/*******************************************************************************
 **                                string utils                               **
 ******************************************************************************/
std::string
str_realpath(std::string s)
{
  char real[PATH_MAX+1];

  if(!realpath(s.c_str(), real)) {
    return "";
  }
  return std::string(real);
}


std::string
str_realpath_dir(std::string s)
{
  char real[PATH_MAX+1], *dir;

  if(!realpath(s.c_str(), real)) {
    return "";
  }

  dir = dirname(real);
  return std::string(dir);
}


std::string
str_realpath_base(std::string s)
{
  char real[PATH_MAX+1], *base;

  if(!realpath(s.c_str(), real)) {
    return "";
  }

  base = basename(real);
  return std::string(base);
}


std::string
str_getenv(std::string env)
{
  char *e;

  e = getenv(env.c_str());
  return e ? std::string(e) : "";
}

/*******************************************************************************
 **                               rand functions                              **
 ******************************************************************************/
uint64_t
rand64()
{
  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_int_distribution<unsigned long long> dis(0, 0xffffffffffffffff);
 
  return dis(gen);
}


uint64_t
xorshift128plus()
{
  uint64_t x, y;
  static uint64_t s[2];
  static int inited = 0;

  if(!inited) {
    s[0] = rand64();
    s[1] = rand64();
    inited = 1;
  }

  x = s[0];
  y = s[1];

  s[0] = y;
  x ^= x << 23;
  s[1] = x ^ y ^ (x >> 17) ^ (y >> 26);

  return s[1] + y;
}


uint64_t
fast_rand64()
{
  return xorshift128plus();
}

