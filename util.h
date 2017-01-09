#ifndef NUCLEUS_UTIL_H
#define NUCLEUS_UTIL_H

#include <stdint.h>

#include <string>

std::string str_realpath      (std::string s);
std::string str_realpath_dir  (std::string s);
std::string str_realpath_base (std::string s);
std::string str_getenv        (std::string env);

uint64_t rand64          ();
uint64_t xorshift128plus ();
uint64_t fast_rand64     ();

template<typename T> bool compare_ptr (const T *const& a, const T *const& b) { return (*a) < (*b); }

#endif /* NUCLEUS_UTIL_H */

