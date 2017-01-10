#ifndef NUCLEUS_UTIL_H
#define NUCLEUS_UTIL_H

#include <stdint.h>

#include <string>

string str_realpath      (string s);
string str_realpath_dir  (string s);
string str_realpath_base (string s);
string str_getenv        (string env);

uint64_t rand64          ();
uint64_t xorshift128plus ();
uint64_t fast_rand64     ();

template<typename T> bool compare_ptr (const T *const& a, const T *const& b) { return (*a) < (*b); }

#endif /* NUCLEUS_UTIL_H */

