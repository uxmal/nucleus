#ifndef NUCLEUS_LOG_H
#define NUCLEUS_LOG_H

void verbose    (int level, char const *fmt, ...);
void print_warn (char const *fmt, ...);
void print_err  (char const *fmt, ...);

#endif /* NUCLEUS_LOG_H */

