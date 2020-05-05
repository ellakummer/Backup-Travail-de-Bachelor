#ifndef INDCPA_H
#define INDCPA_H


static inline uint64_t mul_mod_p(uint64_t a, uint64_t b);
static inline uint64_t pow_mod_p(uint64_t a, uint64_t b);
uint64_t powmodp(uint64_t a, uint64_t b);
uint64_t randomint64();
uint64_t dh_computing(uint64_t a, uint64_t b);

#endif
