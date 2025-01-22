#ifndef FIXED_H
#define FIXED_H

#include <stdint.h>

#define F (1 << 14)

typedef int fixed_t;

static inline fixed_t
int_to_fixed(int n)
{
  return n * F;
}

static inline int
fixed_to_int_trunc(fixed_t x)
{
  return x / F;
}

static inline int
fixed_to_int_near(fixed_t x)
{
  if (x >= 0)
    return (x + F / 2) / F;
  else
    return (x - F / 2) / F;
}

static inline fixed_t
fixed_add(fixed_t x, fixed_t y)
{
  return x + y;
}

static inline fixed_t
fixed_sub(fixed_t x, fixed_t y)
{
  return x - y;
}

static inline fixed_t
fixed_add_int(fixed_t x, int n)
{
  return x + n * F;
}

static inline fixed_t
fixed_sub_int(fixed_t x, int n)
{
  return x - n * F;
}

static inline fixed_t
fixed_mult(fixed_t x, fixed_t y)
{
  return ((int64_t) x) * y / F;
}

static inline fixed_t
fixed_mult_int(fixed_t x, int n)
{
  return x * n;
}

static inline fixed_t
fixed_div(fixed_t x, fixed_t y)
{
  return ((int64_t) x) * F / y;
}

static inline fixed_t
fixed_div_int(fixed_t x, int n)
{
  return x / n;
}

#endif