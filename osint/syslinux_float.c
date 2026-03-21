/*
 * syslinux_float.c - C-ABI float helpers missing from math.c.
 *
 * math.c provides void f_atn..f_tan(void) using reg_ra global (MINIMAL style).
 * syslinux.c APDF table needs f_2_i, i_2_f, and the arithmetic f_add..f_neg
 * which are genuinely absent from math.c.
 *
 * The trig functions (f_atn, f_chp, f_cos, f_etx, f_lnf, f_sin, f_sqr, f_tan)
 * are provided by math.c — declared extern void in syslinux.c via cast.
 */

#include <math.h>

long   f_2_i(double ra)             { return (long)ra; }
double i_2_f(long ia)               { return (double)ia; }
double f_add(double arg, double ra) { return arg + ra; }
double f_sub(double arg, double ra) { return arg - ra; }
double f_mul(double arg, double ra) { return arg * ra; }
double f_div(double arg, double ra) { return (ra != 0.0) ? arg / ra : __builtin_nan(""); }
double f_neg(double ra)             { return -ra; }
