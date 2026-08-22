#include "port.h"
#include "time.h"
/* NS-TIME (s249, Lon in-chat): ONE clock across SCRIP / SPITBOL / CSNOBOL4 -- CLOCK_MONOTONIC nanoseconds since an
   arbitrary epoch.  This RESTORES the nanosecond unit that 3e519f9 replaced with milliseconds; sbl.min:16746-16752
   still divides the value by 1000 twice to reach ms and has been wrong for the whole interval.  It also moves the arm
   off CLOCK_PROCESS_CPUTIME_ID, which on this host resolves no finer than ~471 ns and costs ~502 ns per read (a real
   syscall), to CLOCK_MONOTONIC: 1 ns resolution, ~20 ns per read through the vDSO.  A CPU-clock "nanosecond" TIME()
   would be fake precision and would perturb the loop it measures.  sbl.min subtracts timsx, so the epoch cancels. */
int zystm() {
    struct timespec tim;
    clock_gettime(CLOCK_MONOTONIC, &tim);
    long etime = (long)tim.tv_sec * 1000000000L + (long)tim.tv_nsec;
    SET_IA(etime);
    return NORMAL_RETURN;
}
