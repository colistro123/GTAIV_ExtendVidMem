#ifndef TIMER_H
#define TIMER_H
static double		pfreq;
static double		curtime = 0.0;
static double		lastcurtime = 0.0;
static int			lowshift;

void InitializeClock();
double Sys_FloatTime(void);

#endif