#!/usr/sbin/dtrace -s

#pragma D option quiet
#pragma D option dynvarsize=128m

BEGIN
{
    startTime = timestamp;
    min_ns = 1000000;
}

pid$1::NfsExecContextCreate:entry /arg9 != 0/
{
    self->exec_context = arg9;
}

pid$1::NfsExecContextCreate:return /self->exec_context && arg1 == 0/
{
    contexts[*(int64_t*)copyin(self->exec_context, 8)] = timestamp;
}

pid$1::NfsExecContextCreate:return
{
    self->exec_context = 0
}


pid$1::NfsExecContextContinue:entry
/contexts[arg1]/
{
    @time["Average exec latency (ns)"] = quantize(timestamp - contexts[arg1]);
    contexts[arg1] = 0;
}

sched:::off-cpu /execname == "nfs"/
{
    self->ts = timestamp;
}


sched:::on-cpu /self->ts && ((timestamp - self->ts) > min_ns)/
{
    @offcpu[ustack()] = quantize(timestamp - self->ts);
}
sched:::on-cpu /self->ts/
{
    self->ts = 0;
}

profile:::tick-5s,
dtrace:::END
{
    printf("NFS Query Latency (ns):\n");

    printa(@time);
    clear(@time);
}

dtrace:::END
{
    printf("Top 10 off-CPU user & kernel stacks, by wait latency(ns):\n");
}

