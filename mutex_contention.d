#!/usr/sbin/dtrace -s

#pragma D option quiet
#pragma D option dynvarsize=128m

BEGIN
{
}

END
{
}


pid$target::NfsLruSetValue:entry
{
    self->start_time = timestamp;
}

/* If taking the lock took more than 1us quantize it */
pid$target::NfsLruSetValue:return
/((self->current = timestamp) - self->start_time) > 1000/
{
    @["Mutex Acquire Time (ns)"] = quantize(self->current - self->start_time);
    @average["average"] = avg(self->current - self->start_time);
    self->current = 0;
}

pid$target::NfsLruSetValue:return
{
    @count["Num Lock Calls"] = count();
    self->start_time = 0;
}


