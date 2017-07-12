#!/usr/sbin/dtrace -s

#pragma D option quiet
#pragma D option dynvarsize=128m

BEGIN
{
    /*
    printf("Dumping NFS exec contexts that took more than %d ms to execute\n",
           $2);
    */
    startTime = timestamp;
    printf("TIMEus DELTAus\n");
}


END
{
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
    /*
    this->delta = ((this->current = timestamp) - contexts[arg1]) / 100000;
    */
    this->delta = ((this->current = timestamp) - contexts[arg1]) / 1000;
    printf("%01d %01d\n",
        (this->current - startTime) / 1000,
        this->delta);
    contexts[arg1] = 0;
}

