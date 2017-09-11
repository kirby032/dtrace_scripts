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

pid$target::NfsExecContextCreate:entry /arg8 != 0/
{
    self->exec_context = arg8;
}

pid$target::NfsExecContextCreate:return /self->exec_context && arg1 == 0/
{
    contexts[*(int64_t*)copyin(self->exec_context, 8)] = timestamp;
}

pid$target::NfsExecContextCreate:return
{
    self->exec_context = 0
}


pid$target::NfsProtoNfs3Dispatch:entry
/contexts[arg0] != 0/
{
    this->delta = timestamp - contexts[arg0];
    @["Exec Context Create to Dispatch (ns)", -1] = quantize(this->delta);
    @count["ExecToDispatchCount", -1] = count();
    @avg["ExecToDispatchAvg", -1] = avg(this->delta);

    @["Procedure to Dispatch(ns)",*(uint32_t*)copyin(((int64_t)arg0) + 40,4)] = quantize(this->delta);
    @count["ProcedureToDispatchCount", *(uint32_t*)copyin(((int64_t)arg0) + 40,4)] = count();
    @avg["ProcedureToDispatchAvg", *(uint32_t*)copyin(((int64_t)arg0) + 40,4)] = avg(this->delta);
}

pid$target::NfsExecContextFree:entry
/contexts[*(int64_t*)copyin(arg0,8)]/
{
    this->context = *(void**)copyin(arg0,8);
    this->delta = timestamp - contexts[*(int64_t*)copyin(arg0,8)];
    @["Exec Context Total Time (nfs)", -1] = quantize(this->delta);
    @count["ExecToFinishCount", -1] = count();
    @avg["ExecToFinishAvg", -1] = avg(this->delta);

    /*
    printf("this->context: 0x%x, ((int64_t)this->context) + 40: 0x%x\n", (int64_t)this->context, ((int64_t)this->context) + 40);
    */
    @["Procedure TotalTime(ns)",*(uint32_t*)copyin(((int64_t)this->context) + 40,4)] = quantize(this->delta);
    @count["ProcedureToFinishCount", *(uint32_t*)copyin(((int64_t)this->context) + 40,4)] = count();
    @avg["ProcedureToFinishAvg", *(uint32_t*)copyin(((int64_t)this->context) + 40,4)] = avg(this->delta);
}

pid$target::NfsProtoNfs3ProcCreate:entry
{
    self->TrackCreate = 1;
    self->execContext = arg0;
    self->MeasureCreate = 0;
    self->BeginTimestamp = 0;
}

pid$target::FiberTaskBeginBlock:entry
{
    self->TrackCreate = 0;
    self->execContext = 0;
}

pid$target::NfsProtoNfs3ProcCreate:return
{
    self->TrackCreate = 0;
    self->execContext = 0;
}

pid$target::IoCreateFile:entry
/self->execContext != 0 && self->TrackCreate == 1/
{
    self->TrackIrpCreate = 1;
}

pid$target::IoCreateFile:return
/self->TrackIrpCreate == 1/
{
    self->TrackIrpCreate = 0;
}

/*
 * If we've enabled tracing and our type is 'create' then we
 * should measure the time taken for this irp
 */
pid$target::IopIrpCreate:entry
/ self->TrackIrpCreate == 1 && arg1 == 1 /
{
    self->irpContext= arg0;
}

pid$target::IopIrpCreate:return
/self->TrackIrpCreate && self->irpContext && arg1 == 0/
{
    irpContexts[*(int64_t*)copyin(self->irpContext, 8)] = timestamp;
}

pid$target::IopIrpCreate:return
{
    self->TrackIrpCreate = 0;
    self->irpContext = 0;
}

pid$target::IopIrpCompleteInternal:entry
/irpContexts[arg0] != 0/
{
    this->delta = timestamp - irpContexts[arg0];

    @["TimeForCreateIrpComplete (ns)", -1] = quantize(this->delta);
    @count["TimeForCreateIrpCompleteCount", -1] = count();
    @avg["TimeForCreateIrpCompleteAvg", -1] = avg(this->delta);
}

pid$target::IopIrpDereferenceAux:entry
/irpContexts[*(int64_t*)copyin(arg0,8)] != 0 &&
 *(int32_t*)copyin(*(int64_t*)copyin(arg0,8) + 0x170, 4) == 1/
{
    this->delta = timestamp - irpContexts[*(int64_t*)copyin(arg0,8)];
    irpContexts[*(int64_t*)copyin(arg0,8)] = 0;

    @["TimeForCreateIrp (ns)", -1] = quantize(this->delta);
    @count["TimeForCreateIrpCount", -1] = count();
    @avg["TimeForCreateIrpAvg", -1] = avg(this->delta);
}

pid$target::Nfs3CommonGetCcbByName:return
{
    self->MeasureCreate = 1;
    self->BeginTimestamp = timestamp;
}

pid$target::NfsStatsRecord:entry
/self->MeasureCreate != 0/
{
    this->delta = timestamp - self->BeginTimestamp;

    @["CreateToEnd (ns)", -1] = quantize(this->delta);
    @count["CreateToEndCount", -1] = count();
    @avg["CreateToEndAvg (ns)", -1] = avg(this->delta);
}

pid$target::NfsProtoNfs3ProcSymlink:return
/self->MeasureCreate != 0/
{
    self->MeasureCreate = 0;
    self->BeginTimestamp = 0;
}

pid$target::NfsProtoNfs3ProcMkdir:return
/self->MeasureCreate != 0/
{
    self->MeasureCreate = 0;
    self->BeginTimestamp = 0;
}

pid$target::NfsProtoNfs3ProcMknod:return
/self->MeasureCreate != 0/
{
    self->MeasureCreate = 0;
    self->BeginTimestamp = 0;
}

pid$target::_NfsSchedulePromiseComplete:entry
/self->MeasureCreate != 0/
{
    self->MeasureCreate = 0;
    self->BeginTimestamp = 0;
    self->MeasureSchedComplete = 1;
    self->SchedTimestamp = timestamp;
}

pid$target::Nfs3PromiseCallback:entry
/self->MeasureSchedComplete != 0/
{
    this->delta = timestamp - self->SchedTimestamp;
    self->SchedTimestamp = 0;

    @["SchedCompletion (ns)", -1] = quantize(this->delta);
    @count["SchedCompletionCount", -1] = count();
    @avg["SchedCompletionAvg (ns)", -1] = avg(this->delta);
}

pid$target::_NfsSchedulePromiseComplete:return
{
    self->MeasureCreate = 0;
    self->BeginTimestamp = 0;
    self->MeasureSchedComplete = 0;
    self->SchedTimestamp = 0;
}

/* Any exec context that takes over 1 ms 
pid$target::NfsExecContextFree:entry
/contexts[*(int64_t*)copyin(arg0,8)] && ((this->current = timestamp) - contexts[*(int64_t*)copyin(arg0,8)]  > 50000000)/
{
    comment here
    this->delta = ((this->current = timestamp) - contexts[arg0]) / 100000;
    
    this->delta = (this->current - contexts[*(int64_t*)copyin(arg0,8)]) / 1000;
    printf("%01dus, %01dus\n",
        (this->current - startTime) / 1000,
        this->delta);

    @["Exec Context execution time (us)"] = quantize(this->delta);
    contexts[*(int64_t*)copyin(arg0,8)] = 0;
}
*/

pid$target::NfsExecContextFree:entry
/contexts[*(int64_t*)copyin(arg0,8)]/
{
    contexts[*(int64_t*)copyin(arg0,8)] = 0;
}

tick-10s
{
    exit(0);
}

