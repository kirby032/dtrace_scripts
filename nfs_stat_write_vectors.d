#!/usr/sbin/dtrace -s

pid$target::NfsIovecFromZC:entry
{
    self->do_trace = 1;
}

pid$target::NfsIovecEntryFromZC:entry
/self->do_trace == 1/
{
    self->entry = arg0;
}

pid$target::NfsIovecEntryFromZC:return
/self->entry && arg1 == 0/
{
    this->entry = *(int64_t*)copyin((int64_t)self->entry, 8);
    this->Type = *(uint32_t*)copyin(this->entry + 24, 4);
    this->Size = *(uint32_t*)copyin(this->entry + 32, 4);
    @[this->Type] = sum(this->Size);
}

pid$target::NfsIovecEntryFromZC:return
{
    self->entry = 0;
}

pid$target::NfsIovecFromZC:return
{
    self->do_trace = 0;
}
