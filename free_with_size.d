#!/usr/sbin/dtrace -s

BEGIN
{
    printf("Tracking pid %d\n", $1);
}

pid$1::malloc:entry /arg0 > 992 && arg0 <= 2016/
{
    @[ustack()] = count();
}
