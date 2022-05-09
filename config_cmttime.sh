#!/usr/bin/sh

WORK_DIR=$(cd "$( dirname "$0" )" && pwd)

cd "$WORK_DIR" || exit

../tools/AutoMacro/automacro.py --defs HK_CMT_TIME_GAP,"$1" -f config.h 

cd - || exit