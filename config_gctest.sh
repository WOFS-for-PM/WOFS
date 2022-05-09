#!/usr/bin/sh

WORK_DIR=$(cd "$( dirname "$0" )" && pwd)

cd "$WORK_DIR" || exit

../tools/AutoMacro/automacro.py --defs ENABLE_GC_TEST_MODE,"" -f config.h 
../tools/AutoMacro/automacro.py --defs EMU_PMEM_SIZE_GB,"$1" -f config.h 

cd - || exit