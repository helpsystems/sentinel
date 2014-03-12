
rem Sentinel make for Borland C 32 bits (BCC)

bcc32 -Iinclude -Llib sentinel.cpp
bcc32 -Iinclude -Llib protector.cpp
bcc32 -Iinclude -Llib -WD sentinel.c
