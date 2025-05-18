# Dumper

An automatic dumper for a certain gacha game protected by (poorly implemented) ACE.
Might work for other games as well.

It hooks `NtQuerySystemInformation` to fake Code Integrity being enabled,
so it can be run on a system with Test Signing enabled (which is the case for Github Runners).

It also hooks `GetSystemTimeAsFileTime` which is called by CRT when initializing security cookies.
If the return address is in the image, it is dumped.
