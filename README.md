# Osu-Bypass
Circumvents HWID bans on osu without tampering with any windows settings.

Requires special launcher. Not releasing the launcher, but instructions to create: 

1. Game is launched by custom launcher in suspended state (CreateProcess with CREATE_SUSPENDED flag)
2. Osu-Bypass mapped into game (I use a manual map via thread hijacking to load my code).
3. Launcher resumes all threads.

The hooks are installed before the HWID is taken by doing this therefore allowing you to play.
