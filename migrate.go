package main

// legacyID is the identifier of 2.0.0. Starting at login is keyed by the
// identifier on Windows (the Run value) and Linux (the autostart entry), so
// after the identifier changed an entry of 2.0.0 would still start the app
// but no longer show as on, nor go away when turned off.
const legacyID = "io.github.zzstar101.gzist-netkeeper"
