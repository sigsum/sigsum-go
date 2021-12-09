**Title:** Add verify tooling </br>
**Date:** 2021-12-09 </br>

# Summary
Add a command-line utility that makes log verification easy.

# Description
This issue requires design considerations before getting started.  The goal is
to have a verify tool that checks if some data is signed and transparency logged
without any outbound network connections.  It should be possible to configure
which policy to use for known logs and required witnesses.

(Remark: there is no strict requirement that this has to be in Go.  If anyone
wants to work on tooling in, say, rust or python, that would be welcomed too.)
