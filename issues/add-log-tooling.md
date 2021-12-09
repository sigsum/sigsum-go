**Title:** Add log tooling </br>
**Date:** 2021-12-09 </br>

# Summary
Add a command-line utility that makes log interactions easy.

# Description
This issue require design considerations before getting started.  Minimum
functionality probably includes the ability to do relevant formatting (like
outputting serialized blobs to be signed or ASCII key-value pairs for
submission), as well as an "upload" command that is smart enough to wait for
inclusion with regards to a cosigned tree head.  It would also be good to think
about how to make uploads convenient if there are multiple submissions.

(Remark: there is no strict requirement that this has to be in Go.  If anyone
wants to work on tooling in, say, rust or python, that would be welcomed too.)
