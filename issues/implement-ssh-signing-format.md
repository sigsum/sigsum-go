**Title:** Implement SSH signing format</br>
**Date:** 2021-12-20 </br>

# Summary
Implement SSH signing format for statements and tree heads.

# Description
Sigsum decided to adopt the SSH signing format for both statements and tree
heads, see
	[proposal](https://git.sigsum.org/sigsum/tree/doc/proposals/2021-11-ssh-signature-format.md).
Implementation is relatively straight-forward: update `ToBinary()` for
`Statement` and `TreeHead` and add relevant unit tests.
