**Title:** Add library </br>
**Date:** 2021-12-09 </br>
**Status:** ongoing in branch rgdd/pkg </br>

# Summary
Refactor pkg/types from sigsum-log-go into a stand-alone Go library.

# Description
The pkg/types part of sigsum-log-go needs refactoring after the ssh signing
format proposal is done.  We also want to make the parts that are generally
useful into a stand-alone library without any non-standard dependencies.
