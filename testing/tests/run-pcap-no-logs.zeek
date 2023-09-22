# @TEST-DOC: Example of a test that runs Zeek on a pcap and verifies log content
# @TEST-EXEC: zeek -Cr $TRACES/amadey.pcap $PACKAGE %INPUT >output
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: test ! -f amadey.log
# @TEST-EXEC: btest-diff notice.log
# @TEST-EXEC: btest-diff http.log

redef Amadey::enable_detailed_logs = F;