signature amadey_sig {
    ip-proto == tcp
    payload /^POST/
    payload /.*\x0d\x0a\x0d\x0aid=[0-9]+&/
    payload /.*&vs=[0-9\.]+&/
    payload /.*&os=[0-9]+&/
    payload /.*&bi=[01]&/
    payload /.*&ar=[01]&/
    payload /.*&pc=/
    payload /.*&un=/
    eval Amadey::amadey_match
}

signature amadey_sig_20231102_1 {
    ip-proto == tcp
    payload /^POST/
    payload /.*\x0d\x0a\x0d\x0ast=s/
    eval Amadey::amadey_match
}