signature amadey_sig {
    ip-proto == tcp
    payload /^POST/
    http-request-body /^id=[0-9]+&/
    http-request-body /.*&vs=[0-9\.]+&/
    http-request-body /.*&os=[0-9]+&/
    http-request-body /.*&bi=[01]&/
    http-request-body /.*&ar=[01]&/
    http-request-body /.*&pc=/
    http-request-body /.*&un=/
    eval Amadey::amadey_match
}