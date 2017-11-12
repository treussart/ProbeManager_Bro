signature my-first-sig {
    ip-proto == tcp
    dst-port == 443
    dst-ip == 104.154.164.197
    event "Found root!"
}