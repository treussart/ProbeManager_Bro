signature my-first-sig {
    ip-proto == prout
    dst-port == 80p
    paylad /.*root/
    event "Found root!"
}