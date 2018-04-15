@load frameworks/intel/seen
@load base/frameworks/intel/files.bro

redef Intel::read_files += {
  fmt("%s/intel-1.dat", @DIR)
};
