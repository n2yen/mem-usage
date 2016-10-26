#!/usr/bin/python
#
# mem-usage.py - detailed process memory statistics.
#
# Based on mem_usage perl script in public domain by Andy Wingo <wingo@pobox.com>
#
# 2015 Nelson Yen, Simplified BSD License
#

import argparse
import re

# CONSTANTS
INODE_NONE  = 0

class ProcMaps:
  # Supported 'keys'
  all_keys = ('writeable_code',
              'data',
              'rodata',
              'rxdata',
              'unreadable',
              'anon_unknown',    
              'anon_shared',
              'mapped_exe',
              'mapped_wrexe',
              'mapped_rodata',
              'mapped_rwdata',
              'mapped_unreadable',
              'mapped_unknown',
              'mapped_shared')

  def __init__(self):
    self.maps = {}
    self.keys_anon = []
    self.keys_mapped = []
    self.DEBUG=False

    for key in self.all_keys :
      self.maps[key] = 0

    for key in self.all_keys:
      if key.find('mapped') == 0 :
        self.keys_mapped.append(key)
      else :
        self.keys_anon.append(key)

    if self.DEBUG :
      print [elem for elem in self.keys_mapped]
      print [elem for elem in self.keys_anon]

  def add_count(self, key, count):
    assert(key in self.all_keys)
    self.maps[key] += count

  def total_anon(self):
    total = 0
    for key in self.keys_anon :
      if key != 'anon_shared' :
        total += self.maps[key]
    return total

  def total_mapped(self):
    total = 0
    for key in self.keys_mapped:
      if key != 'mapped_shared' :
        total += self.maps[key]
    return total

  def total(self):
    total = 0
    for key in self.maps:
      if (key != 'mapped_shared') and (key != 'anon_shared'): 
        total += self.maps[key]
    return total

  def print_stats(self):
    print "Mapped memory:"
    print "  Executable                r-x {0:>8} kB".format(self.maps['mapped_exe'])
    print "  Write/Exec (jump tables)  rwx {0:>8} kB".format(self.maps['mapped_wrexe'])
    print "  Data                      rw- {0:>8} kB".format(self.maps['mapped_rwdata'])
    print "  RO data                   r-- {0:>8} kB".format(self.maps['mapped_rodata'])
    print "  Unreadable                --- {0:>8} kB".format(self.maps['mapped_unreadable'])
    print "  Unknown                       {0:>8} kB".format(self.maps['mapped_unknown'])
    print
    print "  Shared                        {0:>8} kB".format(self.maps['mapped_shared'])
    print "  Total                         {0:>8} kB".format(self.total_mapped())
    print
    print "Anonymous memory (not file backed):"
    print "  Executable                r-x {0:>8} kB".format(self.maps['rxdata'])
    print "  Writable code (stack)     rwx {0:>8} kB".format(self.maps['writeable_code'])
    print "  Data (malloc, mmap)       rw- {0:>8} kB".format(self.maps['data'])
    print "  RO data                   r-- {0:>8} kB".format(self.maps['rodata'])
    print "  Unreadable                --- {0:>8} kB".format(self.maps['unreadable'])
    print "  Unknown                       {0:>8} kB".format(self.maps['anon_unknown'])
    print
    print "  Shared                        {0:>8} kB".format(self.maps['anon_shared'])
    print "  Total                         {0:>8} kB".format(self.total_anon())
    print 
    print "All:"
    print "  Shared                        {0:>8} kB".format(self.maps['mapped_shared']+self.maps['anon_shared'])
    print "  Total                         {0:>8} kB".format(self.total())
    print 

# End class ProcMaps


def parse_line(line, proc_maps):
  match = re.search(r'^(\w+)-(\w+) (....) (\w+) (\S+) (\d+) *(.*)$', line);
  if match:
    start_addr = int(match.group(1).strip(), 16)
    end_addr   = int(match.group(2).strip(), 16)
    perms      = match.group(3).strip()
    offset     = match.group(4).strip()
    dev        = match.group(5).strip()
    inode      = int(match.group(6).strip())
    pathname   = match.group(7).strip()

    # Size in kB
    vma_size   = (end_addr - start_addr) / 1024

    # Anonymous, not file mapped
    if INODE_NONE == inode:
      if perms.find('rwx') >= 0:
        proc_maps.add_count('writeable_code', vma_size)
        pass
      elif perms.find('rw-') >= 0:
        proc_maps.add_count('data', vma_size)
      elif perms.find('r-x') >= 0:
        proc_maps.add_count('rxdata', vma_size)
      elif perms.find('r--') >= 0:
        proc_maps.add_count('rodata', vma_size)
      elif perms.find('---') >= 0:
        proc_maps.add_count('unreadable', vma_size)
      else :
        proc_maps.add_count('anon_unknown', vma_size)
        print 'anon_unknown:', line

      if perms.find('s') >= 0:
        proc_maps.add_count('anon_shared', vma_size)

    else :
      if perms.find('r-x') >= 0:
        proc_maps.add_count('mapped_exe', vma_size)
      elif perms.find('rwx') >= 0:
        proc_maps.add_count('mapped_wrexe', vma_size)
      elif perms.find('rw-') >= 0:
        proc_maps.add_count('mapped_rwdata', vma_size)
      elif perms.find('r--') >= 0:
        proc_maps.add_count('mapped_rodata', vma_size)
      elif perms.find('---') >= 0:
        proc_maps.add_count('mapped_unreadable', vma_size)
      else :
        proc_maps.add_count('mapped_unknown', vma_size)
        print 'mapped_unknown', line

      if perms.find('s') >= 0:
        proc_maps.add_count('mapped_shared', vma_size)

  else :
    print 'reject: ', line, match.group()


def parse_maps_from_pid(pid, proc_maps):
  fio = open('/proc/'+pid+'/maps', 'r')
  for line in fio:
    parse_line(line, proc_maps)


def parse_mapsfile(filename, proc_maps):
  fio = open(filename, 'r')
  for line in fio:
    parse_line(line, proc_maps)


def main():
  parser = argparse.ArgumentParser()
  # Add mutually exclusive group
  group = parser.add_mutually_exclusive_group(required=True)
  group.add_argument("-p", "--pid", help="pid")
  group.add_argument("-m", "--maps", help="maps file")

  # Get args
  args      = parser.parse_args()
  pid       = args.pid
  mapsfile  = args.maps

  # Use ProcMaps to record stats
  proc_maps_info = ProcMaps()

  if pid:
    parse_maps_from_pid(pid, proc_maps_info)
  elif mapsfile:
    parse_mapsfile(mapsfile, proc_maps_info)
  else :
    print 'bad params'

  proc_maps_info.print_stats()

if __name__ == '__main__':
  main()

