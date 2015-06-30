
# -*- coding: utf-8 -*-

"""
 Windows PE file META data scanning + Virustotal lookup
 created by password123456
"""

import json
import urllib, urllib2
import magic, re, sys, os
import peutils, pefile, hashlib
import time
import binascii
import string
import commands
import argparse
from pprint import pprint

def convert_char(char):
    if char in string.ascii_letters or \
       char in string.digits or \
       char in string.punctuation or \
       char in string.whitespace:
        return char
    else:
        return r'\x%02x' % ord(char)

def convert_to_printable(s):
    return ''.join([convert_char(c) for c in s])

class PESCAN():
    def  __init__(self):
         # PACKER
         SIGNATURE = 'userdb.txt'
         self.pesignature = os.path.abspath(SIGNATURE)

         # VIRUS TOTAL
         self.vt_apikey = 'b549db5605436e507cca5b2a6afb1c5dfbe251505b6d1d5a336ddc8843771b94'
         self.vt_baseurl = 'https://www.virustotal.com/vtapi/v2/'

    def vt_getReport(self, md5):

        param = {'resource':md5,'apikey':self.vt_apikey}
        url = self.vt_baseurl + "file/report"
        data = urllib.urlencode(param)
        result = urllib2.urlopen(url,data)
        jdata =  json.loads(result.read())
        return jdata

    def pe_packdetect(self, target):
        try:
            pe = pefile.PE(target)
            signatures = peutils.SignatureDatabase(self.pesignature)
            with file(self.pesignature, 'rt') as f:
                sig_data = f.read()
            signatures = peutils.SignatureDatabase(data = sig_data)
            matches = signatures.match(pe, ep_only = True)
            return matches
        except pefile.PEFormatError as err:
            print "Error:", err
            sys.exit()

    def pe_getfiletype(self, target):
        if sys.modules.has_key('magic'):
            try:
                ms = magic.from_file(target)
                return ms
                ms.close()
            except magic.MagicException as err:
                print "Error:", err
                return err

    def get_timestamp(self, target):
        pe = pefile.PE(target, fast_load=True)
        val = pe.FILE_HEADER.TimeDateStamp
        ts = '0x%-8X' % (val)
        try:
            ts += ' [%s UTC]' % time.asctime(time.gmtime(val))
            that_year = time.gmtime(val)[0]
            this_year = time.gmtime(time.time())[0]
            if that_year < 2000 or that_year > this_year:
                ts += " [SUSPICIOUS]"
        except:
            ts += ' [SUSPICIOUS]'
        return ts

    def get_verinfo(self, target):
        """ Determine the version info in a PE file """
        pe = pefile.PE(target)
        ret = []

        if hasattr(pe, 'VS_VERSIONINFO'):
            if hasattr(pe, 'FileInfo'):
                for entry in pe.FileInfo:
                    if hasattr(entry, 'StringTable'):
                        for st_entry in entry.StringTable:
                            for str_entry in st_entry.entries.items():
                                ret.append(convert_to_printable(str_entry[0]) + ': ' + convert_to_printable(str_entry[1]) )
                    elif hasattr(entry, 'Var'):
                        for var_entry in entry.Var:
                            if hasattr(var_entry, 'entry'):
                                ret.append(convert_to_printable(var_entry.entry.keys()[0]) + ': ' + var_entry.entry.values()[0])
        return '\n'.join(ret)


def get_filehash(filename, hash):
  if hash in ('sha256', 'SHA256'):
      m = hashlib.sha256()
  elif hash in ('md5', 'MD5'):
      m = hashlib.md5()
  elif hash in ('sha1', 'SHA1'):
      m = hashlib.sha1()
  else:
      m = hashlib.md5()

  try:
      fh = open(filename, 'rb')
      while True:
          data = fh.read(8192)
          if not data:
              break
          m.update(data)
      return m.hexdigest()
  except IOError as err:
      print "Error:" + err.strerror
      sys.exit(1)


def file_result(it, target):
  packer_detect = pescan.pe_packdetect(target)
  get_filetype = pescan.pe_getfiletype(target)
  get_timestamp = pescan.get_timestamp(target)
  get_versioninfo = pescan.get_verinfo(target)

  print ("=" * 40)
  print "===     PE META SCAN + Virustotal    ==="
  print ("=" * 40)
  print "\n"
  print "[+] File Info: "
  print ("=" * 60)
  print "- File  : ", os.path.abspath(target)
  print "- Size  : %d bytes" % os.path.getsize(target)
  print "- Type  : ", get_filetype
  print "- MD5   : %s" % get_filehash(target, 'md5')
  print "- SHA1  : %s" % get_filehash(target, 'sha1')
  print "- SHA256: %s" % get_filehash(target, 'sha256')
  print "- Packer: ", packer_detect
  print "- Date: ", get_timestamp
  print "\n"
  print "[+] Version Info: "
  print ("=" * 60)
  print get_versioninfo
  print "\n"
  if it['response_code'] == 0:
    print "[-] Result: Not Found in VirusTotal malware DB"
    return 0
  print "[+] VirusTotal: "
  print ("=" * 60)
  if 'AhnLab-V3' in it['scans']:
    print '- V3 Detect:',it['scans']['AhnLab-V3']['result']
  if 'Symantec' in it['scans']:
    print '- Symantec Detect:',it['scans']['Symantec']['result']
  if 'Kaspersky' in it['scans']:
    print '- Kaspersky Detect:',it['scans']['Kaspersky']['result']

  print "- Detect Count: ",it['positives'],'/',it['total']
  print "- VirusTotal Link: ",it['permalink']
  print "- Scanned on:",it['scan_date'],"\n"

def main():
  opt=argparse.ArgumentParser(description="::::: PE MetaScan + Virustotal :::::")
  opt.add_argument("filename", help="ex) c:\windows\malware.exe")
  opt.add_argument("-f", "--file", action="store_true", dest="file", help="ex) python mt_scan.py -f c:\windows\malware.exe")

  if len(sys.argv)<=2:
    opt.print_help()
    sys.exit(1)

  options= opt.parse_args()
  target = os.path.abspath((options.filename))

  if options.file:
      target = os.path.abspath((options.filename))

      checksum = 'md5'
      hash = get_filehash(target, checksum)

      file_result(pescan.vt_getReport(hash), target)
  else:
      opt.print_help()
      sys.exit()

if __name__ == '__main__':
    pescan = PESCAN()
    main()
