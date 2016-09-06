#!/usr/bin/env python3

# Copyright 2010 Karl A. Magdsickk
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Site configuration
DEFAULT_EMAIL_DOMAIN = 'gmail.com'
GPG_PATH = 'gpg'

import argparse
import bz2
import json
import hashlib
from math import log, ceil
import os
import random
import sys
import string
import time

ALPHABET_32 = string.digits + 'abcdefghjkmnpqrstvwxyz'
ALPHABET_36 = string.digits + string.ascii_lowercase
ALPHABET_62 = string.ascii_letters + string.digits
ALPHABET_64 = ALPHABET_62 + '_-'
ALPHABET_68 = ALPHABET_64 + '.!?/'
ALPHABET_71 = ALPHABET_64 + '#@$?.!/'
ALPHABET_84 = ALPHABET_62 + string.punctuation

ALL_ALPHABETS = [string.ascii_lowercase, string.ascii_letters, ALPHABET_32, ALPHABET_36, ALPHABET_62, ALPHABET_64, ALPHABET_68,
  ALPHABET_71, ALPHABET_84]
DEFAULT_ALPHABETS = (ALPHABET_62, ALPHABET_71, ALPHABET_71, ALPHABET_71, ALPHABET_84)

def base_dir():
  if os.name == 'posix':
    return os.path.join(os.getenv('HOME'), 'Documents', 'Passwords')
  else:
    return os.path.join(os.getenv('CSIDL_MYDOCUMENTS'), 'Passwords')

def get_bits(n, generator = os.urandom):
  '''Returns a long integer suitable for generating a password with at least n bits of entropy'''
  byte_count = (n+128+7)//8 # get 128 extra bits (rounded up) to reduce bias when taking modulo a non-power of two
  data = generator(byte_count)
  result = 0
  for x in data:
    result = 256 * result + x
  return result

def create_password(bits, alphabet = ALPHABET_71, generator = os.urandom):
  alphabet_size = len(alphabet)
  length = ceil(log(1<<bits) / log(alphabet_size))
  bits = ceil(log(alphabet_size**length) / log(2))
  seed = get_bits(bits, generator)
  if type(alphabet) == str:
    result = ''
    while len(result) < length:
      result += alphabet[seed % alphabet_size]
      seed //= alphabet_size
    return result
  else:
    result = []
    while len(result) < length:
      result.append(alphabet[seed % alphabet_size])
      seed //= alphabet_size
    return ' '.join(result)

def defaults():
  config_path = os.path.join(base_dir(),'config.json')
  if os.path.exists(config_path):
    with open(config_path) as f:
      config = json.load(f)
  else:
    config = {}
  if not 'email' in config:
    config['email'] = '{0}@{1}'.format(os.getenv('USER'), DEFAULT_EMAIL_DOMAIN)
  if not 'user' in config:
    config['user'] = config['email']
  if not 'keys' in config:
    config['keys'] = []
  if 'key' in config:
    config['keys'].append(config['key'])
    del config['key']
  if len(config['keys']) == 0:
    config['keys'].append(config['email'])
  if not 'alphabet' in config:
     config['alphabet'] = None 
  if not 'bits' in config:
    config['bits'] = 96
  if not 'wordlist' in config:
    config['wordlist'] = 'wordlist.txt.bz2'
  # wordlist in the config doesn't make sense as a path relative to cwd specified in the config
  # so a relative path in the config is relative to base_dir()
  if not os.path.isabs(config['wordlist']):
    config['wordlist'] = os.path.join(base_dir(), config['wordlist'])
  return config

def try_load_wordlist(path):
  print('Trying to load ' + path)
  if os.path.exists(path):
    with bz2.BZ2File(path) as wordlist:
      words = [line.decode('utf8').strip() for line in wordlist.readlines()]
      ALL_ALPHABETS.append(words)
      ALL_ALPHABETS.append(words)
      ALL_ALPHABETS.append(words) # Make pass-phrases thee times as likely

def shuffle_alphabets(alphabet_len, loop):
  if alphabet_len != None and alphabet_len > 0:
    if alphabet_len < 100:
      result = [x for x in list(ALL_ALPHABETS) if len(x) == alphabet_len]
    else:
      result = [x for x in list(ALL_ALPHABETS) if len(x) >= alphabet_len]
    if len(result) == 0:
      raise ValueError('No known alphabets of length {0}'.format(alphabet_len))
  elif loop:
    result = list(ALL_ALPHABETS)
  else:
    result = list(DEFAULT_ALPHABETS)
  random.shuffle(result)
  return result

if __name__ == '__main__':
  config = defaults()
  parser = argparse.ArgumentParser(description='Generate a secure password')
  parser.add_argument('domain')
  parser.add_argument('--user', default=config['user'])
  parser.add_argument('--email', default=config['email'])  
  parser.add_argument('--key', action='append', dest='keys', help='GPG key to use to store random passwords', default=config['keys'])  
  parser.add_argument('--alphabet', type=int, help='Number of characters in the alphabet to be used', default=config['alphabet'])  
  parser.add_argument('--wordlist', help='Path to a bzip2 compressed list of words, one word per line', default=config['wordlist'])  
  parser.add_argument('--bits', type=int, help='password securty level, in bits of entropy', default=config['bits'])
  parser.add_argument('--loop', action='store_true', help='loop forever generating passwords until interrupted')
  parser.add_argument('--verbose', action='store_true', help='verbose output')
  parser.add_argument('--note', action='append', dest='notes', help='Note to be added to encrypted data')
  args = parser.parse_args()
  if args.bits < 40:
    parser.print_help()
    print('\n\nPasswords must be at least 64 bits strong\n') # lie about the limit   
    sys.exit(1)
  gpg_file = os.path.join(base_dir(), args.domain + '.gpg')
  try_load_wordlist(args.wordlist)
  alphabets = shuffle_alphabets(args.alphabet, args.loop)
  if args.domain == '':
    if args.loop:
      try:
        while True:
          for alphabet in alphabets:
            print(create_password(args.bits, alphabet))
            time.sleep(0.75)
      except KeyboardInterrupt:
        sys.exit(0)
    parser.print_help()
    print('\nNo domain specified\n')
    sys.exit(1)
  if not os.path.exists(base_dir()):
    raise NotADirectoryError('Missing folder {0}'.format(base_dir()))
  if args.user == None:
    args.user = args.email
  if not args.keys:
    args.keys = [args.email]

  if os.path.exists(gpg_file):
    print('ALREADY HAVE PASSWORD FOR '+args.domain)
    time.sleep(0.1)
  else:
    if args.loop:
      try:
        while True:
          for alphabet in alphabets:
            password = create_password(args.bits, alphabet)
            print(password)
            time.sleep(2)
      except KeyboardInterrupt:
        print('\n')
    else:
      password = create_password(args.bits, alphabets[0])
    if args.user == args.email:
      msg = 'username:  {0}\npassword:  {1}'.format(args.user, password)
    else:
      msg = 'username:  {0}\npassword:  {1}\nemail:  {2}'.format(args.user, password, args.email)
    if args.notes:
      msg += '\nNotes:\n    {0}'.format('\n\n    '.join(args.notes))
    cmd = '{0} -e -r "{1}" --output "{2}"'.format( GPG_PATH, '" -r "'.join(args.keys), gpg_file)
    if args.verbose:
      print(cmd)
    pipe = os.popen(cmd, 'w')
    print(msg, file=pipe) # Use print to get DOS line endings on Windows
    pipe.close()
  cmd = '{0} -d "{1}"'.format(GPG_PATH, gpg_file)
  if args.verbose:
    print(cmd)
  time.sleep(1)
  os.system(cmd)
