import sys

len_11 = []
len_13 = []
lessthan_13 = []

leet = {
  'h': ["|-|"],
  'n': ["]\["],
  'l': ["!_"],
  'e': ["&"],
  'o': ["0"],
  'z': ["2"],
  't': ["7"],
  'y': ["\\'", "`/"],
  's': ["5"],
  'd': ["c!", "{|", "c|"],
  'w': ["\|/"],
  'm': ["|v|", "/\\/\\"],
  'a': ["/-\\", "4"],
  't': ["'|'"],
  'c': ["[", "{"],
  'v': ["`'"],
  'k': ["|("],
  'b': ["|o"],
  'p': ["|*"],
}

def leetify(word, prev_replaced=None):
  permutations = []
  for key, val in leet.items():
    if key in word and key != prev_replaced:
      for t in val:
        leet_word = word.replace(key, t, 1)
        if(len(leet_word) < 13):
          permutations.append(leet_word)
          if prev_replaced:
            return permutations
          else:
            permutations = permutations + (leetify(leet_word, key))
  return permutations

def gen_dictionaries():
  with open('./standard.txt', 'w') as out:
    out.write('\n'.join(lessthan_13))
  with open('./combined.txt', 'w') as out:
    for word in len_11:
      for word1 in len_13:
          out.write(word+word1 + '\n')
  with open('./leet.txt', 'w') as out:
    for word in lessthan_13:
      x = leetify(word)
      out.write('\n'.join(x))

def gen_permutations():
  with open('./output.txt', 'w') as out:
    # joined
    for word in len_11:
      for word1 in len_13:
          out.write(word+word1 + '\n')
    # leet
    for word in lessthan_13:
      for key, val in leet.items():
        if key in word:
          for t in val:
            leet_word = word.replace(key, t, 1);
            if(len(leet_word) < 13):
              out.write(leet_word + '\n');

def find_words(words):
  global len_11;
  global len_13;
  global lessthan_13;
  for word in words:
    if len(word) == 11:
      len_11.append(word)
    elif len(word) <= 12:
      lessthan_13.append(word)
    elif len(word) == 13:
      len_13.append(word)

def main():
  lines = []
  with open(sys.argv[1], 'r') as dic:
    lines = dic.read().splitlines()
    find_words(lines)
    # gen_leet()
    # gen_permutations()
    gen_dictionaries()


if __name__  == '__main__':
  main()
