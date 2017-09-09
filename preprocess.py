import sys

len_11 = []
len_13 = []
lessthan_13 = []

def gen_permutations():
  with open('./output.txt', 'w') as out:
    out.write('\n'.join(lessthan_13))
    for word in len_11:
      for word1 in len_13:
          out.write(word+word1 + '\n')

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
    gen_permutations()


if __name__  == '__main__':
  main()
