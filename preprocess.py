import sys

def gen_permutations(words):
  with open('./output.txt', 'w') as out:
    for word in words:
      for j in range(len(words)):
        if(word != words[j]):
          out.write(word+words[j] + '\n')


def main():
  lines = []
  with open(sys.argv[1], 'r') as dic:
    lines = dic.read().splitlines()
    gen_permutations(lines)


if __name__  == '__main__':
  main()
