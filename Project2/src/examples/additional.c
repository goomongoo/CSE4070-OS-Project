#include <stdio.h>
#include <syscall.h>
#include <stdlib.h>

int
main (int argc, char **argv)
{
  int fib_arg;
  int max_arg1, max_arg2, max_arg3, max_arg4;

  if (argc != 5)
    {
      printf("Wrong arguments\n");
      return -1;
    }
  
  fib_arg = atoi (argv[1]);
  max_arg1 = fib_arg;
  max_arg2 = atoi (argv[2]);
  max_arg3 = atoi (argv[3]);
  max_arg4 = atoi (argv[4]);
  printf("%d %d\n", fibonacci (fib_arg), max_of_four_int (max_arg1, max_arg2, max_arg3, max_arg4));

  return 0;
}