#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>

int
main (int argc, char **argv)
{
  struct rusage buf;

  if (argc > 1)
    {
      system (argv[1]);

      if (getrusage (RUSAGE_CHILDREN, &buf ))
        {
          perror ("getrusage");
          return 1;
        }
    }
  else
    {
      if (getrusage (RUSAGE_SELF, &buf ))
        {
          perror ("getrusage");
          return 1;
        }
    }

  printf ("ru_utime   = %ld.%06ld\n",
          buf.ru_utime.tv_sec, buf.ru_utime.tv_usec); 
  printf ("ru_stime   = %ld.%06ld\n",
          buf.ru_stime.tv_sec, buf.ru_stime.tv_usec);
  printf ("ru_maxrss  = %ld\n", buf.ru_maxrss   );
  printf ("ru_ixrss   = %ld\n", buf.ru_ixrss    );
  printf ("ru_idrss   = %ld\n", buf.ru_idrss    );
  printf ("ru_isrss   = %ld\n", buf.ru_isrss    );
  printf ("ru_minflt  = %ld\n", buf.ru_minflt   );
  printf ("ru_majflt  = %ld\n", buf.ru_majflt   );
  printf ("ru_nswap   = %ld\n", buf.ru_nswap    );
  printf ("ru_inblock = %ld\n", buf.ru_inblock  );
  printf ("ru_oublock = %ld\n", buf.ru_oublock  );
  printf ("ru_msgsnd  = %ld\n", buf.ru_msgsnd   );
  printf ("ru_msgrcv  = %ld\n", buf.ru_msgrcv   );
  printf ("ru_nsignals= %ld\n", buf.ru_nsignals );
  printf ("ru_nvcsw   = %ld\n", buf.ru_nvcsw    );
  printf ("ru_nivcsw  = %ld\n", buf.ru_nivcsw   );

  return 0;
}
