/* testapi.c - for libgcrypt
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <gcrypt.h>


int
main( int argc, char **argv )
{
    printf("%s\n", gcry_check_version ( argc > 1 ? argv[1] : NULL ) );


    return 0;
}

