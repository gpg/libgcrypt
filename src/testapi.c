/* testapi.c - for libgcrypt
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <gcrypt.h>


int
main( int argc, char **argv )
{
    GCRY_MD_HD md;


    md = gcry_md_open( GCRY_MD_RMD160, 0 );




    return 0;
}

