/* sexp.c  -  S-Expression handling
 *	Copyright (C) 1999, 2000 Free Software Foundation, Inc.
 *
 * This file is part of GnuPG.
 *
 * GnuPG is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GnuPG is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */


#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <ctype.h>
#include <assert.h>

#define GCRYPT_NO_MPI_MACROS 1
#include "g10lib.h"
#include "memory.h"

typedef struct gcry_sexp *NODE;
typedef unsigned short DATALEN;

struct gcry_sexp {
    byte d[1];
};

#define ST_STOP  0  /* datalen does not follow this tag */
#define ST_DATA  1
#define ST_HINT  2
#define ST_OPEN  3
#define ST_CLOSE 4  /* datalen does not follow this tag */

#if 0
static void
dump_mpi( GCRY_MPI a )
{
    char buffer[1000];
    size_t n = 1000;

    if( !a )
	fputs("[no MPI]", stderr );
    else if( gcry_mpi_print( GCRYMPI_FMT_HEX, buffer, &n, a ) )
	fputs("[MPI too large to print]", stderr );
    else
	fputs( buffer, stderr );
}
#endif

static void
dump_string( FILE *fp, const byte *p, size_t n, int delim )
{
    for( ; n; n--, p++ )
	if( (*p & 0x80) || iscntrl( *p ) || *p == delim ) {
	    putc('\\', fp);
	    if( *p == '\n' )
		putc('n', fp);
	    else if( *p == '\r' )
		putc('r', fp);
	    else if( *p == '\f' )
		putc('f', fp);
	    else if( *p == '\v' )
		putc('v', fp);
	    else if( *p == '\b' )
		putc('b', fp);
	    else if( !*p )
		putc('0', fp);
	    else
		fprintf(fp, "x%02x", *p );
	}
	else
	    putc(*p, fp);
}


void
gcry_sexp_dump( const GCRY_SEXP a )
{
    const byte *p;
    DATALEN n;
    int indent = 0;
    int type;

    if ( !a ) {
	fputs ( "[nil]\n", stderr );
	return;
    }

    p = a->d;
    while ( (type = *p) != ST_STOP ) {
	if ( type == ST_CLOSE ) {
	    n = 0;
	    p++;
	}
	else {
	    memcpy ( &n, ++p, sizeof n );
	    p += sizeof n;
	}
	switch ( type ) {
	  case ST_OPEN:
	    fprintf ( stderr, "%*s[open len=%u]\n", 2*indent, "", n );
	    indent++;
	    break;
	  case ST_CLOSE:
	    if( indent )
		indent--;
	    fprintf ( stderr, "%*s[close]\n", 2*indent, "" );
	    break;
	  case ST_DATA:
	    fprintf ( stderr, "%*s[data=\"", 2*indent, "" );
	    dump_string ( stderr, p, n, '\"' );
	    fputs ( "\"]\n", stderr );
	    p += n;
	    break;
	  default:
	    fprintf ( stderr, "%*s[unknown tag %d]\n", 2*indent, "", type );
	    p += n;
	    break;
	}
    }
}

/****************
 * Pass list thru expcept when it is an empty list in taht case
 * return NULL and release the passed list.
 */
static GCRY_SEXP
normalize ( GCRY_SEXP list )
{
    char *p;
    if ( !list )
	return NULL;
    p = list->d;
    if ( *p == ST_STOP ) {
	/* this is "" */
	gcry_sexp_release ( list );
	return NULL;
    }
    if( *p == ST_OPEN && p[1+sizeof(DATALEN)] == ST_CLOSE ) {
	/* this is "()" */
	gcry_sexp_release ( list );
	return NULL;
    }

    return list;
}

/****************
 * Release resource of the given SEXP object.
 */
void
gcry_sexp_release( GCRY_SEXP sexp )
{
    g10_free ( sexp );
}


/****************
 * Make a pair from lists a and b, don't use a or b later on.
 * Special behaviour:  If one is a single element list we put the
 * element straight into the new pair.
 */
GCRY_SEXP
gcry_sexp_cons( const GCRY_SEXP a, const GCRY_SEXP b )
{
    /* NYI: Implementation should be quite easy with our new data representation */
    BUG ();
    return NULL;
}


/****************
 * Make a list from all items in the array the end of the array is marked
 * with a NULL. 								      y a NULL
 */
GCRY_SEXP
gcry_sexp_alist( const GCRY_SEXP *array )
{
    /* NYI: Implementaion should be quite easy with our new data representation */
    BUG ();
    return NULL;
}

/****************
 * Make a list from all items, the end of list is indicated by a NULL
 */
GCRY_SEXP
gcry_sexp_vlist( const GCRY_SEXP a, ... )
{
    /* NYI: Implementaion should be quite easy with our new data representation */
    BUG ();
    return NULL;
}


/****************
 * Append n to the list a
 * Returns: a new ist (which maybe a)
 */
GCRY_SEXP
gcry_sexp_append( const GCRY_SEXP a, const GCRY_SEXP n )
{
    /* NYI: Implementaion should be quite easy with our new data representation */
    BUG ();
    return NULL;
}

GCRY_SEXP
gcry_sexp_prepend( const GCRY_SEXP a, const GCRY_SEXP n )
{
    /* NYI: Implementaion should be quite easy with our new data representation */
    BUG ();
    return NULL;
}



/****************
 * Locate token in a list. The token must be the car of a sublist.
 * Returns: A new list with this sublist or NULL if not found.
 */
GCRY_SEXP
gcry_sexp_find_token( const GCRY_SEXP list, const char *tok, size_t toklen )
{
    const byte *p;
    DATALEN n;
    int type;

    if ( !list )
	return NULL;

    if( !toklen )
	toklen = strlen(tok);
    p = list->d;
    while ( (type=*p) != ST_STOP ) {
	const byte *head = p;
	DATALEN headlen;

	p++;
	if ( type == ST_CLOSE )
	    n = 0;
	else {
	    memcpy ( &n, p, sizeof n );
	    p += sizeof n;
	}
	headlen = n + 1 + sizeof(DATALEN);
	if ( type == ST_OPEN ) {
	    int type2 = *p;
	    const byte *pp = p+1;
	    DATALEN nn;

	    memcpy ( &nn, pp, sizeof nn );
	    pp += sizeof nn;
	    if ( type2 == ST_DATA )  {
		if ( nn == toklen && !memcmp( pp, tok, toklen ) ) { /* found it */
		    GCRY_SEXP sexp = g10_xmalloc ( sizeof *sexp + headlen + 1 );
		    memcpy ( sexp->d, head, headlen );
		    sexp->d[headlen] = ST_CLOSE;
		    sexp->d[headlen+1] = ST_STOP;
		    return normalize ( sexp );
		}
	    }
	    p = pp + nn;
	}
	else {
	    p += n;
	}
    }
    return NULL;
}

/****************
 * return the length of the given list
 */
int
gcry_sexp_length( const GCRY_SEXP list )
{
    const byte *p;
    DATALEN n;
    int type;
    int length = 0;

    if ( !list )
	return 0;

    p = list->d;
    while ( (type=*p) != ST_STOP ) {
	p++;
	if ( type == ST_CLOSE )
	    n = 0;
	else {
	    memcpy ( &n, p, sizeof n );
	    p += sizeof n;
	}
	p += n;
	length++;
    }
    return length;
}



/****************
 * Extract the CAR of the given list
 */
GCRY_SEXP
gcry_sexp_car( const GCRY_SEXP list )
{
    const byte *p;
    DATALEN n;
    GCRY_SEXP newlist;
    byte *d;

    if ( !list || list->d[0] != ST_OPEN )
	return NULL;
    p = list->d;
    memcpy ( &n, ++p, sizeof n ); p += sizeof n;

    newlist = g10_xmalloc ( sizeof *newlist + n + 1 );
    d = newlist->d;
    memcpy ( d, p, n ); d += n;
    if ( *p == ST_OPEN )
	*d++ = ST_CLOSE;
    *d++ = ST_STOP;
    return normalize (newlist);
}

/****************
 * Get data from the car.  The returned value is valid as long as the list
 * is not modified.
 */
const char *
gcry_sexp_car_data( const GCRY_SEXP list, size_t *datalen )
{
    const byte *p;
    DATALEN n;

    if ( !list ) {
	*datalen = 0;
	return NULL;
    }
    p = list->d;

    if ( *p == ST_OPEN ) {
	p += 1 + sizeof n;
    }

    if ( *p == ST_DATA ) {
	memcpy ( &n, ++p, sizeof n );
	*datalen = n;
	return p + sizeof n;
    }

    *datalen = 0;
    return NULL;
}

/****************
 * Get a MPI from the car
 */
GCRY_MPI
gcry_sexp_car_mpi( GCRY_SEXP list, int mpifmt )
{
    const byte *p;
    DATALEN n;

    if ( !list )
	return NULL;
    if ( !mpifmt )
	mpifmt = GCRYMPI_FMT_STD;

    p = list->d;
    if ( *p == ST_OPEN ) {
	p += 1 + sizeof n;
    }

    if ( *p == ST_DATA ) {
	MPI a;
	size_t nbytes;

	memcpy ( &n, ++p, sizeof n );
	p += sizeof n;
	nbytes = n;
	if( !gcry_mpi_scan( &a, mpifmt, p, &nbytes ) )
	    return a;
    }

    return NULL;
}

GCRY_SEXP
gcry_sexp_cadr ( const GCRY_SEXP list )
{
    GCRY_SEXP a, b;

    a = gcry_sexp_cdr ( list );
    b = gcry_sexp_car ( a );
    gcry_sexp_release ( a );
    return b;
}


/****************
 * Get the CDR
 */
GCRY_SEXP
gcry_sexp_cdr( const GCRY_SEXP list )
{
    const byte *head, *p;
    DATALEN n;
    GCRY_SEXP newlist;
    byte *d;

    if ( !list || list->d[0] != ST_OPEN )
	return NULL;
    p = list->d;

    p++;
    p += sizeof n; /* don't care about the length of the list */

    if ( *p == ST_CLOSE )
	return NULL; /* cdr of an empty list is an empty list */

    /* skip over the first element of the list */
    if ( *p == ST_STOP )
	BUG (); /* oops */
    memcpy ( &n, ++p, sizeof n ); p += sizeof n;
    p += n;

    /* save position and find the end of the list */
    head = p;
    while ( *p != ST_CLOSE ) {
	if ( *p == ST_STOP )
	    BUG (); /* oops */
	memcpy ( &n, ++p, sizeof n ); p += sizeof n;
	p += n;
    }

    /* allocate enough space for the open, close and stop tag */
    newlist = g10_xmalloc ( sizeof *newlist + 3 + sizeof(DATALEN)
			    + ( p - head ) - 1 );
    d = newlist->d;
    /* and create the new list */
    *d++ = ST_OPEN;
    n = ( p - head );
    memcpy ( d, &n, sizeof n ); d += sizeof n;
    memcpy ( d, head, n ); d += n;
    *d++ = ST_CLOSE;
    *d++ = ST_STOP;
    return normalize (newlist);
}

/****************
 * Get data from the cdr assuming this is a pair
 */
const char *
gcry_sexp_cdr_data( GCRY_SEXP list, size_t *datalen )
{
    const byte *p;
    DATALEN n;

    if ( !list ) {
	*datalen = 0;
	return NULL;
    }

    p = list->d;
    if ( *p == ST_OPEN ) {
	memcpy ( &n, ++p, sizeof n );
	p += sizeof n;
	/* skip over the first element */
	if ( *p == ST_STOP )
	    BUG (); /* at least we expect an list end here */
	memcpy ( &n, ++p, sizeof n );
	p += sizeof n;
	p += n; /* actually skip over the car */

	/* we can only return stuff if the element is of type data */
	if ( *p == ST_DATA ) {
	    memcpy ( &n, ++p, sizeof n );
	    p += sizeof n;
	    *datalen = n;
	    return p;
	}
    }
    *datalen = 0;
    return NULL;
}


/****************
 * cdr the mpi from the list or NULL if there is no MPI.
 * This function tries to convert plain data to an MPI.
 * Actually this funtion returns only the second item of the list
 * and ignores any further arguments.
 */
GCRY_MPI
gcry_sexp_cdr_mpi( GCRY_SEXP list, int mpifmt )
{
    const byte *p;
    DATALEN n;

    if ( !list )
	return NULL;

    if ( !mpifmt )
	mpifmt = GCRYMPI_FMT_STD;

    p = list->d;
    if ( *p == ST_OPEN ) {
	memcpy ( &n, ++p, sizeof n );
	p += sizeof n;
	/* skip over the first element */
	if ( *p == ST_STOP )
	    BUG (); /* at least we expect an list end here */
	memcpy ( &n, ++p, sizeof n );
	p += sizeof n;
	p += n; /* actually skip over the car */

	/* we can only return stuff if the element is of type data */
	if ( *p == ST_DATA ) {
	    MPI a;
	    size_t nbytes;

	    memcpy ( &n, ++p, sizeof n );
	    p += sizeof n;
	    nbytes =n;
	    if( !gcry_mpi_scan( &a, mpifmt, p, &nbytes ) )
		return a;
	}
    }
    return NULL;
}





static int
hextobyte( const byte *s )
{
    int c=0;

    if( *s >= '0' && *s <= '9' )
	c = 16 * (*s - '0');
    else if( *s >= 'A' && *s <= 'F' )
	c = 16 * (10 + *s - 'A');
    else if( *s >= 'a' && *s <= 'f' ) {
	c = 16 * (10 + *s - 'a');
    }
    s++;
    if( *s >= '0' && *s <= '9' )
	c += *s - '0';
    else if( *s >= 'A' && *s <= 'F' )
	c += 10 + *s - 'A';
    else if( *s >= 'a' && *s <= 'f' ) {
	c += 10 + *s - 'a';
    }
    return c;
}

struct make_space_ctx {
    GCRY_SEXP sexp;
    size_t allocated;
    byte *pos;
    byte **fixups;
    int  max_fixups;
    int  n_fixups;
};

static void
make_space ( struct make_space_ctx *c, size_t n )
{
    size_t used = c->pos - c->sexp->d;

    if ( used + n +sizeof(DATALEN) + 1 >= c->allocated ) {
	GCRY_SEXP newsexp;
	byte *newhead;
	int i;

	c->allocated += 2*(n+sizeof(DATALEN)+1);
	newsexp = g10_xrealloc ( c->sexp, sizeof *newsexp + c->allocated - 1 );
	newhead = newsexp->d;
	c->pos = newhead + used;
	for ( i=0; i < c->n_fixups; i++ )
	    c->fixups[i] = newhead + (c->fixups[i] - c->sexp->d );
	c->sexp = newsexp;
    }
}


/****************
 * Scan the provided buffer and return the S expression in our internal
 * format.  Returns a newly allocated expression.  If erroff is not NULL and
 * a parsing error has occured, the offset into buffer will be returned.
 * If ARG_PTR is not NULL, the function supports some printf like
 * expressions.
 *  These are:
 *	%m - MPI
 *	%s - string (no autoswitch to secure allocation)
 *	%d - integer stored as string (no autoswitch to secure allocation)
 *  all other format elements are currently not defined and return an error.
 *  this includes the "%%" sequence becauce the percent sign is not an
 *  allowed character.
 * FIXME: We should find a way to store the secure-MPIS not in the string
 * but as reference to somewhere - this can help us to save huge amounts
 * of secure memory.  The problem is, taht if only one element is secure, all
 * other elements are automagicaly copied to secure meory too, so the most
 * common operation gcry_sexp_cdr_mpi() will always return a secure MPI
 * regardless whether it is needed or not.
 */
static int
sexp_sscan( GCRY_SEXP *retsexp, size_t *erroff ,
	    const char *buffer, size_t length, va_list arg_ptr )
{
    static const char tokenchars[] = "abcdefghijklmnopqrstuvwxyz"
				     "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
				     "0123456789-./_:*+=";
    const char *p;
    size_t n;
    const char *digptr=NULL;
    const char *quoted=NULL;
    const char *tokenp=NULL;
    const char *hexfmt=NULL;
    const char *base64=NULL;
    const char *disphint=NULL;
    const char *percent=NULL;
    int hexcount=0;
    int quoted_esc=0;
    int datalen=0;
    size_t dummy_erroff;

    struct make_space_ctx c;

    if( !erroff )
	erroff = &dummy_erroff;

    /* FIXME: replace all the returns by a jump to the leave label
     * and invent better error codes. Make sure that everything is cleaned up*/
  #define MAKE_SPACE(n)  do { make_space ( &c, (n) ); } while (0)
  #define STORE_LEN(p,n) do {						   \
			    DATALEN ashort = (n);			   \
			    memcpy ( (p), &ashort, sizeof(ashort) );	   \
			    (p) += sizeof (ashort);			   \
			} while (0)

    /* We assume that the internal representation takes less memory
     * than the provided one.  However, we add space for one extra datalen
     * so that the code which does the ST_CLOSE can use MAKE_SPACE */
    c.allocated = length + sizeof(DATALEN);
    c.sexp = g10_xmalloc ( sizeof *c.sexp + c.allocated - 1 );
    c.pos = c.sexp->d;
    c.fixups = NULL;
    c.max_fixups = 0;
    c.n_fixups = 0;

    for(p=buffer,n=length; n; p++, n-- ) {
	if( tokenp && !hexfmt ) {
	    if( strchr( tokenchars, *p ) )
		continue;
	    datalen = p - tokenp;
	    MAKE_SPACE ( datalen );
	    *c.pos++ = ST_DATA;
	    STORE_LEN ( c.pos, datalen );
	    memcpy ( c.pos, tokenp, datalen );
	    c.pos += datalen;
	    tokenp = NULL;
	}
	if( quoted ) {
	    if( quoted_esc ) {
		switch( *p ) {
		  case 'b': case 't': case 'v': case 'n': case 'f':
		  case 'r': case '"': case '\'': case '\\':
		    quoted_esc = 0;
		    break;
		  case '0': case '1': case '2': case '3': case '4':
		  case '5': case '6': case '7':
		    if( !(n > 2 && p[1] >= '0' && p[1] <= '7'
				&& p[2] >= '0' && p[2] <= '7') ) {
			*erroff = p - buffer;
			return -6;   /* invalid octal value */
		    }
		    p += 2; n -= 2;
		    quoted_esc = 0;
		    break;
		  case 'x':
		    if( !(n > 2 && isxdigit(p[1]) && isxdigit(p[2]) ) ) {
			*erroff = p - buffer;
			return -6;   /* invalid hex value */
		    }
		    p += 2; n -= 2;
		    quoted_esc = 0;
		    break;
		  case '\r':  /* ignore CR[,LF] */
		    if( n && p[1] == '\n' ) {
			p++; n--;
		    }
		    quoted_esc = 0;
		    break;
		  case '\n':  /* ignore LF[,CR] */
		    if( n && p[1] == '\r' ) {
			p++; n--;
		    }
		    quoted_esc = 0;
		    break;
		  default:
		    *erroff = p - buffer;
		    return -6;	 /* invalid quoted string escape */
		}
	    }
	    else if( *p == '\\' )
		quoted_esc = 1;
	    else if( *p == '\"' ) {
		/* fixme: add item */
		quoted = NULL;
	    }
	}
	else if( hexfmt ) {
	    if( isxdigit( *p ) )
		hexcount++;
	    else if( *p == '#' ) {
		if( (hexcount & 1) ) {
		    *erroff = p - buffer;
		    return -12;  /* odd number of hex digits */
		}

		datalen = hexcount/2;
		MAKE_SPACE (datalen);
		*c.pos++ = ST_DATA;
		STORE_LEN (c.pos, datalen);
		for( hexfmt++; hexfmt < p; hexfmt++ ) {
		    if( isspace( *hexfmt ) )
			continue;
		    *c.pos++ = hextobyte( hexfmt );
		    hexfmt++;
		}
		hexfmt = NULL;
	    }
	    else if( !isspace( *p ) ) {
		*erroff = p - buffer;
		return -11;  /* invalid hex character */
	    }
	}
	else if( base64 ) {
	    if( *p == '|' )
	       base64 = NULL;
	}
	else if( digptr ) {
	    if( isdigit(*p) )
		;
	    else if( *p == ':' ) {
		datalen = atoi( digptr ); /* fixme: check for overflow */
		digptr = NULL;
		if( datalen > n-1 ) {
		    *erroff = p - buffer;
		    return -2; /* buffer too short */
		}
		/* make a new list entry */
		MAKE_SPACE (datalen);
		*c.pos++ = ST_DATA;
		STORE_LEN (c.pos, datalen);
		memcpy (c.pos, p+1, datalen );
		c.pos += datalen;
		n -= datalen;
		p += datalen;
	    }
	    else if( *p == '\"' ) {
		digptr = NULL; /* we ignore the optional length */
		quoted = p;
		quoted_esc = 0;
	    }
	    else if( *p == '#' ) {
		digptr = NULL; /* we ignore the optional length */
		hexfmt = p;
		hexcount = 0;
	    }
	    else if( *p == '|' ) {
		digptr = NULL; /* we ignore the optional length */
		base64 = p;
	    }
	    else {
		*erroff = p - buffer;
		return -1;
	    }
	}
	else if ( percent ) {
	    if ( *p == 'm' ) { /* insert an MPI */
		GCRY_MPI m = va_arg (arg_ptr, GCRY_MPI);
		size_t nm;

		if ( gcry_mpi_print( GCRYMPI_FMT_STD, NULL, &nm, m ) )
		    BUG ();

		MAKE_SPACE (nm);
		if ( !g10_is_secure ( c.sexp->d )
		     &&  gcry_mpi_get_flag ( m, GCRYMPI_FLAG_SECURE ) ) {
		    /* we have to switch to secure allocation */
		    GCRY_SEXP newsexp;
		    byte *newhead;

		    newsexp = g10_xmalloc_secure ( sizeof *newsexp
						   + c.allocated - 1 );
		    newhead = newsexp->d;
		    memcpy ( newhead, c.sexp->d, (c.pos - c.sexp->d) );
		    c.pos = newhead + ( c.pos - c.sexp->d );
		    g10_free ( c.sexp );
		    c.sexp = newsexp;
		}

		*c.pos++ = ST_DATA;
		STORE_LEN (c.pos, nm);
		if ( gcry_mpi_print( GCRYMPI_FMT_STD, c.pos, &nm, m ) )
		    BUG ();
		c.pos += nm;
	    }
	    else if ( *p == 's' ) { /* insert an string */
		const char *astr = va_arg (arg_ptr, const char *);
		size_t alen = strlen ( astr );

		MAKE_SPACE (alen);
		*c.pos++ = ST_DATA;
		STORE_LEN (c.pos, alen);
		memcpy ( c.pos, astr, alen );
	    }
	    else if ( *p == 'd' ) { /* insert an integer as string */
		int aint = va_arg (arg_ptr, int);
		size_t alen;
		char buf[20];

		sprintf ( buf, "%d", aint );
		alen = strlen ( buf );
		MAKE_SPACE (alen);
		*c.pos++ = ST_DATA;
		STORE_LEN (c.pos, alen);
		memcpy ( c.pos, buf, alen );
		c.pos += alen;
	    }
	    else {
		*erroff = p - buffer;
		return -1;  /* invalid format specifier */
	    }
	    percent = NULL;
	}
	else if( *p == '(' ) {
	    if( disphint ) {
		*erroff = p - buffer;
		return -9; /* open display hint */
	    }
	    MAKE_SPACE (0);
	    *c.pos++ = ST_OPEN;

	    if ( !c.fixups ) {
		c.max_fixups = 10;
		c.fixups = g10_xcalloc( c.max_fixups, sizeof *c.fixups );
		c.n_fixups = 0;
	    }
	    else if ( c.n_fixups >= c.max_fixups ) {
		c.max_fixups += 10;
		c.fixups = g10_xrealloc( c.fixups,
					 c.max_fixups * sizeof *c.fixups );
	    }
	    c.fixups[c.n_fixups++] = c.pos;

	    STORE_LEN ( c.pos, 0 ); /* reserve */
	}
	else if( *p == ')' ) { /* walk up */
	    byte *fixup;

	    if( disphint ) {
		*erroff = p - buffer;
		return -9; /* open display hint */
	    }
	    if( !c.n_fixups ) {
		*erroff = 0;
		return -4;   /* no open list */
	    }
	    MAKE_SPACE (0);
	    fixup = c.fixups[--c.n_fixups];
	    *c.pos++ = ST_CLOSE;
	    STORE_LEN ( fixup, c.pos - fixup - sizeof(DATALEN) );
	}
	else if( *p == '\"' ) {
	    quoted = p;
	    quoted_esc = 0;
	}
	else if( *p == '#' ) {
	    hexfmt = p;
	    hexcount = 0;
	}
	else if( *p == '|' )
	    base64 = p;
	else if( *p == '[' ) {
	    if( disphint ) {
		*erroff = p - buffer;
		return -8; /* nested display hints */
	    }
	    disphint = p;
	}
	else if( *p == ']' ) {
	    if( !disphint ) {
		*erroff = p - buffer;
		return -9; /* unmatched display hint close */
	    }
	    disphint = NULL;
	}
	else if( isdigit(*p) ) {
	    if( *p == '0' ) { /* a length may not begin with zero */
		*erroff = p - buffer;
		return -7;
	    }
	    digptr = p;
	}
	else if( strchr( tokenchars, *p ) )
	    tokenp = p;
	else if( isspace(*p) )
	    ;
	else if( *p == '{' ) {
	    /* fixme: handle rescanning:
	     * we can do this by saving our current state
	     * and start over at p+1 -- Hmmm. At this point here
	     * we are in a well defined state, so we don't need to save
	     * it.  Great.
	     */
	    *erroff = p - buffer;
	    return -10; /* unexpected reserved punctuation */
	}
	else if( strchr( "&\\", *p ) ) { /*reserved punctuation*/
	    *erroff = p - buffer;
	    return -10; /* unexpected reserved punctuation */
	}
	else if( arg_ptr && *p == '%' ) {
	    percent = p;
	}
	else { /* bad or unavailable*/
	    *erroff = p - buffer;
	    return -5;
	}

    }
    MAKE_SPACE (0);
    *c.pos++ = ST_STOP;

    g10_free ( c.fixups );
    *retsexp = normalize ( c.sexp );
    return 0;
  #undef MAKE_SPACE
  #undef STORE_LEN
}

int
gcry_sexp_sscan( GCRY_SEXP *retsexp, size_t *erroff,
			    const char *buffer, size_t length )
{
    return sexp_sscan( retsexp, erroff, buffer, length, NULL );
}

int
gcry_sexp_build( GCRY_SEXP *retsexp, size_t *erroff, const char *format, ... )
{
    int rc;
    va_list arg_ptr ;

    va_start( arg_ptr, format ) ;
    rc = sexp_sscan( retsexp, erroff, format, strlen(format), arg_ptr );
    va_end(arg_ptr);

    return rc;
}

/****************
 * Print SEXP to buffer using the MODE.  Returns the length of the
 * SEXP in buffer or 0 if the buffer is too short (We have at least an
 * empty list consisting of 2 bytes).  If a buffer of NULL is provided,
 * the required length is returned.
 */
size_t
gcry_sexp_sprint( GCRY_SEXP sexp, int mode, char *buffer, size_t maxlength )
{
    return 0;
}





#if 0
/***********************************************************/

const char *
strusage( int level )
{
    return "?";
}


int
main(int argc, char **argv)
{
    char buffer[5000];
    size_t erroff;
    int rc, n;
    FILE *fp;
    GCRY_SEXP s_pk, s_dsa, s_p, s_q, s_g, s_y, sexp;

  #if 1
    fp = stdin;
    n = fread(buffer, 1, 5000, fp );
    rc = gcry_sexp_sscan( &sexp, buffer, n, &erroff );
    if( rc ) {
	fprintf(stderr, "parse error %d at offset %u\n", rc, erroff );
	exit(1);
    }
    fputs("We have this S-Exp:\n",stderr);
    dump_sexp( sexp );
  #else
    s_pk = SEXP_NEW( "public-key", 10 );
    fputs("pk:\n",stderr);dump_sexp( s_pk );
    s_dsa = SEXP_NEW( "dsa", 3 );
    s_p = SEXP_CONS( SEXP_NEW( "p", 1 ), SEXP_NEW( "PPPPPP", 6 ) );
    fputs("p:\n",stderr);dump_sexp( s_p );
    s_y = SEXP_CONS( SEXP_NEW( "y", 1 ), SEXP_NEW( "YYYYYYYY", 8 ) );
    fputs("y:\n",stderr);dump_sexp( s_y );
    s_q = gcry_sexp_new_name_data( "q", "QQQ", 3 );
    fputs("q:\n",stderr);dump_sexp( s_q );
    s_g = gcry_sexp_new_name_mpi( "g" , gcry_mpi_set_ui(NULL, 42) );
    fputs("g:\n",stderr);dump_sexp( s_g );
    sexp = SEXP_CONS( s_pk, gcry_sexp_vlist( s_dsa,
					     s_y,
					     s_p,
					     s_q,
					     s_g,
					     NULL ));
    fputs("Here is what we have:\n",stderr);
    dump_sexp( sexp );
  #endif

    /* now find something */
    if( argc > 1 )
      {
	GCRY_SEXP s1;

	s1 = gcry_sexp_find_token( sexp, argv[1], strlen(argv[1]) );
	if( !s1 )
	  {
	    fprintf(stderr, "didn't found `%s'\n", argv[1] );
	  }
	else
	  {
	    fprintf(stderr, "found `%s':\n", argv[1] );
	    dump_sexp( s1 );
	  }

	#if 0
	{  int i,rc, algo;
	   GCRY_MPI *array;

	   rc = sexp_to_pk( s1, 0, &array, &algo);
	   if( rc )
	      fprintf(stderr, "sexp_to_pk failed: rc=%d\n", rc );
	   else {
	       for(i=0; array[i]; i++ ) {
		   fprintf(stderr, "MPI[%d]: ", i);
		   dump_mpi( array[i] );
		   fprintf(stderr, "\n");
	       }
	    }
	}
	#endif


	if( argc > 2 ) /* get the MPI out of the list */
	#if 0
	  {
	    GCRY_SEXP s2;
	    const char *p;
	    size_t n;

	    p = gcry_sexp_car_data( s1, &n );
	    if( !p ) {
		fputs("no CAR\n", stderr );
		exit(1);
	    }
	    fprintf(stderr, "CAR=`%.*s'\n", (int)n, p );

	    p = gcry_sexp_cdr_data( s1, &n );
	    if( !p ) {
		s2 = gcry_sexp_cdr( s1 );
		if( !s2 ) {
		    fputs("no CDR at all\n", stderr );
		    exit(1);
		}
		p = gcry_sexp_car_data( s2, &n );
	    }
	    if( !p ) {
		fputs("no CDR data\n", stderr );
		exit(1);
	    }
	    fprintf(stderr, "CDR=`%.*s'\n", (int)n, p );



	  }
	#elif 1
	  {
	    GCRY_SEXP s2;
	    MPI a;
	    const char *p;
	    size_t n;

	    fprintf(stderr,"*********************************\n");
	    p = gcry_sexp_car_data( s1, &n );
	    if( !p ) {
		fputs("no CAR\n", stderr );
		exit(1);
	    }
	    fprintf(stderr, "CAR=`%.*s'\n", (int)n, p );
	    s2 = gcry_sexp_cdr( s1 );
	    if( !s2 ) {
		fputs("no CDR\n", stderr );
		exit(1);

	    }
	    p = gcry_sexp_car_data( s2, &n );
	    if( !p ) {
		fputs("no data at CAR\n", stderr );
		exit(1);
	    }
	    fprintf(stderr, "CAR=`%.*s'\n", (int)n, p );

	    s2 = gcry_sexp_find_token( s1, argv[2], strlen(argv[2]) );
	    if( !s2 )
	    {
	       fprintf(stderr, "didn't found `%s'\n", argv[2] );
	       exit(1);
	    }
	    p = gcry_sexp_car_data( s2, &n );
	    if( !p ) {
		fputs("no CAR\n", stderr );
		exit(1);
	    }
	    fprintf(stderr, "CAR=`%.*s'\n", (int)n, p );

	    a = gcry_sexp_cdr_mpi( s2, GCRYMPI_FMT_USG );
	    if( a ) {
		fprintf(stderr, "MPI: ");
		dump_mpi( a );
		fprintf(stderr, "\n");
	    }
	    else
		fprintf(stderr, "cannot cdr a mpi\n" );
	  }
	 #else
	  {    /* print all MPIs */
	    void *ctx = NULL;
	    GCRY_SEXP s2;
	    MPI a;

	    while( (s2 = gcry_sexp_enum( s1, &ctx, 0 )) )
	      {
		const char *car_d;
		size_t car_n;

		car_d = gcry_sexp_car_data( s2, &car_n );
		if( car_d ) {
		   fprintf(stderr, "CAR: %.*s=", (int)car_n, car_d );
		   a = gcry_sexp_cdr_mpi( s2, GCRYMPI_FMT_USG );
		   dump_mpi( a );
		   fprintf(stderr, "\n");

		}
		else
		    fprintf(stderr, "no CAR\n");
	      }
	  }
	 #endif
      }
    return 0;
}
#endif
