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


/****************
 * TODO:
 *  - implement reference counting to defere freeing of
 *    data and make copies of the data on demand.
 *    --> do we really need this?
 *
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



#if 0
struct sexp_node;
typedef struct sexp_node *NODE;

struct gcry_sexp {
    int orig_format;  /* format which we used to create this object */
    NODE sexp;	      /* a NULL indicates an empty list */
};
#else
typedef struct gcry_sexp *NODE;
#endif


enum node_types { ntLIST, ntDATA, ntMPI };

struct gcry_sexp {
    NODE next;
    NODE up;	    /* helper needed for faster traversal */
    enum node_types type;
    union {
	NODE list;
	GCRY_MPI mpi;
	struct {
	    size_t len;
	    byte  d[1];
	} data;
    } u;
};


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

static void
dump_string( FILE *fp, const byte *p, size_t n, int delim )
{
    for( ; n; n--, p++ )
	if( iscntrl( *p ) || *p == delim ) {
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

static void
do_dump_list( NODE node, int indent )
{
    for( ; node; node = node->next ) {
	switch( node->type ) {
	  case ntLIST:
	    if( indent )
		putc('\n', stderr);
	    fprintf(stderr, "%*s(", indent, "");
	    do_dump_list( node->u.list, indent+1 );
	    putc(')', stderr);
	    break;
	  case ntDATA:
	    if( !node->u.data.len )
		fputs("EMPTY", stderr );
	    else
		dump_string(stderr, node->u.data.d, node->u.data.len, ')');
	    putc(' ', stderr);
	    break;
	  case ntMPI:
	    dump_mpi( node->u.mpi );
	    putc(' ', stderr);
	    break;
	}
	if( !indent )
	    putc('\n', stderr);
    }
}

static void
dump_sexp( NODE node )
{
    do_dump_list( node, 0 );
}


void
gcry_sexp_dump( GCRY_SEXP a )
{
    do_dump_list( a, 0 );
}


/****************
 * Create a new SEXP element (data)
 * If length is 0 it is assumed that buffer is a C string.
 */
GCRY_SEXP
gcry_sexp_new_data( const char *buffer, size_t length )
{
    NODE list, node;

    if( !length )
	length = strlen(buffer);
    node = g10_xcalloc( 1, sizeof *node + length );
    node->type = ntDATA;
    node->u.data.len = length;
    memcpy(node->u.data.d, buffer, length );
    list = g10_xcalloc( 1, sizeof *list );
    list->type = ntLIST;
    list->u.list = node;
    return list;
}

/****************
 * Create a new SEXP element (mpi)
 */
GCRY_SEXP
gcry_sexp_new_mpi( GCRY_MPI mpi )
{
    NODE list, node;

    node = g10_xcalloc( 1, sizeof *node );
    node->type = ntMPI;
    node->u.mpi = gcry_mpi_copy( mpi );
    list = g10_xcalloc( 1, sizeof *list );
    list->type = ntLIST;
    list->u.list = node;
    return list;
}


/****************
 * Create a pair of a name and some arbitrary data.
 */
GCRY_SEXP
gcry_sexp_new_name_data( const char *name, const char *buffer, size_t length )
{
    return gcry_sexp_cons( gcry_sexp_new_data( name, 0 ),
			   gcry_sexp_new_data( buffer, length ) );
}

/****************
 * Create a pair of a name and a MPI
 */
GCRY_SEXP
gcry_sexp_new_name_mpi( const char *name, GCRY_MPI mpi )
{
    return gcry_sexp_cons( gcry_sexp_new_data( name, 0 ),
			   gcry_sexp_new_mpi( mpi ) );
}


/****************
 * Release resource of the given SEXP object.
 */
void
gcry_sexp_release( GCRY_SEXP sexp )
{
    /* FIXME! */
}




/****************
 * Make a pair from lists a and b, don't use a or b later on.
 * Special behaviour:  If one is a single element list we put the
 * element straight into the new pair.
 */
GCRY_SEXP
gcry_sexp_cons( GCRY_SEXP a, GCRY_SEXP b )
{
    NODE head;

    if( a->type != ntLIST ) {
	fputs("sexp_cons: arg 1 is not a list\n", stderr );
	return NULL;
    }
    if( b->type != ntLIST ) {
	fputs("sexp_cons: arg 2 is not a list\n", stderr );
	return NULL;
    }


    head = g10_xcalloc( 1, sizeof *head );
    head->type = ntLIST;
    if( !a->u.list->next ) { /* a has only one item */
	NODE tmp = a;
	a = a->u.list;
	/* fixme: release tmp here */
    }
    if( !b->u.list->next ) { /* b has only one item */
	NODE tmp = b;
	b = b->u.list;
	/* fixme: release tmp here */
    }

    head->u.list = a;
    a->up = head;
    a->next = b;
    b->up = head;

    return head;
}


/****************
 * Make a list from all items in the array the end of the array is marked
 * with a NULL. 								      y a NULL
 * Don't use the passed lists later on, they are void.
 */
GCRY_SEXP
gcry_sexp_alist( GCRY_SEXP *array )
{
    NODE head, tail = NULL, node;
    va_list arg_ptr ;
    int i;

    if( !*array )
	return NULL;

    head = g10_xcalloc( 1, sizeof *node );
    head->type = ntLIST;

    for( i=0; (node = array[i]); i++ ) {
	if( node->type != ntLIST ) {
	    fputs("sexp_alist: an arg is not a list\n", stderr );
	    return NULL;  /* fixme: we should release already allocated nodes */
	}
	if( !node->u.list->next ) { /* node has only one item */
	    NODE tmp = node;
	    node = node->u.list;
	    /* fixme: release tmp here */
	}
	if( !tail )  {
	    head->u.list = node;
	}
	else
	    tail->next = node;
	node->up = head;
	tail = node;
    }

    return head;
}

/****************
 * Make a list from all items, the end of list is indicated by a NULL
 * don't use the passed lists later on, they are void.
 */
GCRY_SEXP
gcry_sexp_vlist( GCRY_SEXP a, ... )
{
    NODE head, tail, node;
    va_list arg_ptr ;

    if( a->type != ntLIST ) {
	fputs("sexp_vlist: arg 1 is not a list\n", stderr );
	return NULL;
    }
    head = g10_xcalloc( 1, sizeof *node );
    head->type = ntLIST;
    if( !a->u.list->next ) { /* a has only one item */
	NODE tmp = a;
	a = a->u.list;
	/* fixme: release tmp here */
    }
    head->u.list = a;
    a->up = head;
    tail = a;

    va_start( arg_ptr, a ) ;
    while( (node = va_arg( arg_ptr, NODE )) ) {
	if( node->type != ntLIST ) {
	    fputs("sexp_vlist: an arg is not a list\n", stderr );
	    return NULL;  /* fixme: we should release already allocated nodes */
	}
	if( !node->u.list->next ) { /* node has only one item */
	    NODE tmp = node;
	    node = node->u.list;
	    /* fixme: release tmp here */
	}
	tail->next = node;
	node->up = head;
	tail = node;
    }

    va_end( arg_ptr );
    return head;
}


/****************
 * Append n to the list a
 * Don't use n later on.
 * Returns: a new ist (which maybe a)
 */
GCRY_SEXP
gcry_sexp_append( GCRY_SEXP a, GCRY_SEXP n )
{
    GCRY_SEXP node;

    if( a->type != ntLIST ) {
	fputs("sexp_append: a is not a list\n", stderr );
	return a;
    }

    if( n->type != ntLIST ) {
	fputs("sexp_append: n is not a list\n", stderr );
	return a;
    }

    for( node = a; node->next; node = node->next )
	;

    node->next = n;
    return a;
}

GCRY_SEXP
gcry_sexp_prepend( GCRY_SEXP a, GCRY_SEXP n )
{

    fputs("sexp_prepend: not impl.\n", stderr );
    return a;
}



/****************
 * Locate data in a list. Data must be the first item in the list.
 * Returns: The sublist with that Data (don't modify it!)
 */
GCRY_SEXP
gcry_sexp_find_token( GCRY_SEXP list, const char *tok, size_t toklen )
{
    NODE node;

    if( !toklen )
	toklen = strlen(tok);

    for( node=list ; node; node = node->next )
      {
	switch( node->type ) {
	  case ntLIST: {
		NODE n = gcry_sexp_find_token( node->u.list, tok, toklen );
		if( n )
		    return n;
	    }
	    break;
	  case ntDATA:
	    if( node == list
		&& node->u.data.len == toklen
		&& !memcmp( node->u.data.d, tok, toklen ) )
	      {
		return node;
	      }
	    break;
	  case ntMPI:
	    break;
	}
      }

    return NULL;
}


/****************
 * Enumerate all objects in the list.  Ther first time you call this, pass
 * the address of a void pointer initialized to NULL.  Then don't touch this
 * variable anymore but pass it verbatim to the function; you will get
 * all lists back in turn. End of lists is indicated by a returned NIL in
 * which case you should not continue to use this function
 * (it would wrap around).  If you decide to cancel the operation before
 * the final NIL you have to release the context by calling the function
 * with a the context but a LIST set to NULL.
 * Note that this function returns only lists and not single objects.
 */
GCRY_SEXP
gcry_sexp_enum( GCRY_SEXP list, void **context, int mode )
{
    NODE node;

    if( mode )
	return NULL; /* mode is reserved and must be 0 */
    if( !list ) {
	/* we are lucky that we can hold all information in the pointer
	 * value ;-) - so there is no need to release any memory */
	*context = NULL;
	return NULL;
    }
    if( !*context )  /* start enumeration */
	node = list;
    else {
	node = *context;
	node = node->next;
    }

    for( ; node; node = node->next ) {
	*context = node; /* store our context */
	if( node->type == ntLIST )
	    return node->u.list;
	return node;
    }

    /* release resources and return nil */
    return gcry_sexp_enum( NULL, context, mode );
}



/****************
 * Get the CAR
 */
GCRY_SEXP
gcry_sexp_car( GCRY_SEXP list )
{
    return list;
}

/****************
 * Get data from the car
 */
const char *
gcry_sexp_car_data( GCRY_SEXP list, size_t *datalen )
{
    if( list && list->type == ntLIST && !list->next )
	list = list->u.list;
    if( list && list->type == ntDATA ) {
	*datalen = list->u.data.len;
	return list->u.data.d;
    }

    return NULL;
}

/****************
 * Get a MPI from the car
 */
GCRY_MPI
gcry_sexp_car_mpi( GCRY_SEXP list, int mpifmt )
{
    if( list && list->type == ntLIST && !list->next )
	list = list->u.list;
    if( mpifmt && list->type == ntDATA ) {
	MPI a;
	size_t n = list->u.data.len;
	if( gcry_mpi_scan( &a, mpifmt, list->u.data.d, &n ) )
	    return NULL;
	return a;
    }
    else if( list->type == ntMPI )
	return gcry_mpi_copy( list->u.mpi );

    return NULL;
}

/****************
 * Get the CDR
 */
GCRY_SEXP
gcry_sexp_cdr( GCRY_SEXP list )
{
    if( list && (list = list->next) )
	return list;
    return NULL;
}

/****************
 * Get data from the cdr assuming this is a pair
 */
const char *
gcry_sexp_cdr_data( GCRY_SEXP list, size_t *datalen )
{
    if( list && (list = list->next) && list->type == ntDATA ) {
	*datalen = list->u.data.len;
	return list->u.data.d;
    }

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
    NODE node = list;

    if( !node || !(node = node->next) || node == ntLIST )
	return NULL;
    if( mpifmt && node->type == ntDATA ) {
	MPI a;
	size_t n = node->u.data.len;
	if( gcry_mpi_scan( &a, mpifmt, node->u.data.d, &n ) )
	    return NULL;
	return a;
    }
    else if( node->type == ntMPI )
	return gcry_mpi_copy( node->u.mpi );
    else
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



/****************
 * Scan the provided buffer and return the S expression in our internal
 * format.  Returns a newly allocated expression.  If erroff is not NULL and
 * a parsing error has occured, the offset into buffer will be returned.
 */
int
gcry_sexp_sscan( GCRY_SEXP *retsexp, const char *buffer,
				     size_t length, size_t *erroff )
{
    static const char tokenchars[] = "abcdefghijklmnopqrstuvwxyz"
				     "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
				     "0123456789-./_:*+=";
    const char *p;
    size_t n;
    NODE head, tail, node;
    const char *digptr=NULL;
    const char *quoted=NULL;
    const char *tokenp=NULL;
    const char *hexfmt=NULL;
    const char *base64=NULL;
    const char *disphint=NULL;
    int hexcount=0;
    int quoted_esc=0;
    int datalen=0;
    int first;
    size_t dummy_erroff;

    if( !erroff )
	erroff = &dummy_erroff;

    tail = head = NULL;
    first = 0;
    for(p=buffer,n=length; n; p++, n-- ) {
	if( tokenp && !hexfmt ) {
	    if( strchr( tokenchars, *p ) )
		continue;
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
		int i;

		if( (hexcount & 1) ) {
		    *erroff = p - buffer;
		    return -12;  /* odd number of hex digits */
		}

		/* make a new list entry */
		datalen = hexcount/2;
		node = g10_xcalloc( 1, sizeof *node + datalen );
		if( first ) { /* stuff it into the first node */
		    first = 0;
		    node->up = tail;
		    tail->u.list = node;
		}
		else {
		    node->up = tail->up;
		    tail->next = node;
		}
		tail = node;
		/* and fill in the value (we store the value in the node)*/
		node->type = ntDATA;
		node->u.data.len = datalen;
		for(i=0, hexfmt++; hexfmt < p; hexfmt++ ) {
		    if( isspace( *hexfmt ) )
			continue;
		    node->u.data.d[i++] = hextobyte( hexfmt );
		    hexfmt++;
		}
		assert( hexfmt == p );
		assert( i == datalen );
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
		if( !head ) {
		    *erroff = 0;
		    return -4;	 /* not a list */
		}
		datalen = atoi( digptr ); /* fixme: check for overflow */
		digptr = NULL;
		if( datalen > n-1 ) {
		    *erroff = p - buffer;
		    return -2; /* buffer too short */
		}
		/* make a new list entry */
		node = g10_xcalloc( 1, sizeof *node + datalen );
		if( first ) { /* stuff it into the first node */
		    first = 0;
		    node->up = tail;
		    tail->u.list = node;
		}
		else {
		    node->up = tail->up;
		    tail->next = node;
		}
		tail = node;
		/* and fill in the value (we store the value in the node)*/
		node->type = ntDATA;
		node->u.data.len = datalen;
		memcpy(node->u.data.d, p+1, datalen );

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
	else if( *p == '(' ) {
	    if( disphint ) {
		*erroff = p - buffer;
		return -9; /* open display hint */
	    }
	    node = g10_xcalloc( 1, sizeof *node );
	    if( !head )
		head = node;
	    else {
		node->up = tail->up;
		tail->next = node;
	    }
	    node->type = ntLIST;
	    tail = node;
	    first = 1;
	}
	else if( *p == ')' ) { /* walk up */
	    if( disphint ) {
		*erroff = p - buffer;
		return -9; /* open display hint */
	    }
	    if( !head ) {
		*erroff = 0;
		return -4;   /* not a list */
	    }
	    tail = tail->up;
	    if( !tail ) {
		*erroff = p - buffer;
		return -3;
	    }
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
	else { /* bad or unavailable*/
	    *erroff = p - buffer;
	    return -5;
	}

    }
    *retsexp = head;
    return 0;
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





#if 1
/***********************************************************/

const char *
strusage( int level )
{
    return "?";
}


#if 0
static int
sexp_to_pk( GCRY_SEXP sexp, int want_private, MPI **retarray, int *retalgo)
{
    GCRY_SEXP list, l2;
    const char *name;
    const char *s;
    size_t n;
    int i, idx;
    int algo;
    const char *elems1, *elems2;
    GCRY_MPI *array;
    static struct { const char* name; int algo;
		    const char* common_elements;
		    const char* public_elements;
		    const char* secret_elements;
		  } algos[] = {
	{  "dsa"            , PUBKEY_ALGO_DSA       , "pqgy", "", "x"    },
	{  "rsa"            , PUBKEY_ALGO_RSA       , "ne",   "", "dpqu" },
	{  "openpgp-dsa"    , PUBKEY_ALGO_DSA       , "pqgy", "", "x"    },
	{  "openpgp-rsa"    , PUBKEY_ALGO_RSA       , "pqgy", "", "x"    },
	{  "openpgp-elg"    , PUBKEY_ALGO_ELGAMAL_E , "pgy",  "", "x"    },
	{  "openpgp-elg-sig", PUBKEY_ALGO_ELGAMAL   , "pgy",  "", "x"    },
	{  NULL }};

    /* check that the first element is valid */
    list = gcry_sexp_find_token( sexp, want_private? "private-key"
						    :"public-key", 0 );
    if( !list )
	return -1; /* Does not contain a public- or private-key object */
    list = gcry_sexp_cdr( list );
    if( !list )
	return -2; /* no cdr for the key object */
    name = gcry_sexp_car_data( list, &n );
    if( !name )
	return -3; /* invalid structure of object */
    fprintf(stderr, "algorithm name: `%.*s'\n", (int)n, name );
    for(i=0; (s=algos[i].name); i++ ) {
	if( strlen(s) == n && !memcmp( s, name, n ) )
	    break;
    }
    if( !s )
	return -4; /* unknown algorithm */
    algo = algos[i].algo;
    elems1 = algos[i].common_elements;
    elems2 = want_private? algos[i].secret_elements : algos[i].public_elements;
    array = g10_xcalloc( (strlen(elems1)+strlen(elems2)+1) , sizeof *array );
    idx = 0;
    for(s=elems1; *s; s++, idx++ ) {
	l2 = gcry_sexp_find_token( list, s, 1 );
	if( !l2 ) {
	    g10_free( array );
	    return -5; /* required parameter not found */
	}
	array[idx] = gcry_sexp_cdr_mpi( l2, GCRYMPI_FMT_USG );
	if( !array[idx] ) {
	    g10_free( array );
	    return -6; /* required parameter is invalid */
	}
    }
    for(s=elems2; *s; s++, idx++ ) {
	l2 = gcry_sexp_find_token( list, s, 1 );
	if( !l2 ) {
	    g10_free( array );
	    return -5; /* required parameter not found */
	}
	/* FIXME: put the MPI in secure memory when needed */
	array[idx] = gcry_sexp_cdr_mpi( l2, GCRYMPI_FMT_USG );
	if( !array[idx] ) {
	    g10_free( array );
	    return -6; /* required parameter is invalid */
	}
    }

    *retarray = array;
    *retalgo = algo;

    return 0;
}
#endif


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
