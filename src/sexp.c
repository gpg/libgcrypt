/* sexp.c  -  S-Expression handling
 *	Copyright (C) 1999 Free Software Foundation, Inc.
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
#include "util.h"
#include "memory.h"


/* FIXME: We should really have the m_lib functions to allow
 *	  overriding of the default malloc functions
 * For now use this kludge: */
#define m_lib_alloc	   m_alloc
#define m_lib_alloc_clear  m_alloc_clear
#define m_lib_free	   m_free




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

    if( gcry_mpi_print( GCRYMPI_FMT_HEX, buffer, &n, a ) )
	fputs("[MPI too large to print]", stderr );
    else
	fputs( buffer, stderr );
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
		print_string(stderr, node->u.data.d, node->u.data.len, ')');
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


/****************
 * Create a new SEXP element (data)
 */
GCRY_SEXP
gcry_sexp_new( const char *buffer, size_t length )
{
    NODE node;

    node = m_alloc_clear( sizeof *node + length );
    node->type = ntDATA;
    node->u.data.len = length;
    memcpy(node->u.data.d, buffer, length );
    return node;
}

/****************
 * Release resource of the given SEXP object.
 */
void
gcry_sexp_release( GCRY_SEXP sexp )
{
}




/****************
 * Make a pair from items a and b
 */
GCRY_SEXP
gcry_sexp_cons( GCRY_SEXP a, GCRY_SEXP b )
{
    NODE head;

    head = m_alloc_clear( sizeof *head );
    head->type = ntLIST;
    head->u.list = a;
    a->up = head;
    a->next = b;
    b->up = head;
    return head;
}

/****************
 * Make a list from all items, the end of list is indicated by a NULL
 */
GCRY_SEXP
gcry_sexp_vlist( GCRY_SEXP a, ... )
{
    NODE head, tail, node;
    va_list arg_ptr ;

    head = m_alloc_clear( sizeof *node );
    head->type = ntLIST;
    head->u.list = a;
    a->up = head;
    tail = a;

    va_start( arg_ptr, a ) ;
    while( (node = va_arg( arg_ptr, NODE )) ) {
	tail->next = node;
	node->up = head;
	tail = node;
    }

    va_end( arg_ptr );
    return head;
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
    int quoted_esc=0;
    int datalen=0;
    int first;

    tail = head = NULL;
    first = 0;
    for(p=buffer,n=length; n; p++, n-- ) {
	if( tokenp ) {
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
	    if( *p == '#' )
	       hexfmt = NULL;
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
		node = m_alloc_clear( sizeof *node + datalen );
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
	    node = m_alloc_clear( sizeof *node );
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
	else if( *p == '#' )
	    hexfmt = p;
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
	     * we are in a well defined state, so we don´ need to save
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
    dump_sexp( head );
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



/***********************************************************/

const char *
strusage( int level )
{
    return default_strusage(level);
}

int
main(int argc, char **argv)
{
    char buffer[5000];
    size_t erroff;
    int rc, n;
    FILE *fp;
    GCRY_SEXP s_pk, s_dsa, s_p, s_q, s_g, sexp;

    if( argc > 1 ) {
	fp = fopen( argv[1], "r" );
	if( !fp )
	    exit(1);
	n = fread(buffer, 1, 5000, fp );
	fprintf(stderr,"read %d bytes\n", n );
	rc = gcry_sexp_sscan( NULL, buffer, n, &erroff );
	fprintf(stderr, "read: rc=%d  erroff=%u\n", rc, erroff );
    }

    s_pk = SEXP_NEW( "public-key", 10 );
    fputs("pk:\n",stderr);dump_sexp( s_pk );
    s_dsa = SEXP_NEW( "dsa", 3 );
    s_p = SEXP_CONS( SEXP_NEW( "p", 1 ), SEXP_NEW( "PPPPPP", 6 ) );
    fputs("p:\n",stderr);dump_sexp( s_p );
    s_q = SEXP_CONS( SEXP_NEW( "q", 1 ), SEXP_NEW( "QQQ", 3 ) );
    s_g = SEXP_CONS( SEXP_NEW( "g", 1 ), SEXP_NEW( "GGGGGG", 6 ) );
    sexp = SEXP_CONS( s_pk, gcry_sexp_vlist( s_dsa,
					     s_p,
					     s_q,
					     s_g,
					     NULL ));
    fputs("all:\n",stderr);dump_sexp( sexp );

    return 0;
}

