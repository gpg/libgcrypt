/* dynload.c - load cipher extensions
 *	Copyright (C) 1998, 2001, 2002 Free Software Foundation, Inc.
 *
 * This file is part of Libgcrypt.
 *
 * Libgcrypt is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser general Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * Libgcrypt is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

/*
 Note: We don't support dynamically loaded modules anymore.  This
 would be troublesome for thread-safety and it is better done by the
 application.  One of the next releases will have an API to support
 additional ciphers.
*/


#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "g10lib.h"
#include "cipher.h"
#include "dynload.h"


typedef struct ext_list {
    struct ext_list *next;
    int internal;
    int handle;   /* if the function has been loaded, this is true */
    int  failed;  /* already tried but failed */
    void * (*enumfunc)(int, int*, int*, int*);
    char *hintstr; /* pointer into name */
    char name[1];
} *EXTLIST;

static EXTLIST extensions;

typedef struct {
    EXTLIST r;
    int seq1;
    int seq2;
    void *sym;
    int reqalgo;
} ENUMCONTEXT;


void
_gcry_register_internal_cipher_extension(
			const char *module_id,
			void * (*enumfunc)(int, int*, int*, int*)
				  )
{
    EXTLIST r, el;

    el = gcry_xcalloc( 1, sizeof *el + strlen(module_id) );
    strcpy(el->name, module_id );
    el->internal = 1;

    /* check that it is not already registered */
    for(r = extensions; r; r = r->next ) {
	if( !strcmp (r->name, el->name) ) {
	    log_info("extension `%s' already registered\n", el->name );
	    gcry_free(el);
	    return;
	}
    }
    /* and register */
    el->enumfunc = enumfunc;
    el->handle = 1;
    el->next = extensions;
    extensions = el;
}


static int
load_extension( EXTLIST el )
{
    return -1;
}



int
_gcry_enum_gnupgext_digests( void **enum_context,
	    int *algo,
	    const char *(**r_get_info)( int, size_t*,byte**, int*, int*,
				       void (**)(void*),
				       void (**)(void*,byte*,size_t),
				       void (**)(void*),byte *(**)(void*)) )
{
    EXTLIST r;
    ENUMCONTEXT *ctx;

    if( !*enum_context ) { /* init context */
	ctx = gcry_xcalloc( 1, sizeof( *ctx ) );
	ctx->r = extensions;
	ctx->reqalgo = *algo;
	*enum_context = ctx;
    }
    else if( !algo ) { /* release the context */
	gcry_free(*enum_context);
	*enum_context = NULL;
	return 0;
    }
    else
	ctx = *enum_context;

    for( r = ctx->r; r; r = r->next )  {
	int class, vers;

	if( r->failed )
	    continue;
	if( !r->handle && load_extension(r) )
	    continue;
	/* get a digest info function */
	if( ctx->sym )
	    goto inner_loop;
	while( (ctx->sym = (*r->enumfunc)(10, &ctx->seq1, &class, &vers)) ) {
	    void *sym;
	    /* must check class because enumfunc may be wrong coded */
	    if( vers != 1 || class != 10 )
		continue;
	  inner_loop:
	    *r_get_info = ctx->sym;
	    while( (sym = (*r->enumfunc)(11, &ctx->seq2, &class, &vers)) ) {
		if( vers != 1 || class != 11 )
		    continue;
		*algo = *(int*)sym;
		ctx->r = r;
		return 1;
	    }
	    ctx->seq2 = 0;
	}
	ctx->seq1 = 0;
    }
    ctx->r = r;
    return 0;
}

const char *
_gcry_enum_gnupgext_ciphers( void **enum_context, int *algo,
		       size_t *keylen, size_t *blocksize, size_t *contextsize,
		       int  (**setkeyf)( void *c, byte *key, unsigned keylen ),
		       void (**encryptf)( void *c, byte *outbuf, byte *inbuf ),
		       void (**decryptf)( void *c, byte *outbuf, byte *inbuf )
		     )
{
    EXTLIST r;
    ENUMCONTEXT *ctx;
    const char * (*finfo)(int, size_t*, size_t*, size_t*,
			  int  (**)( void *, byte *, unsigned),
			  void (**)( void *, byte *, byte *),
			  void (**)( void *, byte *, byte *));

    if( !*enum_context ) { /* init context */
	ctx = gcry_xcalloc( 1, sizeof( *ctx ) );
	ctx->r = extensions;
	*enum_context = ctx;
    }
    else if( !algo ) { /* release the context */
	gcry_free(*enum_context);
	*enum_context = NULL;
	return NULL;
    }
    else
	ctx = *enum_context;

    for( r = ctx->r; r; r = r->next )  {
	int class, vers;

	if( r->failed )
	    continue;
	if( !r->handle && load_extension(r) )
	    continue;
	/* get a cipher info function */
	if( ctx->sym )
	    goto inner_loop;
	while( (ctx->sym = (*r->enumfunc)(20, &ctx->seq1, &class, &vers)) ) {
	    void *sym;
	    /* must check class because enumfunc may be wrong coded */
	    if( vers != 1 || class != 20 )
		continue;
	  inner_loop:
	    finfo = ctx->sym;
	    while( (sym = (*r->enumfunc)(21, &ctx->seq2, &class, &vers)) ) {
		const char *algname;
		if( vers != 1 || class != 21 )
		    continue;
		*algo = *(int*)sym;
		algname = (*finfo)( *algo, keylen, blocksize, contextsize,
				    setkeyf, encryptf, decryptf );
		if( algname ) {
		    ctx->r = r;
		    return algname;
		}
	    }
	    ctx->seq2 = 0;
	}
	ctx->seq1 = 0;
    }
    ctx->r = r;
    return NULL;
}

const char *
_gcry_enum_gnupgext_pubkeys( void **enum_context, int *algo,
    int *npkey, int *nskey, int *nenc, int *nsig, int *use,
    int (**generate)( int algo, unsigned int nbits, unsigned long use_e,
                      MPI *skey, MPI **retfactors ),
    int (**check_secret_key)( int algo, MPI *skey ),
    int (**encryptf)( int algo, MPI *resarr, MPI data, MPI *pkey ),
    int (**decryptf)( int algo, MPI *result, MPI *data, MPI *skey ),
    int (**sign)( int algo, MPI *resarr, MPI data, MPI *skey ),
    int (**verify)( int algo, MPI hash, MPI *data, MPI *pkey,
		    int (*cmp)(void *, MPI), void *opaquev ),
    unsigned (**get_nbits)( int algo, MPI *pkey ) )
{
    EXTLIST r;
    ENUMCONTEXT *ctx;
    const char * (*finfo)( int, int *, int *, int *, int *, int *,
			   int (**)( int, unsigned int, unsigned long,
                                     MPI *, MPI **),
			   int (**)( int, MPI * ),
			   int (**)( int, MPI *, MPI , MPI * ),
			   int (**)( int, MPI *, MPI *, MPI * ),
			   int (**)( int, MPI *, MPI , MPI * ),
			   int (**)( int, MPI , MPI *, MPI *,
					    int (*)(void*,MPI), void *),
			   unsigned (**)( int , MPI * ) );

    if( !*enum_context ) { /* init context */
	ctx = gcry_xcalloc( 1, sizeof( *ctx ) );
	ctx->r = extensions;
	*enum_context = ctx;
    }
    else if( !algo ) { /* release the context */
	gcry_free(*enum_context);
	*enum_context = NULL;
	return NULL;
    }
    else
	ctx = *enum_context;

    for( r = ctx->r; r; r = r->next )  {
	int class, vers;

	if( r->failed )
	    continue;
	if( !r->handle && load_extension(r) )
	    continue;
	/* get a pubkey info function */
	if( ctx->sym )
	    goto inner_loop;
	while( (ctx->sym = (*r->enumfunc)(30, &ctx->seq1, &class, &vers)) ) {
	    void *sym;
	    if( vers != 1 || class != 30 )
		continue;
	  inner_loop:
	    finfo = ctx->sym;
	    while( (sym = (*r->enumfunc)(31, &ctx->seq2, &class, &vers)) ) {
		const char *algname;
		if( vers != 1 || class != 31 )
		    continue;
		*algo = *(int*)sym;
		algname = (*finfo)( *algo, npkey, nskey, nenc, nsig, use,
				    generate, check_secret_key, encryptf,
				    decryptf, sign, verify, get_nbits );
		if( algname ) {
		    ctx->r = r;
		    return algname;
		}
	    }
	    ctx->seq2 = 0;
	}
	ctx->seq1 = 0;
    }
    ctx->r = r;
    return NULL;
}


int (*
_gcry_dynload_getfnc_gather_random())(void (*)(const void*, size_t, int), int,
							    size_t, int)
{
    EXTLIST r;
    void *sym;

    for( r = extensions; r; r = r->next )  {
	int seq, class, vers;

	if( r->failed )
	    continue;
	if( !r->handle && load_extension(r) )
	    continue;
	seq = 0;
	while( (sym = (*r->enumfunc)(40, &seq, &class, &vers)) ) {
	    if( vers != 1 || class != 40 )
		continue;
	    return (int (*)(void (*)(const void*, size_t, int), int,
							size_t, int))sym;
	}
    }
    return NULL;
}


void (*
_gcry_dynload_getfnc_fast_random_poll())( void (*)(const void*, size_t, int), int)
{
    EXTLIST r;
    void *sym;

    for( r = extensions; r; r = r->next )  {
	int seq, class, vers;

	if( r->failed )
	    continue;
	if( !r->handle && load_extension(r) )
	    continue;
	seq = 0;
	while( (sym = (*r->enumfunc)(41, &seq, &class, &vers)) ) {
	    if( vers != 1 || class != 41 )
		continue;
	    return (void (*)( void (*)(const void*, size_t, int), int))sym;
	}
    }
    return NULL;
}

