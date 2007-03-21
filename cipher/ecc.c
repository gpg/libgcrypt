/* ecc.c  -  ECElGamal Public Key encryption & ECDSA signature algorithm
 *	Copyright (C) 2004, 2005, 2006 Free Software Foundation, Inc.
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

/* This code is a based on the 
 * Patch 0.1.6 for the gnupg 1.4.x branch
 * as retrieved on 2007-03-21 from
 * http://www.calcurco.cat/eccGnuPG/src/gnupg-1.4.6-ecc0.2.0beta1.diff.bz2
 *
 * Written by 
 *  Sergi Blanch i Torne <d4372211 at alumnes.eup.udl.es>, 
 *  Ramiro Moreno Chiral <ramiro at eup.udl.es>
 * Maintainers
 *  Sergi Blanch i Torne
 *  Ramiro Moreno Chiral
 *  Mikael Mylnikov (mmr)
 */

/*
 * This module are under development, it would not have to be used 
 * in a production environments. It can have bugs!
 * 
 * Made work:
 *  alex: found a bug over the passphrase.
 *  mmr: signature bug found and solved (afine conversion).
 *  mmr: found too many mistakes in the mathematical background transcription.
 *  mmr: improve the mathematical performance.
 *  mmr: solve ECElGamal IFP weakness.
 *  more polite gen_k() and its calls.
 *  mmr: extend the check_secret_key()
 * In process:
 *  genBigPoint(): Randomize the point generation.
 *  improve te memory uses.
 *  Separation between sign & encrypt keys to facility the subkeys creation.
 *  read & reread the code in a bug search!
 * To do:
 *  2-isogeny: randomize the elliptic curves.
 *  E(F_{2^m})
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "types.h"
#include "util.h"
#include "mpi.h"
#include "cipher.h"
#include "ecc.h"

//ECC over F_p; E(F_p)
//T=(p,a,b,G,n,h)
//         p:    big odd number
//         a,b:  curve generators
//         G:    Subgroup generator point
//         n:    big int, in G order
//         h:    cofactor
// y^2=x^3+ax+b --> (Y^2)Z=X^3+aX(Z^2)+b(Z^3)

//
//         Q=[d]G, 1<=d<=n-1

typedef struct {
        MPI x_;
        MPI y_;
        MPI z_;
} point; //Point representation in projective coordinates.

typedef struct {
        MPI p_;
        MPI a_,b_;
        //MPI Gx,Gy,Gz;
        point G;
        MPI n_;
        //MPI h_; =1                    //!! We will need to change this value in 2-isogeny
} ellipticCurve;//doubtful name         //!!

typedef struct {
        ellipticCurve E;
        point Q;        /*Q=[d]G*/
} ECC_public_key;//Q

typedef struct {
        ellipticCurve E;
        point Q;        /*Q=[d]G*/
        MPI d;
} ECC_secret_key;//d


static MPI gen_k( MPI p, int secure );

static void generateCurve(unsigned nbits, ellipticCurve *ECC_curve);//choice a curve of the rank

static void generateKey(ECC_secret_key *sk, unsigned nbits , MPI **factors );//Generate de cryptosystem setup.
static void testKeys( ECC_secret_key *sk, unsigned nbits );//verify correct skey
static int check_secret_key( ECC_secret_key *sk );//check the validity of the value
static void doEncrypt(MPI input, ECC_public_key *pkey, point *R, MPI c);
static MPI decrypt(MPI output, ECC_secret_key *skey, point R, MPI c);
static void sign(MPI input, ECC_secret_key *skey, MPI *r, MPI *s);
static int verify(MPI input, ECC_public_key *pkey, MPI r, MPI s);

static int genBigPoint(MPI *prime, ellipticCurve *base, point *G, unsigned nbits);//return -1 if it isn't possible
static point genPoint(MPI prime, ellipticCurve base);//random point over an Elliptic curve
static MPI existSquareRoot(MPI integer, MPI modulus);//return true or false
static void Lucas(MPI n, MPI p_, MPI q_, MPI k, MPI V_n, MPI Q_0);

static int PointAtInfinity(point Query);//return true(1), false(0), or error(-1) for an invalid point

static void escalarMult(MPI escalar, point *P, point *R, ellipticCurve *base);//return R=escalarP
static void sumPoints(point *P0, point *P1, point *P2, ellipticCurve *base);//P2=P0+P1
static void duplicatePoint(point *P, point *R, ellipticCurve *base);//R=2P
static void invertPoint(point *P, ellipticCurve *base);//P=-P

static point point_copy(point P);
static void point_free(point *P);
static int point_affine(point *P, MPI x, MPI y, ellipticCurve *base);//turn an projective coordinate to affine, return 0 (1 if error).
static ellipticCurve curve_copy(ellipticCurve E);
static void curve_free(ellipticCurve *E);
static MPI gen_bit();
static MPI gen_y_2(MPI x, ellipticCurve *base);

//Function for IFP ECElGamal Weakness.
static void sha256_hashing(MPI input, MPI *output);//Compute a hash
static void aes256_encrypting(MPI key, MPI input, MPI *output);//Encrypt simmetricaly
static void aes256_decrypting(MPI key, MPI input, MPI *output);//Decrypt simmetricaly

static void (*progress_cb) ( void *, int );
static void *progress_cb_data;

static void
progress( int c )
{
    if ( progress_cb )
	progress_cb ( progress_cb_data, c );
    else
	fputc( c, stderr );
}

/****************
 * At the begging was the same than elgamal.c
 * but mmr improve it.
 * Generate a random secret scalar k with an order of p
 * Moreover it do NOT use Wiener's table.
 */
static MPI
gen_k( MPI p, int secure ){

    MPI k = mpi_alloc_secure( 0 );
    unsigned int nbits = mpi_get_nbits(p);
    unsigned int nbytes;

    nbytes = (nbits+7)/8;
    if( DBG_CIPHER )
	log_debug("choosing a random k of %u bits\n", nbits);
    char *c = get_random_bits( nbits, secure, 1 );
    mpi_set_buffer( k, c, nbytes, 0 );
    xfree(c);
    mpi_fdiv_r(k,k, p);//simple module: k=k (mod p)
    if( DBG_CIPHER )
	progress('\n');

    return k;
}

/****************
 * Generate de cryptosystem setup.
 * At this time it fix the values to the ones which NIST recomend.
 * The subgroup generator point is in another function: 'genBigPoint'.
 */
static void
generateCurve(unsigned nbits, ellipticCurve *ECC_curve){

        ellipticCurve E;
        //point *G;

        if( nbits == 192 ){//NIST P-192
                E.p_ =mpi_alloc((nbits/(BYTES_PER_MPI_LIMB*8))+1);
                if (mpi_fromstr(E.p_,\
                        "0xfffffffffffffffffffffffffffffffeffffffffffffffff"))
                        log_fatal("ECC operation: Curve assigments failed(p)\n");
                else    ECC_curve->p_ = mpi_copy(E.p_);
                E.a_ =mpi_alloc((2/(BYTES_PER_MPI_LIMB*8))+1);
                if (mpi_fromstr(E.a_,\
			"0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFC"))//"-0x3"))
                        log_fatal("ECC operation: Curve assigments failed(a)\n");
                else    ECC_curve->a_ = mpi_copy(E.a_);
                E.b_ =mpi_alloc((nbits/(BYTES_PER_MPI_LIMB*8))+1);
                if (mpi_fromstr(E.b_,\
                        "0x64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1"))
                        log_fatal("ECC operation: Curve assigments failed(b)\n");
                else    ECC_curve->b_ = mpi_copy(E.b_);
                E.n_ =mpi_alloc((nbits/(BYTES_PER_MPI_LIMB*8))+1);
                if (mpi_fromstr(E.n_,\
                        "0xffffffffffffffffffffffff99def836146bc9b1b4d22831"))
                        log_fatal("ECC operation: Curve assigments failed(n)\n");
                else    ECC_curve->n_ = mpi_copy(E.n_);
        }
        else if( nbits == 224 ){//NIST P-224
	        E.p_ =mpi_alloc((nbits/(BYTES_PER_MPI_LIMB*8))+1);
                if (mpi_fromstr(E.p_,\
                        "0xffffffffffffffffffffffffffffffff000000000000000000000001"))
                        log_fatal("ECC operation: Curve assigments failed(p)\n");
		else    ECC_curve->p_ = mpi_copy(E.p_);
		E.a_ =mpi_alloc((2/(BYTES_PER_MPI_LIMB*8))+1);
                if (mpi_fromstr(E.a_,\
			"0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFE"))//"-0x3"))
                        log_fatal("ECC operation: Curve assigments failed(a)\n");
		else    ECC_curve->a_ = mpi_copy(E.a_);
		E.b_ =mpi_alloc((nbits/(BYTES_PER_MPI_LIMB*8))+1);
                if (mpi_fromstr(E.b_,\
                        "0xb4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4"))
                        log_fatal("ECC operation: Curve assigments failed(b)\n");
		else    ECC_curve->b_ = mpi_copy(E.b_);
		E.n_ =mpi_alloc((nbits/(BYTES_PER_MPI_LIMB*8))+1);
                if (mpi_fromstr(E.n_,\
                        "0xffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3d"))
                        log_fatal("ECC operation: Curve assigments failed(n)\n");
		else    ECC_curve->n_ = mpi_copy(E.n_);
        }
        else if( nbits == 256 ){//NIST P-256
	        E.p_ =mpi_alloc((nbits/(BYTES_PER_MPI_LIMB*8))+1);
                if (mpi_fromstr(E.p_,\
                        "0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff"))
                        log_fatal("ECC operation: Curve assigments failed(p)\n");
		else    ECC_curve->p_ = mpi_copy(E.p_);
		E.a_ =mpi_alloc((2/(BYTES_PER_MPI_LIMB*8))+1);
                if (mpi_fromstr(E.a_,\
			"0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC"))//"-0x3"))
                        log_fatal("ECC operation: Curve assigments failed(a)\n");
		else    ECC_curve->a_ = mpi_copy(E.a_);
		E.b_ =mpi_alloc((nbits/(BYTES_PER_MPI_LIMB*8))+1);
                if (mpi_fromstr(E.b_,\
                        "0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b"))
                        log_fatal("ECC operation: Curve assigments failed(b)\n");
		else    ECC_curve->b_ = mpi_copy(E.b_);
		E.n_ =mpi_alloc((nbits/(BYTES_PER_MPI_LIMB*8))+1);
                if (mpi_fromstr(E.n_,\
                        "0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"))
                        log_fatal("ECC operation: Curve assigments failed(n)\n");
		else    ECC_curve->n_ = mpi_copy(E.n_);
        }
        else if( nbits == 384 ){//NIST P-384
	        E.p_ =mpi_alloc((nbits/(BYTES_PER_MPI_LIMB*8))+1);
                if (mpi_fromstr(E.p_,\
                        "0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff"))
		        log_fatal("ECC operation: Curve assigments failed(p)\n");
		else    ECC_curve->p_ = mpi_copy(E.p_);
		E.a_ =mpi_alloc((2/(BYTES_PER_MPI_LIMB*8))+1);
                if (mpi_fromstr(E.a_,\
			"0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC"))//"-0x3"))
                        log_fatal("ECC operation: Curve assigments failed(a)\n");
		else    ECC_curve->a_ = mpi_copy(E.a_);
		E.b_ =mpi_alloc((nbits/(BYTES_PER_MPI_LIMB*8))+1);
                if (mpi_fromstr(E.b_,\
                        "0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef"))
                        log_fatal("ECC operation: Curve assigments failed(b)\n");
		else    ECC_curve->b_ = mpi_copy(E.b_);
		E.n_ =mpi_alloc((nbits/(BYTES_PER_MPI_LIMB*8))+1);
                if (mpi_fromstr(E.n_,\
                        "0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973"))
                        log_fatal("ECC operation: Curve assigments failed(n)\n");
		else    ECC_curve->n_ = mpi_copy(E.n_);
        }
        else if( nbits == 521 ){//NIST P-521
	        E.p_ =mpi_alloc((nbits/(BYTES_PER_MPI_LIMB*8))+1);
                if (mpi_fromstr(E.p_,\
                        "0x1ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"))
                        log_fatal("ECC operation: Curve assigments failed(p)\n");
		else    ECC_curve->p_ = mpi_copy(E.p_);
		E.a_ =mpi_alloc((2/(BYTES_PER_MPI_LIMB*8))+1);
                if (mpi_fromstr(E.a_,\
			"0x1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC"))//"-0x3"))
                        log_fatal("ECC operation: Curve assigments failed(a)\n");
		else    ECC_curve->a_ = mpi_copy(E.a_);
		E.b_ =mpi_alloc((nbits/(BYTES_PER_MPI_LIMB*8))+1);
                if (mpi_fromstr(E.b_,\
                        "0x051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00"))
                        log_fatal("ECC operation: Curve assigments failed(b)\n");
		else    ECC_curve->b_ = mpi_copy(E.b_);
		E.n_ =mpi_alloc((nbits/(BYTES_PER_MPI_LIMB*8))+1);
                if (mpi_fromstr(E.n_,\
                        "0x1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409"))
                        log_fatal("ECC operation: Curve assigments failed(n)\n");
		else    ECC_curve->n_ = mpi_copy(E.n_);
        }
        else{
                log_fatal("ECC operation: Curve generation failed\n");
        }
        if( DBG_CIPHER ){
	        progress('\n');
	        log_mpidump("generation  p= ", ECC_curve->p_ );
	        log_mpidump("generation  a= ", ECC_curve->a_ );
	        log_mpidump("generation  b= ", ECC_curve->b_ );
	        log_mpidump("generation  n= ", ECC_curve->n_ );
        }
        if ( genBigPoint(&ECC_curve->n_, ECC_curve, &ECC_curve->G, nbits) == -1){
                log_fatal("ECC operation: Point generation failed\n");
        }
        if( DBG_CIPHER ) {
	        log_mpidump("generation  Gx= ", ECC_curve->G.x_ );
	        log_mpidump("generation  Gy= ", ECC_curve->G.y_ );
	        log_mpidump("generation  Gz= ", ECC_curve->G.z_ );
                log_info("Setup generated\n");
	        progress('\n');
        }
}

/****************
 * Fisrt obtain the setup.
 * Over the finite field randomize an scalar secret value, and calculat de public point.
 * 
 *        !! What about the **ret_factors !!  //!!
 */
static void
generateKey(ECC_secret_key *sk, unsigned nbits , MPI **ret_factors ){

        ellipticCurve E;
        MPI d;
        point Q,G;

        generateCurve(nbits,&E);

	d = mpi_alloc_secure(nbits/BITS_PER_MPI_LIMB);
        if( DBG_CIPHER )
                log_debug("choosing a random x of size %u\n", nbits );
	d = gen_k(E.n_,2);//generate_secret_prime(nbits);
        G = point_copy(E.G);

        escalarMult(d,&E.G,&Q,&E);

        /* copy the stuff to the key structures */
        sk->E.p_ = mpi_copy(E.p_);
        sk->E.a_ = mpi_copy(E.a_);
        sk->E.b_ = mpi_copy(E.b_);
        sk->E.G = point_copy(E.G);
        sk->E.n_ = mpi_copy(E.n_);
        sk->Q = point_copy(Q);
        sk->d = mpi_copy(d);

        /* now we can test our keys (this should never fail!) */
        testKeys( sk, nbits - 64 );

        point_free(&Q);
        mpi_free(d);
        curve_free(&E);
}

/****************
 * To verify correct skey it use a random information.
 * First, encrypt and decrypt this dummy value, 
 * test if the information is recuperated.
 * Second, test with the sign and verify functions.
 */
static void
testKeys( ECC_secret_key *sk, unsigned nbits ){

        ECC_public_key pk;
        MPI test = mpi_alloc( nbits / BITS_PER_MPI_LIMB );
        point R_;
        MPI c = mpi_alloc( nbits / BITS_PER_MPI_LIMB );
        MPI out = mpi_alloc( nbits / BITS_PER_MPI_LIMB );
        MPI r = mpi_alloc( nbits / BITS_PER_MPI_LIMB );
        MPI s = mpi_alloc( nbits / BITS_PER_MPI_LIMB );

        if( DBG_CIPHER )log_info("Testing key.\n");

        pk.E = curve_copy(sk->E);
        pk.E.G = point_copy(sk->E.G);
        pk.Q = point_copy(sk->Q);

        /*mpi_set_bytes( test, nbits, get_random_byte, 0 );*/
        {	char *p = get_random_bits( nbits, 0, 0 );
        	mpi_set_buffer( test, p, (nbits+7)/8, 0 );
        	xfree(p);
        }

        doEncrypt(test,&pk,&R_,c);

        out = decrypt(out,sk,R_,c);

        if( mpi_cmp( test, out ) )//test!=out
	        log_fatal("ECELG operation: encrypt, decrypt failed\n");
        if( DBG_CIPHER )log_info("ECELG operation: encrypt, decrypt ok.\n");

        sign(test,sk,&r,&s);

        if( !verify(test,&pk,r,s) ){
        	log_fatal("ECDSA operation: sign, verify failed\n");}

        if( DBG_CIPHER )log_info("ECDSA operation: sign, verify ok.\n");

        mpi_free(s);
        mpi_free(r);
        mpi_free(out);
        mpi_free(c);
        point_free(&R_);
        mpi_free(test);
}

/****************
 * To check the validity of the value, recalculate the correspondence
 * between the public value and de secret one.
 */
static int
check_secret_key( ECC_secret_key *sk ){

        point Q;
        MPI y_2,y2 = mpi_alloc(0);

        //?primarity test of 'p'
        // (...) //!!
        //G in E(F_p)
        y_2 = gen_y_2(sk->E.G.x_,&sk->E);// y^2=x^3+a*x+b
        mpi_mulm(y2,sk->E.G.y_,sk->E.G.y_,sk->E.p_);// y^2=y*y
        if (mpi_cmp(y_2,y2)){
                if( DBG_CIPHER )log_info("Bad check: Point 'G' does not belong to curve 'E'!\n");
                return (1);
        }
        //G != PaI
        if (PointAtInfinity(sk->E.G)){
                if( DBG_CIPHER )log_info("Bad check: 'G' cannot be Point at Infinity!\n");
                return (1);
        }
        //?primarity test of 'n'
        // (...) //!!
        //?(p-sqrt(p)) < n < (p+sqrt(p))
        //?n!=p
        //?(n^k) mod p !=1 for k=1 to 31 (from GOST) or k=1 to 50 (from MIRACL)
        //Q=[n]G over E = PaI
        escalarMult(sk->E.n_,&sk->E.G,&Q,&sk->E);
        if (!PointAtInfinity(Q)){
                if( DBG_CIPHER )log_info("Bad check: 'E' is not curve of order 'n'!\n");
                return (1);
        }
        //pubkey cannot be PaI
        if (PointAtInfinity(sk->Q)){
                if( DBG_CIPHER )log_info("Bad check: Q can not be a Point at Infinity!\n");
                return (1);
        }
        //pubkey = [d]G over E
        escalarMult(sk->d,&sk->E.G,&Q,&sk->E);
        if ((Q.x_ == sk->Q.x_) && (Q.y_ == sk->Q.y_) && (Q.z_ == sk->Q.z_)){
                if( DBG_CIPHER )log_info("Bad check: There is NO correspondence between 'd' and 'Q'!\n");
                return (1);
        }
        point_free(&Q);
        return (0);
}

/****************
 * Encrypt a number and obtain and struct (R,c)
 */
static void
doEncrypt(MPI input, ECC_public_key *pkey, point *R, MPI c){

        MPI k,p,x,y;
        point P,Q,G;
        ellipticCurve E;

        k = mpi_alloc(0);
        p = mpi_copy(pkey->E.p_);
        x = mpi_alloc(0);
        y = mpi_alloc(0);
        Q = point_copy(pkey->Q);
        G = point_copy(pkey->E.G);
        E = curve_copy(pkey->E);

        k = gen_k( p, 1);//2nd parametre: how much security?
        escalarMult(k,&Q,&P,&E);//P=[k]Q=[k]([d]G)
        escalarMult(k,&G,R,&E);//R=[k]G
        //IFP weakness//mpi_mul(c,input,Q.x_);//c=input*Q_x
        //MMR Use affine conversion befor extract x-coordinate
        if (point_affine(&P,x,y,&E)){//Q cannot turn to affine coordinate
                if( DBG_CIPHER ){log_info("Encrypting: Cannot turn to affine.\n");}
        }
        //MMR According to the standard P1363 we can not use x-coordinate directly.
        // It is necessary to add hash-operation later. 
        // As the maximal length of a key for the symmetric cipher is 256 bit it is possible to take hash-function SHA256.
        sha256_hashing(x,&x);
        aes256_encrypting(x,input,&c);

        if( DBG_CIPHER ){log_debug("doEncrypt: end.\n");}
}

/****************
 * Undo the ciphertext
 */
static MPI
decrypt(MPI output, ECC_secret_key *skey, point R, MPI c){

        MPI p,inv,x,y;
        point P,Q;
        ellipticCurve E;

        p = mpi_copy(skey->E.p_);
        inv = mpi_alloc(0);
        x = mpi_alloc(0);
        y = mpi_alloc(0);
        Q = point_copy(skey->Q);
        E = curve_copy(skey->E);

        escalarMult(skey->d,&R,&P,&E);//P=[d]R
        //That is like: mpi_fdiv_q(output,c,Q.x_);
	//IFP weakness//mpi_invm(inv,Q.x_,p);//inv=Q{_x}^-1 (mod p)
	//IFP weakness//mpi_mulm(output,c,inv,p);//output=c*inv (mod p)
        //MMR Use affine conversion befor extract x-coordinate
        if (point_affine(&P,x,y,&E)){//Q cannot turn to affine coordinate
                if( DBG_CIPHER ){log_info("Encrypting: Cannot turn to affine.\n");}
        }
        sha256_hashing(x,&x);
        aes256_decrypting(x,c,&output);

        if( DBG_CIPHER ){log_debug("decrypt: end.\n");}
        return (output);
}

/****************
 * Return the signature struct (r,s) from the message hash.
 */
static void
sign(MPI input, ECC_secret_key *skey, MPI *r, MPI *s){

        MPI k,i,dr,sum,k_1,x,y;
        point G,I;
        ellipticCurve E;

        k = mpi_alloc(0); i = mpi_alloc(0); dr = mpi_alloc(0); sum = mpi_alloc(0); k_1 = mpi_alloc(0);
        x = mpi_alloc(0); y = mpi_alloc(0);
        G = point_copy(skey->E.G);
        E = curve_copy(skey->E);
        *r = mpi_alloc(0);
        *s = mpi_alloc(0);

        while (!mpi_cmp_ui(*s,0)){//s==0
	        while (!mpi_cmp_ui(*r,0)){//r==0
                        k = gen_k( E.p_, 1 );
                        escalarMult(k,&G,&I,&E);//I=[k]G
                        if (point_affine(&I,x,y,&E)){//I cannot turn to affine coordinate
                              if( DBG_CIPHER ){log_info("Sign: Cannot turn to affine. Cannot complete sign.\n");}
                        }
                        i = mpi_copy(x);//i=I_x
                        mpi_fdiv_r(*r,i,E.n_);//simple module: r=i (mod n)
                }
                mpi_mulm(dr,skey->d,*r,E.n_);//dr=d*r (mod n)
                mpi_addm(sum,input,dr,E.n_);//sum=hash+(d*r) (mod n)
                mpi_invm(k_1,k,E.n_);//k_1=k^(-1) (mod n)
                mpi_mulm(*s,k_1,sum,E.n_);// s=k^(-1)*(hash+(d*r)) (mod n)
        }
	if( DBG_CIPHER ){log_debug("Sign: end\n");}
        mpi_free(y);
        mpi_free(x);
        mpi_free(k_1);
        mpi_free(sum);
        mpi_free(dr);
        mpi_free(i);
        mpi_free(k);
}

/****************
 * Check if the struct (r,s) is for the hash value that it have.
 */
static int
verify(MPI input, ECC_public_key *pkey, MPI r, MPI s){

        MPI r_,s_,h,h1,h2,i,x,y;
        point Q,Q1,Q2,G;
        ellipticCurve E;

        r_ = mpi_alloc(0); s_ = mpi_alloc(0); h = mpi_alloc(0); h1 = mpi_alloc(0); h2 = mpi_alloc(0); x = mpi_alloc(0); y = mpi_alloc(0);
        G = point_copy(pkey->E.G);
        E = curve_copy(pkey->E);
        
        mpi_fdiv_r(r_,r,pkey->E.n_);//simple module
        mpi_fdiv_r(s_,s,pkey->E.n_);//simple module

        //check if the input parameters are valid.
        if ( mpi_cmp(r_,r) || mpi_cmp(s_,s)) {//r_!=r || s_!=s
                if( DBG_CIPHER ){log_info("Verification: No valid values.\n");}
                return 0; //not valid values.
        }

        mpi_invm(h,s,E.n_);//h=s^(-1) (mod n)
        mpi_mulm(h1,input,h,E.n_);//h1=hash*s^(-1) (mod n)
        escalarMult(h1,&G,&Q1,&E);//Q1=[hash*s^(-1)]G
        mpi_mulm(h2,r,h,E.n_);//h2=r*s^(-1) (mod n)
        escalarMult(h2,&pkey->Q,&Q2,&E);//Q2=[r*s^(-1)]Q
        sumPoints(&Q1,&Q2,&Q,&E);//Q=([hash*s^(-1)]G)+([r*s^(-1)]Q)

        if (PointAtInfinity(Q)){
                if( DBG_CIPHER ){log_info("Verification: Rejected.\n");}
                return 0;//rejected
        }
	if (point_affine(&Q,x,y,&E)){//Q cannot turn to affine coordinate
	        if( DBG_CIPHER ){log_info("Verification: Cannot turn to affine. Rejected.\n");}
		return 0;//rejected
        }
        i = mpi_copy(x);//Give the x_coordinate
        mpi_fdiv_r(i,i,E.n_);//simple module

        if (!mpi_cmp(i,r)){//i==r => Return 0 (distance between them).
                if( DBG_CIPHER ){log_info("Verification: Accepted.\n");}
                return 1;//accepted
        }
        if( DBG_CIPHER ){log_info("Verification: Not verified.\n");}
        return 0;
}

/****************
 * A point of order 'n' is needed to generate a ciclic subgroup.
 * Over this ciclic subgroup it's defined the ECDLP.
 * Now it use a fix values from NIST FIPS PUB 186-2.
 */
static int
genBigPoint(MPI *prime, ellipticCurve *base, point *G, unsigned nbits){
  ///*estandard nist
        if( nbits == 192 ){//NIST P-192
                G->x_ = mpi_alloc(mpi_get_nlimbs(base->n_));
                if (mpi_fromstr(G->x_,\
                        "0x188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012"))
                        log_fatal("Generator operation: Point assigments failed(x)\n");
                G->y_ = mpi_alloc(mpi_get_nlimbs(base->n_));
                if (mpi_fromstr(G->y_,\
                        "0x07192b95ffc8da78631011ed6b24cdd573f977a11e794811"))
                        log_fatal("Generator operation: Point assigments failed(y)\n");
                G->z_ = mpi_alloc_set_ui(1);
        }
        else if( nbits == 224 ){//NIST P-224
                G->x_ = mpi_alloc(mpi_get_nlimbs(base->n_));
                if (mpi_fromstr(G->x_,\
                        "0xb70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21"))
                        log_fatal("Generator operation: Point assigments failed(x)\n");
                G->y_ = mpi_alloc(mpi_get_nlimbs(base->n_));
                if (mpi_fromstr(G->y_,\
                        "0xbd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34"))
                        log_fatal("Generator operation: Point assigments failed(y)\n");
                G->z_ = mpi_alloc_set_ui(1);
        }
        else if( nbits == 256 ){//NIST P-256
                G->x_ = mpi_alloc(mpi_get_nlimbs(base->n_));
                if (mpi_fromstr(G->x_,\
                        "0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"))
                        log_fatal("Generator operation: Point assigments failed(x)\n");
                G->y_ = mpi_alloc(mpi_get_nlimbs(base->n_));
                if (mpi_fromstr(G->y_,\
                        "0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"))
                        log_fatal("Generator operation: Point assigments failed(y)\n");
                G->z_ = mpi_alloc_set_ui(1);
        }
        else if( nbits == 384 ){//NIST P-384
                G->x_ = mpi_alloc(mpi_get_nlimbs(base->n_));
                if (mpi_fromstr(G->x_,\
                        "0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7"))
                        log_fatal("Generator operation: Point assigments failed(x)\n");
                G->y_ = mpi_alloc(mpi_get_nlimbs(base->n_));
                if (mpi_fromstr(G->y_,\
                        "0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f"))
                        log_fatal("Generator operation: Point assigments failed(y)\n");
                G->z_ = mpi_alloc_set_ui(1);
        }
        else if( nbits == 521 ){//NIST P-521
                G->x_ = mpi_alloc(mpi_get_nlimbs(base->n_));
                if (mpi_fromstr(G->x_,\
                        "0xc6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66"))
                        log_fatal("Generator operation: Point assigments failed(x)\n");
                G->y_ = mpi_alloc(mpi_get_nlimbs(base->n_));
                if (mpi_fromstr(G->y_,\
                        "0x11839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650"))
                        log_fatal("Generator operation: Point assigments failed(y)\n");
                G->z_ = mpi_alloc_set_ui(1);
        }
  //end Estandard nist
  /*Randomize G
        unsigned int i=0;
        MPI one;
        point Big, P;

        one = mpi_alloc_set_ui(1);
        G->x_ = mpi_alloc(mpi_get_nlimbs(*prime));
        G->y_ = mpi_alloc(mpi_get_nlimbs(*prime));
        G->z_ = mpi_alloc(mpi_get_nlimbs(*prime));

        if( DBG_MPI )log_info("Generating a Big point.\n");
        do{
                do{
                        *P = genPoint(*prime,*base);
                }while(PointAtInfinity(*P));//A random point in the curve that it's not PaI
                escalarMult(base.h,&P,&G,&base);//cofactor (1 o 2), could be improved
        }while(PointAtInfinity(G));
        if( DBG_MPI )log_info("Big point generated.\n");
        if( DBG_MPI ){
                log_mpidump("Gx=",G->x_);log_mpidump("Gy=",G->y_);log_mpidump("Gz=",G->z_);
        }
        return 0;
  *///end aleatoritzar G
        return 0;
}

/****************
 * Generate a random point over an Elliptic curve 
 * is the first step to find a random ciclic subgroup
 * generator.
 *
 *        !! At this moment it isn't used !!  //!!
 */
static point
genPoint(MPI prime, ellipticCurve base){

        unsigned int i=0;
        MPI x,y_2,y;
        MPI one, one_neg,bit;
        point P;

        x = mpi_alloc(mpi_get_nlimbs(base.p_));
        y_2 = mpi_alloc(mpi_get_nlimbs(base.p_));
        y = mpi_alloc(mpi_get_nlimbs(base.p_));
        one = mpi_alloc_set_ui(1);
        one_neg = mpi_alloc(mpi_get_nlimbs(one));
        mpi_invm(one_neg,one,base.p_);

        if( DBG_MPI )log_info("Generating a normal point.\n");
        do{
	        x = gen_k(base.p_,1);//generate_public_prime(mpi_get_nlimbs(base.n_)*BITS_PER_MPI_LIMB);
                do{
                        y_2 = gen_y_2(x,&base);//x^3+ax+b (mod p)
                        mpi_add_ui(x, x, 1);
                        i++;
                }while( !mpi_cmp_ui(y_2,0) && i<0xf);//Try to find a valid value until 16 iterations.
                i=0;
                y = existSquareRoot(y_2,base.p_);
        }while( !mpi_cmp_ui(y,0));//Repeat until a valid coordinate is found.
        bit = gen_bit();//generate one bit
        if (mpi_cmp_ui(bit,1)){//choose the y coordinate
                mpi_invm(y, y, base.p_);//mpi_powm(y, y, one_neg,base.p_);
        }
        if( DBG_MPI )log_info("Normal point generated.\n");

        P.x_ = mpi_copy(x);
        P.y_ = mpi_copy(y);
        P.z_ = mpi_copy(one);

        mpi_free(bit);
        mpi_free(one_neg);
        mpi_free(one);
        mpi_free(y);
        mpi_free(y_2);
        mpi_free(x);

        return(P);
}

/****************
 * Find, if it exist, the square root of one integer module a big prime.
 * Return the square root or 0 if it is not found.
 */
static MPI
existSquareRoot(MPI integer, MPI modulus){

        unsigned long int i=0;
        MPI one,two,three,four,five,eight;
        MPI k,r,z,k1;
        MPI t1,t2,t3,t4;

        one = mpi_alloc_set_ui(1);
        two = mpi_alloc_set_ui(2);
        three = mpi_alloc_set_ui(3);
        four = mpi_alloc_set_ui(4);
        five = mpi_alloc_set_ui(5);
        eight = mpi_alloc_set_ui(8);
        k = mpi_alloc(mpi_get_nlimbs(modulus));
        r = mpi_alloc(mpi_get_nlimbs(modulus));
        z = mpi_alloc(mpi_get_nlimbs(modulus));
        k1 = mpi_alloc(mpi_get_nlimbs(modulus));
        t1 = mpi_alloc(mpi_get_nlimbs(modulus));
        t2 = mpi_alloc(mpi_get_nlimbs(modulus));
        t3 = mpi_alloc(mpi_get_nlimbs(modulus));
        t4 = mpi_alloc(mpi_get_nlimbs(modulus));

        if( DBG_MPI )log_mpidump("?exist Square Root of ",integer);

        mpi_fdiv_qr(k,r,modulus,four);
        if (mpi_cmp(r,three)){//p=3 (mod 4)
                mpi_addm(k1,k,one,modulus);
                mpi_powm(z,integer,k1,modulus);
                if( DBG_MPI ){log_mpidump("z=",z);}
                return z;//value found
        }
        mpi_fdiv_qr(k,r,modulus,eight);
        if (mpi_cmp(r,five)){//p=5 (mod 8)
                mpi_mulm(t1,two,integer,modulus);
                mpi_powm(t2,t1,k,modulus);
                mpi_powm(t2,t2,two,modulus);
                mpi_mulm(t2,t1,t2,modulus);
                mpi_mulm(t3,integer,t1,modulus);
                mpi_subm(t4,t2,one,modulus);
                mpi_mulm(z,t3,t4,modulus);
                if( DBG_MPI ){log_mpidump("z=",z);}
                return z;//value found
        }
        if (mpi_cmp(r,one)){//p=1 (mod 8)
                while(i<0xFF){//while not find z after 256 iterations*/
                        if( DBG_MPI )log_info("Square root bucle.\n");
                        t1 = mpi_copy(integer);
                        t2 = gen_k(modulus,0);
                        mpi_add_ui(t3,modulus,1);//t3=p+1
                        mpi_rshift(t3,t3,1);//t3=t3/2
                        Lucas(t1,t2,t3,modulus,t4,t3);//t4=V_k
                        mpi_rshift(z,t4,1);//z=V/2
                        mpi_sub_ui(t3,modulus,1);//t3=p-1
                        mpi_rshift(t4,t3,2);//t4=t3/2
                        Lucas(t1,t2,t4,modulus,t4,t1);//t1=Q_0
                        mpi_powm(t2,z,two,modulus);//t2=z^2
                        if (mpi_cmp(t1,integer)){
                                if( DBG_MPI ){log_mpidump("z=",z);}
                                return z;//value found
                        }
                        if (t4>mpi_alloc_set_ui(1) && t4<t3){
                                if( DBG_MPI )log_info("Rejected.\n");
                                return (0);             //NULL
                        }
                        if( DBG_MPI )log_info("Another loop.\n");
                }
        }
        if( DBG_MPI )log_info("iterations limit.\n");
        return (0);//because this algorithm not always finish.
}

/****************
 * Formal definition:
 * V_0=2;V_1=p
 * V_k=(p*V_(k-1))-(q*V_(k-2)) for k>=2
 */
static void
Lucas(MPI n, MPI p_, MPI q_, MPI k, MPI V_n, MPI Q_0){

        MPI v0,v1,q0,q1;
        MPI t1,t2;
        unsigned int r,i;

        v0 = mpi_alloc_set_ui(2);
        v1 = mpi_copy(p_);
        q0 = mpi_alloc_set_ui(1);
        q1 = mpi_alloc_set_ui(1);
        t1 = mpi_alloc_set_ui(0);
        t2 = mpi_alloc_set_ui(0);

        if( DBG_MPI ){log_info("Generating lucas sequence.\n");log_mpidump("k=",k);}

        r = mpi_get_nbits(k)-1;
        i = 0;
        while (mpi_test_bit(k,i) != 1){        //search the first bit with value '1'
                i++;
        }
        while (i<r){
                if( DBG_MPI ){
                        log_info("Lucas sequence bucle.\n");
                        log_mpidump("i=",mpi_alloc_set_ui(i));
                        log_mpidump("r=",mpi_alloc_set_ui(r));
                }
                mpi_mulm(q0,q0,q1,n);
                if (mpi_test_bit(k,i) == 1){
                        mpi_mulm(q1,q0,q_,n);
                        mpi_mul(t1,v0,v1);
                        mpi_mul(t2,p_,q0);
                        mpi_subm(v0,t1,t2,n);
                        mpi_powm(t1,v1,mpi_alloc_set_ui(2),n);
                        mpi_mul(t2,mpi_alloc_set_ui(2),q1);
                        mpi_subm(v1,t1,t2,n);
                }
                else{
                        q1 = mpi_copy(q0);
                        mpi_mul(t1,v0,v1);
                        mpi_mul(t2,p_,q0);
                        mpi_subm(v1,t1,t2,n);
                        mpi_powm(t1,v0,mpi_alloc_set_ui(2),n);
                        mpi_mul(t2,mpi_alloc_set_ui(2),q0);
                        mpi_subm(v0,t1,t2,n);
                }
                i++;
        }
        V_n = mpi_copy(v0);
        Q_0 = mpi_copy(q0);
        if( DBG_MPI ){
                log_info("Lucas sequence generated.\n");
                log_mpidump("V_n=",V_n);
                log_mpidump("Q_0=",Q_0);
        }
}

/****************
 * The point at infinity is needed to make 
 * a group structure to the elliptic curve.
 * Know if one point is it, is needed so 
 * much times in this code.
 */
static int
PointAtInfinity(point Query){

        if( DBG_MPI ){log_info("?is a Point at Infinity.\n");}

        if (!mpi_cmp_ui(Query.z_,0)){//Z=0
               if (/*mpi_cmp_ui(Query.x_,0) && */mpi_cmp_ui(Query.y_,0)){//X & Y!=0 & Z=0
                        if( DBG_MPI )log_info("True:It is a Point at Infinite.\n");
                        return (1); //true
                }
                if( DBG_MPI )log_info("Error:It isn't an elliptic curve valid point.\n");
                return (-1); //
        }
        if( DBG_MPI ){log_info("False:It isn't a Point at Infinity.\n");}
        return (0); //it is a valid curve point, but it isn't the point at infinity
}

/****************
 * The modular power used without EC, 
 * is this function over EC.
 */
static void
escalarMult(MPI escalar, point *P, point *R, ellipticCurve *base){

        MPI one,two,three;
        MPI p;
        MPI xx,yy,zz,x1,y1,z1,z2,z3,k,h;//it could use less memory!!!!
        unsigned int i,loops;
        point P1,P2,P1_;

        x1 = mpi_alloc(mpi_get_nlimbs(P->x_));
        y1 = mpi_alloc(mpi_get_nlimbs(P->y_));
        z2 = mpi_alloc(mpi_get_nlimbs(P->z_));
        z3 = mpi_alloc(mpi_get_nlimbs(P->z_));
        h = mpi_alloc(mpi_get_nlimbs(P->z_));

        if( DBG_MPI )log_info("Calculating an scalar Multiple.\n");

        one = mpi_alloc_set_ui(1);
        two = mpi_alloc_set_ui(2);
        three = mpi_alloc_set_ui(3);
        p = mpi_copy(base->p_);

        if ( !mpi_cmp_ui(escalar,0) || mpi_cmp_ui(P->z_,0)){//n=0 | Z=0 => [1:1:0]
                R->x_ = mpi_copy(one);
                R->y_ = mpi_copy(one);
                R->z_ = mpi_alloc(0);
        }
        xx = mpi_copy(P->x_);
        zz = mpi_copy(P->z_);
        z1 = mpi_copy(one);
        if (mpi_is_neg(escalar)){//(-n)P=n(-P)
                escalar->sign = 0;//+n
                k = mpi_copy(escalar);
                yy = mpi_copy(P->y_);//-P
                mpi_invm(yy,yy,p);
        }
        else {
                k = mpi_copy(escalar);
                yy = mpi_copy(P->y_);
        }
        if (!mpi_cmp(zz,one)){//zz==1
                x1 = mpi_copy(xx);
                y1 = mpi_copy(yy);
        }
        else {
                mpi_mulm(z2,zz,zz,p);//z^2
                mpi_mulm(z3,zz,z2,p);//z^3
                mpi_invm(z2,z2,p);//1/Z^2
                mpi_mulm(x1,xx,z2,p);//xx/z^2
                mpi_invm(z3,z3,p);//1/z^3
                mpi_mulm(y1,yy,z3,p);//yy/z^3
        }
        mpi_mul(h,three,k);//h=3k
        loops = mpi_get_nbits(h);
        i=loops-2; // i = l-1 = loops-2
        R->x_ = mpi_copy(xx);
        R->y_ = mpi_copy(yy);
        R->z_ = mpi_copy(zz);
        P1.x_ = mpi_copy(x1);
        P1.y_ = mpi_copy(y1);
        P1.z_ = mpi_copy(z1);
        while(i>0){ // A.10.9. step 11  i from l-1 downto 1
                duplicatePoint(R,R,base);
                if ( mpi_test_bit(h,i) == 1 && mpi_test_bit(k,i) == 0){//h_i=1 & k_i=0
                        P2 = point_copy(*R);
                        sumPoints(&P2,&P1,R,base);//R=P2+P1 over the base elliptic curve
                }
                if ( mpi_test_bit(h,i) == 0 && mpi_test_bit(k,i) == 1){//h_i=0 & k_i=1
                        P2 = point_copy(*R);
                        P1_ = point_copy(P1);
                        invertPoint(&P1_,base);
                        sumPoints(&P2,&P1_,R,base);//R=P2+P1_ over the base elliptic curve
                }
                i--;
        }
        if( DBG_MPI )log_info("Scalar Multiple calculated.\n");

	point_free(&P1);
	point_free(&P2);
        point_free(&P1_);
	mpi_free(h);
        mpi_free(k);
        mpi_free(z3);
        mpi_free(z2);
        mpi_free(z1);
        mpi_free(y1);
        mpi_free(x1);
        mpi_free(zz);
        mpi_free(yy);
        mpi_free(xx);
        mpi_free(p);
        mpi_free(three);
        mpi_free(two);
        mpi_free(one);
}

/****************
 * Point addition is the group operation.
 */
static void
sumPoints(point *P0, point *P1, point *P2, ellipticCurve *base){

        MPI one,two;
        MPI p;
        MPI t1,t2,t3,t4,t5,t6,t7;

        one = mpi_alloc_set_ui(1);
        two = mpi_alloc_set_ui(2);
        p = mpi_copy(base->p_);
        t1 = mpi_alloc(mpi_get_nlimbs(p));
        t2 = mpi_alloc(mpi_get_nlimbs(p));
        t3 = mpi_alloc(mpi_get_nlimbs(p));
        t4 = mpi_alloc(mpi_get_nlimbs(p));
        t5 = mpi_alloc(mpi_get_nlimbs(p));
        t6 = mpi_alloc(mpi_get_nlimbs(p));
        t7 = mpi_alloc(mpi_get_nlimbs(p));

        if( DBG_MPI )log_info("Add two points.\n");

        if ((!mpi_cmp(P1->x_,P0->x_)) && (!mpi_cmp(P1->y_,P0->y_)) && (!mpi_cmp(P1->z_,P0->z_))){// P1=P0
                duplicatePoint(P0,P2,base);
        }
        else if (PointAtInfinity(*P0)){//(!mpi_cmp_ui(P0->y_,0) || !mpi_cmp_ui(P0->z_,0)){// P2=0+P1=P1
                P2->x_ = mpi_copy(P1->x_);
                P2->y_ = mpi_copy(P1->y_);
                P2->z_ = mpi_copy(P1->z_);
        }
        else if (PointAtInfinity(*P1)){//(!mpi_cmp_ui(P1->y_,0) || !mpi_cmp_ui(P1->z_,0)){// P2=P0+0=P0
                P2->x_ = mpi_copy(P0->x_);
                P2->y_ = mpi_copy(P0->y_);
                P2->z_ = mpi_copy(P0->z_);
        }
        else {
                t1 = mpi_copy(P0->x_);//t1=x0
                t2 = mpi_copy(P0->y_);//t2=y0
                t3 = mpi_copy(P0->z_);//t3=z0
                t4 = mpi_copy(P1->x_);//t4=x1
                t5 = mpi_copy(P1->y_);//t5=y2
                if (mpi_cmp(P1->z_,one)){//z1!=1
                        t6 = mpi_copy(P1->z_);//t6=z1
                        mpi_powm(t7, t6,two,p);//t7=t6^2 mod p
                        mpi_mulm(t1,t1,t7,p);//t1=t1*t7 mod p
                        mpi_mulm(t7,t6,t7,p);//t7=t6*t7 mod p
                        mpi_mulm(t2,t2,t7,p);//t2=t2*t7 mod p
                }
                mpi_powm(t7,t3,two,p);//t7=t3^2 mod p
                mpi_mulm(t4,t4,t7,p);//t4=t4*t7 mod p
                mpi_mulm(t7,t3,t7,p);//t7=t3*t7 mod p
                mpi_mulm(t5,t5,t7,p);//t5=t5*t7 mod p
                mpi_subm(t4,t1,t4,p);//t4=t1-t4 mod p
                mpi_subm(t5,t2,t5,p);//t5=t2-t5 mod p
                if (!mpi_cmp_ui(t4,0)){//t4==0
                        if (!mpi_cmp_ui(t5,0)){//return (0:0:0), it have an special mean.
                                if( DBG_MPI )log_info("Point Addition: [0:0:0]!\n");
                                P2->x_ = mpi_copy(mpi_alloc_set_ui(0));
                                P2->y_ = mpi_copy(mpi_alloc_set_ui(0));
                                P2->z_ = mpi_copy(mpi_alloc_set_ui(0));
                        }
                        else {//return (1:1:0)
                                if( DBG_MPI )log_info("Point Addition: [1:1:0]!\n");
                                P2->x_ = mpi_copy(one);
                                P2->y_ = mpi_copy(one);
                                P2->z_ = mpi_copy(mpi_alloc_set_ui(0));
                        }
                }
                else{
                        mpi_mulm(t1,two,t1,p);
                        mpi_subm(t1,t1,t4,p);//t1=2*t1-t4 mod p
                        mpi_mulm(t2,two,t2,p);
                        mpi_subm(t2,t2,t5,p);//t2=2*t2-t5 mod p
                        if (mpi_cmp(P1->z_,one)){//z1!=1
		          mpi_mulm(t3,t3,t6,p);//t3=t3*t6
                        }
                        mpi_mulm(t3,t3,t4,p);//t3=t3*t4 mod p
                        mpi_powm(t7,t4,two,p);//t7=t4^2 mod p
                        mpi_mulm(t4,t4,t7,p);//t4=t4*t7 mod p
                        mpi_mulm(t7,t1,t7,p);//t7=t1*t7 mod p
                        mpi_powm(t1,t5,two,p);//t1=t5^2 mod p
                        mpi_subm(t1,t1,t7,p);//t1=t1-t7 mod p
                        mpi_mulm(t6,two,t1,p);
                        mpi_subm(t7,t7,t6,p);//t7=t7-2*t1 mod p
                        mpi_mulm(t5,t5,t7,p);//t5=t5*t7 mod p
                        mpi_mulm(t4,t2,t4,p);//t4=t2*t4 mod p
                        mpi_subm(t2,t5,t4,p);//t2=t5-t4 mod p
                        mpi_invm(t6,two,p);
                        mpi_mulm(t2,t2,t6,p);//t2 = t2/2

                        P2->x_ = mpi_copy(t1);
                        P2->y_ = mpi_copy(t2);
                        P2->z_ = mpi_copy(t3);
                }
        }
        mpi_free(t7);
        mpi_free(t6);
        mpi_free(t5);
        mpi_free(t4);
        mpi_free(t3);
        mpi_free(t2);
        mpi_free(t1);
        mpi_free(p);
        mpi_free(two);
        mpi_free(one);
}

/****************
 * Scalar multiplication of one point, with the integer fixed to 2.
 */
static void
duplicatePoint(point *P, point *R, ellipticCurve *base){

        MPI one,two,three,four,eight;
        MPI p,p_3,a;
        MPI t1,t2,t3,t4,t5,t6,t7;
        MPI aux;

        one = mpi_alloc_set_ui(1);
        two = mpi_alloc_set_ui(2);
        three = mpi_alloc_set_ui(3);
        four = mpi_alloc_set_ui(4);
        eight = mpi_alloc_set_ui(8);
        p = mpi_copy(base->p_);
        p_3 = mpi_alloc(mpi_get_nlimbs(p));
        mpi_sub_ui(p_3,p,3);
        a = mpi_copy(base->a_);
        t1 = mpi_alloc(mpi_get_nlimbs(p));
        t2 = mpi_alloc(mpi_get_nlimbs(p));
        t3 = mpi_alloc(mpi_get_nlimbs(p));
        t4 = mpi_alloc(mpi_get_nlimbs(p));
        t5 = mpi_alloc(mpi_get_nlimbs(p));
        t6 = mpi_alloc(mpi_get_nlimbs(p));
        t7 = mpi_alloc(mpi_get_nlimbs(p));
        aux= mpi_alloc(mpi_get_nlimbs(p));

        if( DBG_MPI ){log_info("Duplicate a point.\n");}

        t1 = mpi_copy(P->x_);//t1=x1
        t2 = mpi_copy(P->y_);//t2=y1
        t3 = mpi_copy(P->z_);//t3=z1

        if (!mpi_cmp_ui(t2,0) || !mpi_cmp_ui(t3,0)){//t2==0 | t3==0 => [1:1:0]
                if( DBG_MPI ){log_info("t2==0 | t3==0\n");}
                R->x_ = mpi_copy(one);
                R->y_ = mpi_copy(one);
                R->z_ = mpi_copy(mpi_alloc_set_ui(0));
        }
        else{
                mpi_fdiv_r(a,a,p);//a mod p
                if (!mpi_cmp(a,p_3)){//a==p-3
                        mpi_powm(t4,t3,two,p);//t4=t3^2 mod p
                        mpi_subm(t5,t1,t4,p);//t5=t1-t4 mod p
                        mpi_addm(t4,t1,t4,p);//t4=t1+t4 mod p
                        mpi_mulm(t5,t4,t5,p);//t5=t4*t5 mod p
                        mpi_mulm(t4,three,t5,p);//t4=3*t5 mod p
                }
                else{
                        t4 = mpi_copy(a);//t4=a
                        mpi_powm(t5,t3,two,p);//t5=t3^2 mod p
                        mpi_powm(t5,t5,two,p);//t5=t5^2 mod p
                        mpi_mulm(t5,t4,t5,p);//t5=t4*t5 mod p
                        mpi_powm(t4,t1,two,p);//t4=t1^2 mod p
                        mpi_mulm(t4,three,t4,p);//t4=3*t4 mod p
                        mpi_addm(t4,t4,t5,p);//t4=t4+t5 mod p
                }
                if( DBG_MPI ){log_info("t2!=0 & t3!=0\n");}
                mpi_mulm(t3,t2,t3,p);//t3=t2*t3 mod p
                mpi_mulm(t3,two,t3,p);//t3=2*t3 mod p 
                mpi_powm(aux,t2,two,p);//t2=t2^2 mod p
                t2 = mpi_copy(aux);
                mpi_mulm(t5,t1,t2,p);//t5=t1*t2 mod p
                mpi_mulm(t5,four,t5,p);//t5=4*t5 mod p
                mpi_powm(t1,t4,two,p);//t1=t4^2 mod p
                mpi_mulm(aux,two,t5,p);
                mpi_subm(t1,t1,aux,p);//t1=t1-2*t5 mod p
                mpi_powm(aux,t2,two,p);//t2=t2^2 mod p
                t2 = mpi_copy(aux);
                mpi_mulm(t2,eight,t2,p);//t2=8*t2 mod p
                mpi_subm(t5,t5,t1,p);//t5=t5-t1 mod p
                mpi_mulm(t5,t4,t5,p);//t5=t4*t5 mod p
                mpi_subm(t2,t5,t2,p);//t2=t5-t2 mod p

                R->x_ = mpi_copy(t1);
                R->y_ = mpi_copy(t2);
                R->z_ = mpi_copy(t3);
        }
        if( DBG_MPI ){log_info("Duplicated point.\n");}

        mpi_free(aux);
        mpi_free(t7);
        mpi_free(t6);
        mpi_free(t5);
        mpi_free(t4);
        mpi_free(t3);
        mpi_free(t2);
        mpi_free(t1);
        mpi_free(p);
        mpi_free(p_3);
        mpi_free(a);
        mpi_free(eight);
        mpi_free(four);
        mpi_free(three);
        mpi_free(two);
        mpi_free(one);

}

/****************
 * The point inversion over F_p
 * is a simple modular inversion
 * of the Y coordinate.
 */
static void
invertPoint(point *P, ellipticCurve *base){

        mpi_subm(P->y_,base->p_,P->y_,base->p_);//y=p-y mod p
}

/****************
 * Auxiliar function to made easy a struct copy.
 */
static point
point_copy(point P){
        point R;

        R.x_ = mpi_copy(P.x_);
        R.y_ = mpi_copy(P.y_);
        R.z_ = mpi_copy(P.z_);

        return R;
}

/****************
 * Made easy the free memory for a point struct.
 */
static void
point_free(point *P){

        mpi_free(P->x_);
        mpi_free(P->y_);
        mpi_free(P->z_);
}

/****************
 * Turn a projective coordinate to affine, return 0 (or 1 in error case).
 * Needed to verify a signature.
 *
 * y_coordinate it is never used, we could do without it. //!!
 */
static int 
point_affine(point *P, MPI x, MPI y, ellipticCurve *base){

        //MPI z;
        MPI z1,z2,z3;

        z1 = mpi_alloc(0);
        z2 = mpi_alloc(0);
        z3 = mpi_alloc(0);

        if (PointAtInfinity(*P)){
                if( DBG_CIPHER )log_info("Affine: Point at Infinity does NOT exist in the affine plane!\n");
                return 1;
	}

        mpi_invm(z1,P->z_,base->p_);    //      z1 =Z^{-1} (mod p)
        mpi_mulm(z2,z1,z1,base->p_);    //      z2 =Z^(-2) (mod p)
        mpi_mulm(z3,z2,z1,base->p_);    //      z3 =Z^(-3) (mod p)
        mpi_mulm(x,P->x_,z2,base->p_);
        mpi_mulm(y,P->y_,z3,base->p_);

        mpi_free(z1);
        mpi_free(z2);
        mpi_free(z3);
        return 0;
}

/****************
 * Auxiliar function to made easy a struct copy.
 */
static ellipticCurve
curve_copy(ellipticCurve E){

        ellipticCurve R;

        R.p_ = mpi_copy(E.p_);
        R.a_ = mpi_copy(E.a_);
        R.b_ = mpi_copy(E.b_);
        R.G = point_copy(E.G);
        R.n_ = mpi_copy(E.n_);

        return R;
}

/****************
 * Made easy the free memory for a setup struct.
 */
static void
curve_free(ellipticCurve *E){
        mpi_free(E->p_);
        mpi_free(E->a_);
        mpi_free(E->b_);
        point_free(&E->G);
        mpi_free(E->n_);
}

/****************
 * Boolean generator to choose between to coordinates.
 */
static MPI
gen_bit(){

        MPI aux = mpi_alloc_set_ui(0);

        //Get one random bit, with less security level, and translate it to an MPI.
        mpi_set_buffer( aux, get_random_bits( 1, 0, 1 ), 1, 0 );//gen_k(...)

        return aux;//b;
}

/****************
 * Solve the right side of the equation that define a curve.
 */
static MPI
gen_y_2(MPI x, ellipticCurve *base){

        MPI three;
        MPI x_3,ax,axb,y;
        MPI a,b,p;

        three = mpi_alloc_set_ui(3);
        a = mpi_copy(base->a_);
        b = mpi_copy(base->b_),
        p = mpi_copy(base->p_);
        x_3 = mpi_alloc(mpi_get_nlimbs(p));
        ax = mpi_alloc(mpi_get_nlimbs(p));
        axb = mpi_alloc(mpi_get_nlimbs(p));
        y = mpi_alloc(mpi_get_nlimbs(p));

        if( DBG_MPI )log_info("solving an elliptic equation.\n");

        mpi_powm(x_3,x,three,p);//x_3=x^3 mod p
        mpi_mulm(ax,a,x,p);//ax=a*x mod p
        mpi_addm(axb,ax,b,p);//axb=ax+b mod p
        mpi_addm(y,x_3,axb,p);//y=x^3+ax+b mod p

        if( DBG_MPI )log_info("solved.\n");

        return y;//the quadratic value of the coordinate if it exist.
}

//Function to solve an IFP ECElGamal weakness:
// sha256_hashing()
// aes256_encrypting()
// aes356_decrypting()

/****************
 * Compute 256 bit hash value from input MPI.
 * Use SHA256 Algorithm.
 */
static void 
sha256_hashing(MPI input, MPI *output){ // 

        int sign;
        byte *hash_inp_buf; 
        byte hash_out_buf[32]; 
        MD_HANDLE hash = md_open(8,1);//algo SHA256 in secure mode

        unsigned int nbytes;

        hash_inp_buf = mpi_get_secure_buffer( input, &nbytes, &sign );//convert MPI input to string

        md_write( hash, hash_inp_buf, nbytes );//hashing input string
        wipememory( hash_inp_buf, sizeof hash_inp_buf ); // burn temp value 
        xfree(hash_inp_buf);

        md_digest(hash, 8, hash_out_buf, 32);
        mpi_set_buffer( *output, hash_out_buf, 32, 0 );// convert 256 bit digest to MPI

        wipememory( hash_out_buf, sizeof hash_out_buf ); // burn temp value 
        md_close(hash);// destroy and free hash state.

}

/****************
 * Encrypt input MPI.
 * Use AES256 algorithm.
 */

static void 
aes256_encrypting(MPI key, MPI input, MPI *output){ // 

        int sign;
        byte *key_buf; 
        byte *cipher_buf; 

        unsigned int keylength;
        unsigned int nbytes;


        CIPHER_HANDLE cipher = cipher_open(9,CIPHER_MODE_CFB,1);//algo AES256 CFB mode in secure memory
        cipher_setiv( cipher, NULL, 0 ); // Zero IV

        key_buf = mpi_get_secure_buffer( key, &keylength, &sign );//convert MPI key to string
        cipher_setkey( cipher, key_buf, keylength );
        wipememory( key_buf, sizeof key_buf ); // burn temp value 
        xfree(key_buf);

        cipher_buf = mpi_get_secure_buffer( input, &nbytes, &sign );//convert MPI input to string

        cipher_encrypt( cipher, cipher_buf+1, cipher_buf+1, nbytes-1);//
        cipher_close(cipher);// destroy and free cipher state.

        mpi_set_buffer( *output, cipher_buf, nbytes, 0 );// convert encrypted string to MPI
        wipememory( cipher_buf, sizeof cipher_buf ); // burn temp value 
        xfree(cipher_buf);
}

/****************
 * Decrypt input MPI.
 * Use AES256 algorithm.
 */

static void 
aes256_decrypting(MPI key, MPI input, MPI *output){ // 

        int sign;
        byte *key_buf; 
        byte *cipher_buf; 

        unsigned int keylength;
        unsigned int nbytes;


        CIPHER_HANDLE cipher = cipher_open(9,CIPHER_MODE_CFB,1);//algo AES256 CFB mode in secure memory
        cipher_setiv( cipher, NULL, 0 ); // Zero IV

        key_buf = mpi_get_secure_buffer( key, &keylength, &sign );//convert MPI input to string
        cipher_setkey( cipher, key_buf, keylength );
        wipememory( key_buf, sizeof key_buf ); // burn temp value 
        xfree(key_buf);

        cipher_buf = mpi_get_secure_buffer( input, &nbytes, &sign );//convert MPI input to string;

        cipher_decrypt( cipher, cipher_buf+1, cipher_buf+1, nbytes-1 );//
        cipher_close(cipher);// destroy and free cipher state.

        mpi_set_buffer( *output, cipher_buf, nbytes, 0 );// convert encrypted string to MPI
        wipememory( cipher_buf, sizeof cipher_buf ); // burn temp value 
        xfree(cipher_buf);
}
//End of IFP ECElGamal weakness functions.

/*********************************************
 **************  interface  ******************
 *********************************************/
int
ecc_generate( int algo, unsigned nbits, MPI *skey, MPI **retfactors )
{

        ECC_secret_key sk;

        if( !is_ECC(algo) )
	        return G10ERR_PUBKEY_ALGO;

        generateKey( &sk, nbits, retfactors );

        skey[0] = sk.E.p_;
        skey[1] = sk.E.a_;
        skey[2] = sk.E.b_;
        skey[3] = sk.E.G.x_;
        skey[4] = sk.E.G.y_;
        skey[5] = sk.E.G.z_;
        skey[6] = sk.E.n_;
        skey[7] = sk.Q.x_;
        skey[8] = sk.Q.y_;
        skey[9] = sk.Q.z_;
        skey[10] = sk.d;

        if( DBG_CIPHER ) {
	        progress('\n');

		log_mpidump("[ecc]  p= ", skey[0]);
	        log_mpidump("[ecc]  a= ", skey[1]);
	        log_mpidump("[ecc]  b= ", skey[2]);
	        log_mpidump("[ecc]  Gx= ", skey[3]);
	        log_mpidump("[ecc]  Gy= ", skey[4]);
	        log_mpidump("[ecc]  Gz= ", skey[5]);
	        log_mpidump("[ecc]  n= ", skey[6]);
	        log_mpidump("[ecc]  Qx= ", skey[7]);
	        log_mpidump("[ecc]  Qy= ", skey[8]);
	        log_mpidump("[ecc]  Qz= ", skey[9]);
	        log_mpidump("[ecc]  d= ", skey[10]);
        }

	if( DBG_CIPHER ){log_info("ECC key Generated.\n");}
        return 0;
}


int
ecc_check_secret_key( int algo, MPI *skey )
{
        ECC_secret_key sk;

        if( !is_ECC(algo) )
	        return G10ERR_PUBKEY_ALGO;
        if(!skey[0] || !skey[1] || !skey[2] || !skey[3] || !skey[4] || !skey[5] || !skey[6] || !skey[7] || !skey[8] || !skey[9] || !skey[10])
	        return G10ERR_BAD_MPI;

        if( DBG_CIPHER ){log_info("ECC check secret key.\n");}
        sk.E.p_ = skey[0];
        sk.E.a_ = skey[1];
        sk.E.b_ = skey[2];
        sk.E.G.x_ = skey[3];
        sk.E.G.y_ = skey[4];
        sk.E.G.z_ = skey[5];
        sk.E.n_ = skey[6];
        sk.Q.x_ = skey[7];
        sk.Q.y_ = skey[8];
        sk.Q.z_ = skey[9];
        sk.d = skey[10];

        if( check_secret_key(&sk)){
                if( DBG_CIPHER )log_info("Bad check: Bad secret key.\n");
                return G10ERR_BAD_SECKEY;
        }
        return 0;
}



int
ecc_encrypt( int algo, MPI *resarr, MPI data, MPI *pkey )
{
        ECC_public_key pk;
        point R;

        if( algo != PUBKEY_ALGO_ECC && algo != PUBKEY_ALGO_ECC_E )
                return G10ERR_PUBKEY_ALGO;
        if( !data || !pkey[0] || !pkey[1] || !pkey[2] || !pkey[3] || !pkey[4] || !pkey[5] || !pkey[6] || !pkey[7] || !pkey[8] || !pkey[9])
	        return G10ERR_BAD_MPI;

        if( DBG_CIPHER ){log_info("ECC encrypt.\n");}
        pk.E.p_ = pkey[0];
        pk.E.a_ = pkey[1];
        pk.E.b_ = pkey[2];
        pk.E.G.x_ = pkey[3];
        pk.E.G.y_ = pkey[4];
        pk.E.G.z_ = pkey[5];
        pk.E.n_ = pkey[6];
        pk.Q.x_ = pkey[7];
        pk.Q.y_ = pkey[8];
        pk.Q.z_ = pkey[9];

        R.x_ = resarr[0] = mpi_alloc( mpi_get_nlimbs( pk.Q.x_ ) );
        R.y_ = resarr[1] = mpi_alloc( mpi_get_nlimbs( pk.Q.y_ ) );
        R.z_ = resarr[2] = mpi_alloc( mpi_get_nlimbs( pk.Q.z_ ) );
        resarr[3] = mpi_alloc( mpi_get_nlimbs( pk.E.p_ ) );

        doEncrypt(data, &pk, &R, resarr[3]);

	resarr[0] = mpi_copy(R.x_);
	resarr[1] = mpi_copy(R.y_);
	resarr[2] = mpi_copy(R.z_);
        return 0;
}

int
ecc_decrypt( int algo, MPI *result, MPI *data, MPI *skey )
{
        ECC_secret_key sk;
        point R;

        if( algo != PUBKEY_ALGO_ECC && algo != PUBKEY_ALGO_ECC_E )
                return G10ERR_PUBKEY_ALGO;
        if( !data[0] || !data[1] || !data[2] || !data[3] || !skey[0] || !skey[1] || !skey[2] || !skey[3] || !skey[4] || !skey[5] || !skey[6] || !skey[7] || !skey[8] || !skey[9] || !skey[10])
	        return G10ERR_BAD_MPI;

        if( DBG_CIPHER ){log_info("ECC decrypt.\n");}
        R.x_ = data[0];
        R.y_ = data[1];
        R.z_ = data[2];
        sk.E.p_ = skey[0];
        sk.E.a_ = skey[1];
        sk.E.b_ = skey[2];
        sk.E.G.x_ = skey[3];
        sk.E.G.y_ = skey[4];
        sk.E.G.z_ = skey[5];
        sk.E.n_ = skey[6];
        sk.Q.x_ = skey[7];
        sk.Q.y_ = skey[8];
        sk.Q.z_ = skey[9];
        sk.d = skey[10];

        *result = mpi_alloc_secure( mpi_get_nlimbs( sk.E.p_ ) );
        *result = decrypt( *result, &sk, R, data[3]);
        return 0;
}

int
ecc_sign( int algo, MPI *resarr, MPI data, MPI *skey )
{
        ECC_secret_key sk;

        if( algo != PUBKEY_ALGO_ECC && algo != PUBKEY_ALGO_ECC_S )
                return G10ERR_PUBKEY_ALGO;
        if( !data || !skey[0] || !skey[1] || !skey[2] || !skey[3] || !skey[4] || !skey[5] || !skey[6] || !skey[7] || !skey[8] || !skey[9] || !skey[10])
	        return G10ERR_BAD_MPI;

        sk.E.p_ = skey[0];
        sk.E.a_ = skey[1];
        sk.E.b_ = skey[2];
        sk.E.G.x_ = skey[3];
        sk.E.G.y_ = skey[4];
        sk.E.G.z_ = skey[5];
        sk.E.n_ = skey[6];
        sk.Q.x_ = skey[7];
        sk.Q.y_ = skey[8];
        sk.Q.z_ = skey[9];
        sk.d = skey[10];

        resarr[0] = mpi_alloc( mpi_get_nlimbs( sk.E.p_ ) );
        resarr[1] = mpi_alloc( mpi_get_nlimbs( sk.E.p_ ) );
        sign( data, &sk, &resarr[0], &resarr[1]);
        return 0;
}

int
ecc_verify( int algo, MPI hash, MPI *data, MPI *pkey )
{
        ECC_public_key pk;

        if( algo != PUBKEY_ALGO_ECC && algo != PUBKEY_ALGO_ECC_S )
                return G10ERR_PUBKEY_ALGO;
        if( !data[0] || !data[1] || !hash || !pkey[0] || !pkey[1] || !pkey[2] || !pkey[3] || !pkey[4] || !pkey[5] || !pkey[6] || !pkey[7] || !pkey[8] || !pkey[9])
	        return G10ERR_BAD_MPI;

        if( DBG_CIPHER ){log_info("ECC verify.\n");}
        pk.E.p_ = pkey[0];
        pk.E.a_ = pkey[1];
        pk.E.b_ = pkey[2];
        pk.E.G.x_ = pkey[3];
        pk.E.G.y_ = pkey[4];
        pk.E.G.z_ = pkey[5];
        pk.E.n_ = pkey[6];
        pk.Q.x_ = pkey[7];
        pk.Q.y_ = pkey[8];
        pk.Q.z_ = pkey[9];

        if( !verify( hash, &pk, data[0], data[1]) )
	        return G10ERR_BAD_SIGN;
        return 0;
}



unsigned int
ecc_get_nbits( int algo, MPI *pkey )
{
        if ( !is_ECC(algo) ){
                return 0;
        }
        if( DBG_CIPHER ){log_info("ECC get nbits.\n");}

        if( DBG_CIPHER ) {
	        progress('\n');

		log_mpidump("[ecc]  p= ", pkey[0]);
	        log_mpidump("[ecc]  a= ", pkey[1]);
	        log_mpidump("[ecc]  b= ", pkey[2]);
	        log_mpidump("[ecc]  Gx= ", pkey[3]);
	        log_mpidump("[ecc]  Gy= ", pkey[4]);
	        log_mpidump("[ecc]  Gz= ", pkey[5]);
	        log_mpidump("[ecc]  n= ", pkey[6]);
	        log_mpidump("[ecc]  Qx= ", pkey[7]);
	        log_mpidump("[ecc]  Qy= ", pkey[8]);
	        log_mpidump("[ecc]  Qz= ", pkey[9]);
        }

        return mpi_get_nbits( pkey[0] );
}

const char *
ecc_get_info( int algo, int *npkey, int *nskey, int *nenc, int *nsig, int *use )
{
    *npkey = 10;
    *nskey = 11;
    *nenc = 4;
    *nsig = 2;

    if( DBG_CIPHER ){log_info("ECC get info.\n");}
    switch( algo ) {
      case PUBKEY_ALGO_ECC:
        *use = PUBKEY_USAGE_SIG|PUBKEY_USAGE_ENC;
        return "ECC";
      case PUBKEY_ALGO_ECC_S:
        *use = PUBKEY_USAGE_SIG;
        return "ECDSA";
      case PUBKEY_ALGO_ECC_E:
        *use = PUBKEY_USAGE_ENC;
        return "ECELG";
      default: *use = 0; return NULL;
    }
}
