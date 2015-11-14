// Code by: B-Con (http://b-con.us) 
// Released under the GNU GPL 
// MD5 Hash Digest implementation (little endian byte order) 

#include <stdio.h> 

// Signed variables are for wimps 
#define uchar unsigned char 
#define uint unsigned int 

// DBL_INT_ADD treats two unsigned ints a and b as one 64-bit integer and adds c to it
#define ROTLEFT(a,b) ((a << b) | (a >> (32-b))) 
#define DBL_INT_ADD(a,b,c) if (a > 0xffffffff - c) ++b; a += c; 


typedef struct { 
   uchar data[64]; 
   uint datalen; 
   uint bitlen[2]; 
   uint state[5]; 
   uint k[4]; 
} SHA1_CTX; 


void sha1_transform(SHA1_CTX *ctx, uchar data[]) 
{  
   uint a,b,c,d,e,i,j,t,m[80]; 
      
   for (i=0,j=0; i < 16; ++i, j += 4) 
      m[i] = (data[j] << 24) + (data[j+1] << 16) + (data[j+2] << 8) + (data[j+3]); 
   for ( ; i < 80; ++i) { 
      m[i] = (m[i-3] ^ m[i-8] ^ m[i-14] ^ m[i-16]); 
      m[i] = (m[i] << 1) | (m[i] >> 31); 
   }  
   
   a = ctx->state[0]; 
   b = ctx->state[1]; 
   c = ctx->state[2]; 
   d = ctx->state[3]; 
   e = ctx->state[4]; 
   
   for (i=0; i < 20; ++i) { 
      t = ROTLEFT(a,5) + ((b & c) ^ (~b & d)) + e + ctx->k[0] + m[i]; 
      e = d; 
      d = c; 
      c = ROTLEFT(b,30); 
      b = a; 
      a = t; 
   }  
   for ( ; i < 40; ++i) { 
      t = ROTLEFT(a,5) + (b ^ c ^ d) + e + ctx->k[1] + m[i]; 
      e = d; 
      d = c; 
      c = ROTLEFT(b,30); 
      b = a; 
      a = t; 
   }  
   for ( ; i < 60; ++i) { 
      t = ROTLEFT(a,5) + ((b & c) ^ (b & d) ^ (c & d))  + e + ctx->k[2] + m[i]; 
      e = d; 
      d = c; 
      c = ROTLEFT(b,30); 
      b = a; 
      a = t; 
   }  
   for ( ; i < 80; ++i) { 
      t = ROTLEFT(a,5) + (b ^ c ^ d) + e + ctx->k[3] + m[i]; 
      e = d; 
      d = c; 
      c = ROTLEFT(b,30); 
      b = a; 
      a = t; 
   }  
   
   ctx->state[0] += a; 
   ctx->state[1] += b; 
   ctx->state[2] += c; 
   ctx->state[3] += d; 
   ctx->state[4] += e; 
}  

void sha1_init(SHA1_CTX *ctx) 
{  
   ctx->datalen = 0; 
   ctx->bitlen[0] = 0; 
   ctx->bitlen[1] = 0; 
   ctx->state[0] = 0x67452301; 
   ctx->state[1] = 0xEFCDAB89; 
   ctx->state[2] = 0x98BADCFE; 
   ctx->state[3] = 0x10325476; 
   ctx->state[4] = 0xc3d2e1f0; 
   ctx->k[0] = 0x5a827999; 
   ctx->k[1] = 0x6ed9eba1; 
   ctx->k[2] = 0x8f1bbcdc; 
   ctx->k[3] = 0xca62c1d6; 
}  

void sha1_update(SHA1_CTX *ctx, uchar data[], uint len) 
{  
   uint t,i;
   
   for (i=0; i < len; ++i) { 
      ctx->data[ctx->datalen] = data[i]; 
      ctx->datalen++; 
      if (ctx->datalen == 64) { 
         sha1_transform(ctx,ctx->data); 
         DBL_INT_ADD(ctx->bitlen[0],ctx->bitlen[1],512); 
         ctx->datalen = 0; 
      }  
   }  
}  

