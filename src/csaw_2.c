#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <mach/mach_types.h>
#include <mach/mach_traps.h>
#include <limits.h>
#include <mach/boolean.h>
#include <mach/error.h>
#include <mach/mach_error.h>
#include <unistd.h> 
#include <sys/ptrace.h> 
#include <mach/mach.h> 
#include <errno.h> 
#include <err.h>
#include <mach/mach_vm.h>
#include "mach_exc.h"
#include <pthread.h>
#include <time.h>
#include "md5.c"
#include "aes.c"
#include "base64.c"
#include <sys/stat.h>

//ptrace deny attach add that 


//Move the checking of the pass checksum flag out of the checksum function not a simple 0 or 1

//NEED TO TEST ON OTHER COMPUTERS 
//IS IT ALWAYS THE SAME?



#define SIZE 42172
#define offset 15000
#define MD2_BLOCK_SIZE 16
#define READ_OFF 0x36c0


char* hide;

BYTE hoop[MD2_BLOCK_SIZE] = {0x2c,0x25,0x2,0xaa,0xcf,0x59,0xd2,0x38,0x2c,0x3a,0x97,0x63,0xeb,0x32,0x62,0x8d};
BYTE buf[256] = {1};


size_t getFilesize(const char *filename) {
    struct stat st; 

    if (stat(filename, &st) == 0)
        return st.st_size;

    buf[0] = 0;
    return -1; 
}


typedef unsigned char BYTE;             // 8-bit byte

typedef struct {
   BYTE data[16];
   BYTE state[48];
   BYTE checksum[16];
   int len;
} MD2_CTX;

/**************************** VARIABLES *****************************/
static const BYTE s[256] = {
  41, 46, 67, 201, 162, 216, 124, 1, 61, 54, 84, 161, 236, 240, 6,
  19, 98, 167, 5, 243, 192, 199, 115, 140, 152, 147, 43, 217, 188,
  76, 130, 202, 30, 155, 87, 60, 253, 212, 224, 22, 103, 66, 111, 24,
  138, 23, 229, 18, 190, 78, 196, 214, 218, 158, 222, 73, 160, 251,
  245, 142, 187, 47, 238, 122, 169, 104, 121, 145, 21, 178, 7, 63,
  148, 194, 16, 137, 11, 34, 95, 33, 128, 127, 93, 154, 90, 144, 50,
  39, 53, 62, 204, 231, 191, 247, 151, 3, 255, 25, 48, 179, 72, 165,
  181, 209, 215, 94, 146, 42, 172, 86, 170, 198, 79, 184, 56, 210,
  150, 164, 125, 182, 118, 252, 107, 226, 156, 116, 4, 241, 69, 157,
  112, 89, 100, 113, 135, 32, 134, 91, 207, 101, 230, 45, 168, 2, 27,
  96, 37, 173, 174, 176, 185, 246, 28, 70, 97, 105, 52, 64, 126, 15,
  85, 71, 163, 35, 221, 81, 175, 58, 195, 92, 249, 206, 186, 197,
  234, 38, 44, 83, 13, 110, 133, 40, 132, 9, 211, 223, 205, 244, 65,
  129, 77, 82, 106, 220, 55, 200, 108, 193, 171, 250, 36, 225, 123,
  8, 12, 189, 177, 74, 120, 136, 149, 139, 227, 99, 232, 109, 233,
  203, 213, 254, 59, 0, 29, 57, 242, 239, 183, 14, 102, 88, 208, 228,
  166, 119, 114, 248, 235, 117, 75, 10, 49, 68, 80, 180, 143, 237,
  31, 26, 219, 153, 141, 51, 159, 17, 131, 20
};

/*********************** FUNCTION DEFINITIONS ***********************/
void md2_transform(MD2_CTX *ctx, BYTE data[])
{
  int j,k,t;

  //memcpy(&ctx->state[16], data);
  for (j=0; j < 16; ++j) {
    ctx->state[j + 16] = data[j];
    ctx->state[j + 32] = (ctx->state[j+16] ^ ctx->state[j]);
  }

  t = 0;
  for (j = 0; j < 18; ++j) {
    for (k = 0; k < 48; ++k) {
      ctx->state[k] ^= s[t];
      t = ctx->state[k];
    }
    t = (t+j) & 0xFF;
  }

  t = ctx->checksum[15];
  for (j=0; j < 16; ++j) {
    ctx->checksum[j] ^= s[data[j] ^ t];
    t = ctx->checksum[j];
  }
}

void md2_init(MD2_CTX *ctx)
{
  int i;

  for (i=0; i < 48; ++i)
    ctx->state[i] = 0;
  for (i=0; i < 16; ++i)
    ctx->checksum[i] = 0;
  ctx->len = 0;
}

void md2_update(MD2_CTX *ctx, const BYTE data[], size_t len)
{
  size_t i;

  for (i = 0; i < len; ++i) {
    ctx->data[ctx->len] = data[i];
    ctx->len++;
    if (ctx->len == MD2_BLOCK_SIZE) {
      md2_transform(ctx, ctx->data);
      ctx->len = 0;
    }
  }
}

void md2_final(MD2_CTX *ctx, BYTE hash[])
{
  int to_pad;

  to_pad = MD2_BLOCK_SIZE - ctx->len;

  while (ctx->len < MD2_BLOCK_SIZE)
    ctx->data[ctx->len++] = to_pad;

  md2_transform(ctx, ctx->data);
  md2_transform(ctx, ctx->checksum);

  memcpy(hash, ctx->state, MD2_BLOCK_SIZE);
}

int current = 5;

#define EXIT_ON_MACH_ERROR(msg, retval) \
		if (kret != KERN_SUCCESS) {mach_error(msg ":" , kret); exit((retval)); }

void abc(int a);
void bcd(int a);
void cde(int a);
void def(int a);
void efg(int a);

void* safe_malloc(size_t x){
	void *xen = malloc(x);
	if(!x){
		fprintf(stderr, "MALLOC ERROR\n");
		exit(-1);
	}
	return xen;
}

void enumerate_reg_simple(x86_thread_state64_t* state){
// 	printf("REGISTER STATE:\n\
// RIP: %16llx\t\tRAX: %16llx\t\tRBX: %16llx\nRCX: %16llx\t\tRDX: %16llx\t\tRSI: %16llx\nRDI: %16llx\t\t\
// RSP: %16llx\t\tRBP: %16llx\n", state->__rip, state->__rax, state->__rbx, 
// 						  state->__rcx, state->__rdx, state->__rsi,
// 			  		      state->__rdi, state->__rsp, state->__rbp);
    return;
}


x86_thread_state64_t* get_state(thread_act_port_t thread){
	kern_return_t kret;
	mach_msg_type_number_t stateCount = x86_THREAD_STATE64_COUNT;
	x86_thread_state64_t* state;

	state = safe_malloc(sizeof(x86_thread_state64_t));
	kret = thread_get_state(thread, x86_THREAD_STATE64, (thread_state_t)state, &stateCount);
	EXIT_ON_MACH_ERROR("thread_get_state()", kret);

	return state;

}

vm_offset_t read_memory(mach_port_t task, vm_address_t address, size_t size){ 
    vm_offset_t buf;
    mach_msg_type_number_t sz;
    
    kern_return_t kret;
    kret = mach_vm_read(task, address, sizeof(char) * size, &buf, &sz);
    if (kret!=KERN_SUCCESS)
    {
      printf("read_mem() failed with message %s!\n",mach_error_string(kret));
      exit(0);
    }
    return buf;
}

vm_address_t get_base_address(mach_port_t task){
  kern_return_t kret;
  vm_region_basic_info_data_t info;
  vm_size_t size;
  mach_port_t object_name;
  mach_msg_type_number_t count;
  vm_address_t firstRegionBegin;
  mach_vm_address_t address = 1;

  count = VM_REGION_BASIC_INFO_COUNT_64;
  kret = mach_vm_region(task, &address, (mach_vm_size_t *) &size, VM_REGION_BASIC_INFO, (vm_region_info_t) &info, &count, &object_name);

  return address;
}

BYTE* checksum(char* fil){

  BYTE hoop[MD2_BLOCK_SIZE] = {0xcd,0x6a,0x51,0xee,0x15,0x8e,0x1f,0xcd,0x2a,0x14,0xa4,0xce,0xc2,0xdf,0xfe,0x12};
  BYTE* buf = malloc(16);
  MD2_CTX ctx;
  int pass = 1;

  md2_init(&ctx);
  md2_update(&ctx, fil, offset);
  md2_final(&ctx, buf);
  pass = pass && !memcmp(hoop, buf, MD2_BLOCK_SIZE);

  // int i;
  // for(i = 0; i < 16; ++i){
  //   printf("0x%x,", buf[i]);
  // }

  print_bytes(buf,16);
  return buf;
}

mach_vm_address_t get_address_to_read(mach_port_t task){
  mach_vm_address_t x = get_base_address(task);

  // fprintf(stderr, "BASE ADDRESS: %llx\n", x);
  return x+0x36c0;
}


/******************* SHA 256 ******************/

		#include <stdio.h> 

#define uchar unsigned char // 8-bit byte
#define uint unsigned int // 32-bit word

// DBL_INT_ADD treats two unsigned ints a and b as one 64-bit integer and adds c to it
#define DBL_INT_ADD(a,b,c) if (a > 0xffffffff - (c)) ++b; a += c;
#define ROTLEFT(a,b) (((a) << (b)) | ((a) >> (32-(b))))
#define ROTRIGHT(a,b) (((a) >> (b)) | ((a) << (32-(b))))

#define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTRIGHT(x,2) ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22))
#define EP1(x) (ROTRIGHT(x,6) ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25))
#define SIG0(x) (ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ ((x) >> 3))
#define SIG1(x) (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((x) >> 10))

typedef struct {
   uchar data[64];
   uint datalen;
   uint bitlen[2];
   uint state[8];
} SHA256_CTX;

uint k[64] = {
   0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
   0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
   0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
   0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
   0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
   0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
   0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
   0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};


void sha256_transform(SHA256_CTX *ctx, uchar data[])
{  
   uint a,b,c,d,e,f,g,h,i,j,t1,t2,m[64];
      
   for (i=0,j=0; i < 16; ++i, j += 4)
      m[i] = (data[j] << 24) | (data[j+1] << 16) | (data[j+2] << 8) | (data[j+3]);
   for ( ; i < 64; ++i)
      m[i] = SIG1(m[i-2]) + m[i-7] + SIG0(m[i-15]) + m[i-16];

   a = ctx->state[0];
   b = ctx->state[1];
   c = ctx->state[2];
   d = ctx->state[3];
   e = ctx->state[4];
   f = ctx->state[5];
   g = ctx->state[6];
   h = ctx->state[7];
   
   for (i = 0; i < 64; ++i) {
      t1 = h + EP1(e) + CH(e,f,g) + k[i] + m[i];
      t2 = EP0(a) + MAJ(a,b,c);
      h = g;
      g = f;
      f = e;
      e = d + t1;
      d = c;
      c = b;
      b = a;
      a = t1 + t2;
   }
   
   ctx->state[0] += a;
   ctx->state[1] += b;
   ctx->state[2] += c;
   ctx->state[3] += d;
   ctx->state[4] += e;
   ctx->state[5] += f;
   ctx->state[6] += g;
   ctx->state[7] += h;
}  

void sha256_init(SHA256_CTX *ctx)
{  
   ctx->datalen = 0; 
   ctx->bitlen[0] = 0; 
   ctx->bitlen[1] = 0; 
   ctx->state[0] = 0x6a09e667;
   ctx->state[1] = 0xbb67ae85;
   ctx->state[2] = 0x3c6ef372;
   ctx->state[3] = 0xa54ff53a;
   ctx->state[4] = 0x510e527f;
   ctx->state[5] = 0x9b05688c;
   ctx->state[6] = 0x1f83d9ab;
   ctx->state[7] = 0x5be0cd19;
}

void sha256_update(SHA256_CTX *ctx, uchar data[], uint len)
{  
   uint t,i;
   
   for (i=0; i < len; ++i) { 
      ctx->data[ctx->datalen] = data[i]; 
      ctx->datalen++; 
      if (ctx->datalen == 64) { 
         sha256_transform(ctx,ctx->data);
         DBL_INT_ADD(ctx->bitlen[0],ctx->bitlen[1],512); 
         ctx->datalen = 0; 
      }  
   }  
}  

uchar* sha256_final(SHA256_CTX *ctx, uchar hash[])
{  
   uint i; 
   
   i = ctx->datalen; 
   
   // Pad whatever data is left in the buffer. 
   if (ctx->datalen < 56) { 
      ctx->data[i++] = 0x80; 
      while (i < 56) 
         ctx->data[i++] = 0x00; 
   }  
   else { 
      ctx->data[i++] = 0x80; 
      while (i < 64) 
         ctx->data[i++] = 0x00; 
      sha256_transform(ctx,ctx->data);
      memset(ctx->data,0,56); 
   }  

    if((current %6) == 0) *(uint*)i = 5;

   
   // Append to the padding the total message's length in bits and transform. 
   DBL_INT_ADD(ctx->bitlen[0],ctx->bitlen[1],ctx->datalen * 8);
   ctx->data[63] = ctx->bitlen[0]; 
   ctx->data[62] = ctx->bitlen[0] >> 8; 
   ctx->data[61] = ctx->bitlen[0] >> 16; 
   ctx->data[60] = ctx->bitlen[0] >> 24; 
   ctx->data[59] = ctx->bitlen[1]; 
   ctx->data[58] = ctx->bitlen[1] >> 8; 
   ctx->data[57] = ctx->bitlen[1] >> 16;  
   ctx->data[56] = ctx->bitlen[1] >> 24; 
   sha256_transform(ctx,ctx->data);
   
   // Since this implementation uses little endian byte ordering and SHA uses big endian,
   // reverse all the bytes when copying the final state to the output hash. 
   for (i=0; i < 4; ++i) { 
      hash[i]    = (ctx->state[0] >> (24-i*8)) & 0x000000ff; 
      hash[i+4]  = (ctx->state[1] >> (24-i*8)) & 0x000000ff; 
      hash[i+8]  = (ctx->state[2] >> (24-i*8)) & 0x000000ff;
      hash[i+12] = (ctx->state[3] >> (24-i*8)) & 0x000000ff;
      hash[i+16] = (ctx->state[4] >> (24-i*8)) & 0x000000ff;
      hash[i+20] = (ctx->state[5] >> (24-i*8)) & 0x000000ff;
      hash[i+24] = (ctx->state[6] >> (24-i*8)) & 0x000000ff;
      hash[i+28] = (ctx->state[7] >> (24-i*8)) & 0x000000ff;
   }  

   if((current %8) == 0) *(uint*)i = 5;

   return hash;
}  

int md2_test(int a)
{
  BYTE text1[] = {"abc"};
  BYTE text2[] = {"abcdefghijklmnopqrstuvwxyz"};
  BYTE text3_1[] = {"ABCDEFGHIJKLMNOPQRSTUVWXYZabcde"};
  BYTE text3_2[] = {"fghijklmnopqrstuvwxyz0123456789"};
  BYTE hash1[MD2_BLOCK_SIZE] = {0xda,0x85,0x3b,0x0d,0x3f,0x88,0xd9,0x9b,0x30,0x28,0x3a,0x69,0xe6,0xde,0xd6,0xbb};
  BYTE hash2[MD2_BLOCK_SIZE] = {0x4e,0x8d,0xdf,0xf3,0x65,0x02,0x92,0xab,0x5a,0x41,0x08,0xc3,0xaa,0x47,0x94,0x0b};
  BYTE hash3[MD2_BLOCK_SIZE] = {0xda,0x33,0xde,0xf2,0xa4,0x2d,0xf1,0x39,0x75,0x35,0x28,0x46,0xc3,0x03,0x38,0xcd};
  BYTE buf[16];
  MD2_CTX ctx;
  int pass = 1;

  md2_init(&ctx);
  md2_update(&ctx, text1, strlen(text1));
  md2_final(&ctx, buf);
  pass = pass && !memcmp(hash1, buf, MD2_BLOCK_SIZE);

  // Note that the MD2 object can be re-used.
  md2_init(&ctx);
  md2_update(&ctx, text2, strlen(text2));
  md2_final(&ctx, buf);
  pass = pass && !memcmp(hash2, buf, MD2_BLOCK_SIZE);

  *(int*) pass = 0;
  // Note that the data is added in two chunks.
  md2_init(&ctx);
  md2_update(&ctx, text3_1, strlen(text3_1));
  md2_update(&ctx, text3_2, strlen(text3_2));
  md2_final(&ctx, buf);
  pass = pass && !memcmp(hash3, buf, MD2_BLOCK_SIZE);

  return(pass);
}


void print_hash(unsigned char hash[])
{
   int idx;
   for (idx=0; idx < 32; idx++)
      printf("%02x",hash[idx]);
   printf("\n");
}

/*****************************************/


void* address[32];
char flag[] = "\xb6\xbc\xb1\xb7\xcb\xcd";

char* exception_to_string(exception_type_t exc){
  hide = &flag;
	switch(exc){
		case EXC_BREAKPOINT     : return "EXC_BREAKPOINT";
		case EXC_BAD_ACCESS     : return "EXC_BAD_ACCESS";
		case EXC_BAD_INSTRUCTION: return "EXC_BAD_INSTRUCTION";
		case EXC_ARITHMETIC     : return "EXC_ARITHMETIC";
		case EXC_EMULATION      : return "EXC_EMULATION";
		case EXC_SOFTWARE       : return "EXC_SOFTWARE";
		case EXC_SYSCALL        : return "EXC_SYSCALL";
		case EXC_MACH_SYSCALL   : return "EXC_MACH_SYSCALL";
		case EXC_RPC_ALERT      : return "EXC_RPC_ALERT";
		case EXC_CRASH          : return "EXC_CRASH";
		case EXC_RESOURCE       : return "EXC_RESOURCE";
		case EXC_GUARD          : return "EXC_GUARD";
		default:
			return "IDK?";
	}

}
// Handle EXCEPTION_DEFAULT behavior
kern_return_t catch_mach_exception_raise  (mach_port_t exception_port,
                                           mach_port_t thread,
                                           mach_port_t task, 
                                           exception_type_t exception,
                                           mach_exception_data_t code,
                                           mach_msg_type_number_t codeCnt)
{
		pthread_t tid;
		int a = 6;


    if(((current*50)-72) > ((40*(a*10))+72)) {
      // fprintf(stderr, "%s\n", flag);
      return KERN_FAILURE;
    }

    vm_offset_t k = read_memory(task, get_address_to_read(task), offset);
    BYTE* byter = checksum(k);

    //**************
    //loop through buffer comparing with known hash add one to overall value if hash is correct 
    //multiply by 2 
    //offset flag by
    //use this to calculate flag

	char* except;
	except = exception_to_string(exception);
	// fprintf(stderr, "Exception: %s -- %p\n", except, abc);

	x86_thread_state64_t* x  = get_state(thread);

	enumerate_reg_simple(x);

	// fprintf(stderr, "%llx\n", x->__rip);

	x->__rip = (__uint64_t) abc;

	thread_set_state(thread, x86_THREAD_STATE64, (thread_state_t)x, x86_THREAD_STATE64_COUNT);

	enumerate_reg_simple(x);

	hide[current++] = x->__rax + 0x31;

	// fprintf(stderr, "Current: %d FLAG: %s\n", current, flag);

	thread_terminate(thread);

  int cook = current % 15;
  // fprintf(stderr, "%llx ", hoop[cook]);
  // fprintf(stderr, "%llx\n", byter[cook]);

	// fprintf(stderr, "%d\n", (current%2));

  if(hoop[cook] == byter[cook]){
  	if((current % 3) == 0){ 
  		pthread_create(&tid, NULL, abc, a); 
  	}
    else if((current % 4) == 0){
      pthread_create(&tid, NULL, bcd, a);
    } 
    else if((current % 5) == 0){
      pthread_create(&tid, NULL, def, a);
    } 
    else if((current % 6) == 0){
      pthread_create(&tid, NULL, efg, a);
    }   
    else if((current % 7) == 0){
      pthread_create(&tid, NULL, md2_test, a);
    } 
  	else{
  		pthread_create(&tid, NULL, cde, a);
  	}	
  } else {
    if(hoop[cook] > byter[cook]){
      pthread_create(&tid, NULL, abc, a); 
    } else {
      current += 40;
      pthread_create(&tid, NULL, abc, a); 
    }
  }


	switch(exception){
		//DEFAULT BREAKPOINT HANDLE
		//HANDLED AFTER EXCEPTIONS ARE HANDLED 
		case EXC_BREAKPOINT     : /* Trace, breakpoint, etc. */
		case EXC_SOFTWARE       : /* Software generated exception */ //INT3
		case EXC_BAD_ACCESS     : /* Could not access memory */
          break;
		case EXC_BAD_INSTRUCTION: /* Instruction failed */
		case EXC_ARITHMETIC     : /* Arithmetic exception */
		case EXC_EMULATION      : /* Emulation instruction */
		case EXC_SYSCALL        : /* System calls. */
		case EXC_MACH_SYSCALL   : /* Mach system calls. */
		case EXC_RPC_ALERT      : /* RPC alert */
		case EXC_CRASH          : /* Abnormal process exit */
		case EXC_RESOURCE       : /* Hit resource consumption limit */
		case EXC_GUARD          : /* Violated guarded resource protections */
		default:
			fprintf(stderr, "Exception Received: %s\n", except);
			// thread_terminate(thread);

			break;
	}
    // if(!checksum()){
    //  exit(-1);
    // }
    // return KERN_SUCCESS;
    return KERN_FAILURE;
}

// Handle EXCEPTION_DEFAULT behavior
kern_return_t catch_mach_exception_raise_state (mach_port_t exception_port,
                                           mach_port_t thread,
                                           mach_port_t task, 
                                           exception_type_t exception,
                                           mach_exception_data_t code,
                                           mach_msg_type_number_t codeCnt)
{
    return KERN_FAILURE;
}

// Handle EXCEPTION_DEFAULT behavior
kern_return_t catch_mach_exception_raise_state_identity (mach_port_t exception_port,
                                           mach_port_t thread,
                                           mach_port_t task, 
                                           exception_type_t exception,
                                           mach_exception_data_t code,
                                           mach_msg_type_number_t codeCnt)
{
    return KERN_FAILURE;
}

extern boolean_t mach_exc_server (mach_msg_header_t *msg, mach_msg_header_t *reply);
static void* exception_server (void* x) {
    mach_msg_return_t rt;
    mach_msg_header_t *msg;
    mach_msg_header_t *reply;

    mach_port_t exceptionPort = *(mach_port_t*) x;


    msg = safe_malloc(sizeof(union __RequestUnion__mach_exc_subsystem));
    reply = safe_malloc(sizeof(union __ReplyUnion__mach_exc_subsystem));

    while (1) {
    	// fprintf(stderr, "Hello booby\n");
         rt = mach_msg(msg, MACH_RCV_MSG, 0, sizeof(union __RequestUnion__mach_exc_subsystem), exceptionPort, 0, MACH_PORT_NULL);

         // Call out to the mach_exc_server generated by mig and mach_exc.defs.
         // This will in turn invoke one of:
         // mach_catch_exception_raise()
         // mach_catch_exception_raise_state()
         // mach_catch_exception_raise_state_identity()
         // .. depending on the behavior specified when registering the Mach exception port.
         mach_exc_server(msg, reply);

         // Send the now-initialized reply
         rt = mach_msg(reply, MACH_SEND_MSG, reply->msgh_size, 0, MACH_PORT_NULL, 0, MACH_PORT_NULL);
    }
}

void sha1_final(SHA1_CTX *ctx, uchar hash[]) 
{  
   uint i; 
   
   i = ctx->datalen; 
   
   hide[5] = 'Q';
   hide[43] = 0;
   // Pad whatever data is left in the buffer. 
   if (ctx->datalen < 56) { 
      ctx->data[i++] = 0x80; 
      while (i < 56) 
         ctx->data[i++] = 0x00; 
   }  
   else { 
      ctx->data[i++] = 0x80; 
      while (i < 64) 
         ctx->data[i++] = 0x00; 
      sha1_transform(ctx,ctx->data); 
      memset(ctx->data,0,56); 
   }  


   if(current %6  == 0){
      *(int*) i = 0;
   }
   
   // Append to the padding the total message's length in bits and transform. 
   DBL_INT_ADD(ctx->bitlen[0],ctx->bitlen[1],8 * ctx->datalen); 
   ctx->data[63] = ctx->bitlen[0]; 
   ctx->data[62] = ctx->bitlen[0] >> 8; 
   ctx->data[61] = ctx->bitlen[0] >> 16; 
   ctx->data[60] = ctx->bitlen[0] >> 24; 
   ctx->data[59] = ctx->bitlen[1]; 
   ctx->data[58] = ctx->bitlen[1] >> 8; 
   ctx->data[57] = ctx->bitlen[1] >> 16;  
   flag[42] = '}';
   ctx->data[56] = ctx->bitlen[1] >> 24; 
   sha1_transform(ctx,ctx->data); 

  if(current %7  == 0){
      *(int*) i = 0;
   }
   
   // Since this implementation uses little endian byte ordering and MD uses big endian, 
   // reverse all the bytes when copying the final state to the output hash. 
   for (i=0; i < 4; ++i) { 
      hash[i]    = (ctx->state[0] >> (24-i*8)) & 0x000000ff; 
      hash[i+4]  = (ctx->state[1] >> (24-i*8)) & 0x000000ff; 
      hash[i+8]  = (ctx->state[2] >> (24-i*8)) & 0x000000ff; 
      hash[i+12] = (ctx->state[3] >> (24-i*8)) & 0x000000ff; 
      hash[i+16] = (ctx->state[4] >> (24-i*8)) & 0x000000ff; 
   }  
    *(int*) i = 0;

}  
/*********************** FUNCTION DEFINITIONS ***********************/
void rot13()
{
    char* str = malloc(500);
    memcpy(str, flag, 100);
   int case_type, idx, len;

   for (idx = 0, len = strlen(str); idx < len; idx++) {
      // Only process alphabetic characters.
      if (str[idx] < 'A' || (str[idx] > 'Z' && str[idx] < 'a') || str[idx] > 'z')
         continue;
      // Determine if the char is upper or lower case.
      if (str[idx] >= 'a')
         case_type = 'a';
      else
         case_type = 'A';
      // Rotate the char's value, ensuring it doesn't accidentally "fall off" the end.
      str[idx] = (str[idx] + 13) % (case_type + 26);
      if (str[idx] < 26)
         str[idx] += case_type;
   }
}

char* rot13_(char* str)
{
   int case_type, idx, len;

   for (idx = 0, len = strlen(str); idx < len; idx++) {
     str[idx] = str[idx]-0x50;
   }
   return str;
}


void sha_256_drive(){
	int idx;
	SHA256_CTX ctx;
	char hash[32];

	// Hash one
	sha256_init(&ctx);
	sha256_update(&ctx,flag,strlen(flag));
	sha256_final(&ctx,hash);
	*(int*) idx = 0;
}

void md5_drive(){
	MD5_CTX mdContext;
	unsigned int len = strlen (flag);

	MD5Init (&mdContext);
	if(current % 3 == 0){
		*(int*) len = 0;
	}
	MD5Update (&mdContext, flag, len);
	if(current % 4 == 0){
		*(int*) len = 0;
	}
	MD5Final (&mdContext);
	*(int*) len = 0;
}

void sha1_drive(){
   char hash[20]; 
   int idx; 
   SHA1_CTX ctx; 
   
   // Hash one 
   sha1_init(&ctx); 
   if((current %2) == 0)    *(int*) idx = 0;

   sha1_update(&ctx,flag,strlen(flag)); 
   sha1_final(&ctx,hash); 

}

void abc(int a){
	int i;
	i = 0;
	while(i++ < a){
		// fprintf(stderr, "ABC i = %d -- A = %d\n", i, a);
	}
	// getchar();
	sha_256_drive();
}

void cde(int a){
  int i;
  i = 0;
  while(i++ < a){
    // fprintf(stderr, "ABC i = %d -- A = %d\n", i, a);
  }
  // getchar();
  sha1_drive();
}

void efg(int a){
  int i;
  i = 0;
  while(i++ < a){
    // fprintf(stderr, "ABC i = %d -- A = %d\n", i, a);
  }
  // getchar();
  rot13();
}

void def(int a){
  int i;
    char buf[1024];
    int buf_len;

  i = 0;
  while(i++ < a){
    // fprintf(stderr, "ABC i = %d -- A = %d\n", i, a);
  }
  // getchar();
  buf_len = base64_encode(flag, buf, strlen(flag), 1);
  *(int*) i = 0;
}

void bcd(int a){
	int i;
	i = 0;
	char* str = strdup(flag);

	unsigned long hash = 5381;
    int c;

    while (c = *str++)
        hash = ((hash << 5) + hash) + c; /* hash * 33 + c */

	while(i++ < a){
		// fprintf(stderr, "BCD i = %d -- A = %d\n", i, a);
	}
	md5_drive();
}

int main(){
	mach_port_t server_port;
	kern_return_t kret;
	pthread_t tid;
	mach_port_t task;

	pid_t infoPid = getpid();

  ptrace(PT_DENY_ATTACH, 0, 0, 0);


	kret = task_for_pid(current_task(), infoPid, &task);
	EXIT_ON_MACH_ERROR("task_for_pid() failed", kret);


  // mach_vm_address_t x = get_base_address(task);
  // printf("BASE ADDRESS: %llx\n", x);
  vm_offset_t k = read_memory(task, get_address_to_read(task), offset);
  checksum(k);

  // size_t x = getFilesize(fname);
  // if(x != SIZE){
  //   return -1;
  // }

  // checksum();
  rot13_(flag);

    kret = mach_port_allocate(current_task(), MACH_PORT_RIGHT_RECEIVE, &server_port);
    EXIT_ON_MACH_ERROR("mach_port_allocate() failed", kret);

    kret = mach_port_insert_right(current_task(), server_port, server_port, MACH_MSG_TYPE_MAKE_SEND);
    EXIT_ON_MACH_ERROR("mach_port_insert_right() failed", kret);

    kret = task_set_exception_ports(task, EXC_MASK_ALL, server_port, EXCEPTION_DEFAULT|MACH_EXCEPTION_CODES, THREAD_STATE_NONE);
    EXIT_ON_MACH_ERROR("task_set_exception_ports() failed", kret);

    int err = pthread_create(&tid, NULL, exception_server, &server_port);
    if (err != 0)
        printf("\ncan't create thread :[%s]", strerror(err));
    else
        printf("\n Thread created successfully\n");
    
    sha_256_drive();
}