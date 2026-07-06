/*
 * bench_keygen.c — keypair-generation latency via EVP (homogeneous stack).
 * Falcon keygen (lattice trapdoor sampling) is the expensive one this exposes.
 * Usage: bench_keygen <ALG> <N> <WARMUP> <OUT.csv>   (ALG as in bench_sign)
 */
#define _POSIX_C_SOURCE 199309L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/evp.h>
#include <openssl/provider.h>

static inline uint64_t now_ns(void){ struct timespec t; clock_gettime(CLOCK_MONOTONIC,&t);
    return (uint64_t)t.tv_sec*1000000000ULL+(uint64_t)t.tv_nsec; }
static int is_ecdsa(const char*a){ return strcmp(a,"EC")==0; }

int main(int argc,char**argv){
    if(argc!=5){ fprintf(stderr,"usage: %s <ALG> <N> <WARMUP> <OUT.csv>\n",argv[0]); return 2; }
    const char*alg=argv[1]; long N=atol(argv[2]),warm=atol(argv[3]); const char*out=argv[4];
    OSSL_PROVIDER_load(NULL,"default"); OSSL_PROVIDER_load(NULL,"oqsprovider");
    uint64_t*ns=malloc(sizeof(uint64_t)*N);
    for(long i=0;i<warm+N;i++){
        uint64_t t0=now_ns();
        EVP_PKEY_CTX*c=EVP_PKEY_CTX_new_from_name(NULL,alg,NULL);
        EVP_PKEY_keygen_init(c);
        if(is_ecdsa(alg)) EVP_PKEY_CTX_set_group_name(c,"P-256");
        EVP_PKEY*k=NULL; EVP_PKEY_keygen(c,&k);
        uint64_t t1=now_ns();
        EVP_PKEY_free(k); EVP_PKEY_CTX_free(c);
        if(i>=warm) ns[i-warm]=t1-t0;
    }
    FILE*f=fopen(out,"w"); fprintf(f,"iter,keygen_ns\n");
    for(long i=0;i<N;i++) fprintf(f,"%ld,%llu\n",i,(unsigned long long)ns[i]);
    fclose(f);
    printf("{\"alg\":\"%s\",\"N\":%ld,\"op\":\"keygen\",\"out\":\"%s\"}\n",alg,N,out);
    free(ns); return 0;
}
