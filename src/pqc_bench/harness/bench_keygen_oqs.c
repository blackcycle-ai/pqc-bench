/* bench_keygen_oqs.c — keypair-gen latency via liboqs (for the aarch64 datapoint).
 * Usage: bench_keygen_oqs <ALG> <N> <WARMUP> <OUT.csv>  (ALG e.g. "ML-DSA-44","Falcon-512") */
#define _POSIX_C_SOURCE 199309L
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <oqs/oqs.h>
static inline uint64_t now_ns(void){ struct timespec t; clock_gettime(CLOCK_MONOTONIC,&t);
    return (uint64_t)t.tv_sec*1000000000ULL+(uint64_t)t.tv_nsec; }
int main(int argc,char**argv){
    if(argc!=5){ fprintf(stderr,"usage: %s <ALG> <N> <WARMUP> <OUT.csv>\n",argv[0]); return 2; }
    OQS_SIG*s=OQS_SIG_new(argv[1]); if(!s){ fprintf(stderr,"alg not enabled\n"); return 1; }
    long N=atol(argv[2]),warm=atol(argv[3]);
    uint8_t*pk=malloc(s->length_public_key),*sk=malloc(s->length_secret_key);
    uint64_t*ns=malloc(sizeof(uint64_t)*N);
    for(long i=0;i<warm+N;i++){ uint64_t t0=now_ns(); OQS_SIG_keypair(s,pk,sk); uint64_t t1=now_ns();
        if(i>=warm) ns[i-warm]=t1-t0; }
    FILE*f=fopen(argv[4],"w"); fprintf(f,"iter,keygen_ns\n");
    for(long i=0;i<N;i++) fprintf(f,"%ld,%llu\n",i,(unsigned long long)ns[i]); fclose(f);
    printf("{\"alg\":\"%s\",\"N\":%ld,\"op\":\"keygen\"}\n",argv[1],N);
    return 0;
}
