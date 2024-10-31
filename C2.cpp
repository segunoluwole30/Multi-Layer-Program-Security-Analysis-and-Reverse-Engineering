#include <random>
#include <iostream>
#include <csignal>
#include <sys/ptrace.h>

long long bs1 = 0x0f2bc3ee05faa249;
long long bs2 = 0x70DD85D8FE63E152;
long long bs3 = 0xFCC7752FDB865D11;
long long bs4 = 0x51982D5DCF0B2489;

//interrupt handler for ctrl+c, we can clean up nicely here and not leave atifacts from running on the system
void handle_sigint(int signal){
    printf("Shutting down gracefully");
    exit(0);
}

//can use this function to fuck with them and hide which key gets generated
int gen_key(){
    return 1000;
}

int gen_seed(){

    return 500;
}

/*
Made this a global variable so we can generate a random number at random points and not make it as clear where the generation
starts for the stream_encrypt function
*/
std::mt19937 prng(gen_key());

int sum(int a, int b){
    prng();
    return a + b;
}

int pow(int a, int b){
    int total = 0;
    for(int i = 0; i < b; i++){
        for(int j = 0; j < a; j++){
            total += sum(a, a);
        }
    }
    return total;
}

//Stream encrypt function that relies on a psudeo random number generator and XOR to generate a ciphertxt from a plain txt
void stream_encrypt(char* plaintxt, char* ciphertxt, unsigned int key){
    int index = 0;
    while(*plaintxt != '\0'){
        char byte = prng() % 256;
        ciphertxt[index] = *plaintxt ^ byte;
        plaintxt++;
        index++;
    }
    ciphertxt[index] = '\0';
}

//allegedly this will detect if a debugger is already attached to the program
// bool is_debugger_attached() {
//     // Attempt to attach to the current process
//     if (ptrace(PTRACE_ATTACH, getppid(), 1, 0) == -1) {
//         // If we can't attach, a debugger is likely present
//         if (errno == EPERM) {
//             return true; // Debugger is attached
//         }
//     }
//     return false; // No debugger detected
// }


int main(){
    //detect debugger
    // if(is_debugger_attached()){
    //     //system("shutdown&");
    //     printf("Debugger detected");
    // }

    // Register the signal handler
    signal(SIGINT, handle_sigint);

    char* pt = "WhyHelloThere\0";
    char ct[15];

    stream_encrypt(pt, ct, 1000);

    printf("%s", ct);

    // for(;;){

    // }

    return 0;
}