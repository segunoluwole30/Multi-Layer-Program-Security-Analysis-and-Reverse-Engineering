#include <random>
#include <iostream>
#include <csignal>

//interrupt handler for ctrl+c, we can clean up nicely here and not leave atifacts from running on the system
void handle_sigint(int signal){
    printf("Shutting down gracefully");
    exit(0);
}
//can use this function to fuck with them and hide which key gets generated
int gen_key(){
    return 1000;
}

/*
Made this a global variable so we can generate a random number at random points and not make it as clear where the generation
starts for the stream_encrypt function
*/
std::mt19937 prng(gen_key());

//Stream encrypt function that relies on a psudeo random number generator and XOR to generate a ciphertxt from a plain txt
void stream_encrypt(char* plaintxt, char* ciphertxt, unsigned int key){
    int index = 0;
    while(*plaintxt != '\0'){
        char byte = prng() % 256;
        ciphertxt[index] = *plaintxt ^ byte;
        printf("%c : %c\n", *plaintxt, *plaintxt ^ byte);
        plaintxt++;
        index++;
    }
    ciphertxt[index] = '\0';
}


int main(){
    // Register the signal handler
    signal(SIGINT, handle_sigint);

    char* pt = "WhyHelloThere\0";
    char ct[15];

    stream_encrypt(pt, ct, 1000);

    //std::cout << ct << std::endl;
    printf("%s", ct);

    for(;;){

    }

    return 0;
}