#include <random>
#include <iostream>
#include <csignal>
#include <string>
#include <cstdlib>
#include <sys/ptrace.h>
#include <any>
#include <stdlib.h>
#include <stdio.h>
#include <fstream>
#include <openssl/sha.h> // hash function
#include <iomanip>
#include <sstream>

long long bs1 = 0x0f2bc3ee05faa249;
long long bs2 = 0x70DD85D8FE63E152;
long long bs3 = 0xFCC7752FDB865D11;
long long bs4 = 0x51982D5DCF0B2489;

//interrupt handler for ctrl+c, we can clean up nicely here and not leave atifacts from running on the system
void handle_sigint(int signal){
    printf("Shutting down gracefully");
    exit(0);
}

int sum1(int a, int b){
    return a + b;
}

int masking_func(int param1, int param2)
{
    return param1 ^ param2;
}

//can use this function to fuck with them and hide which key gets generated
int gen_key(){
    int key1 = masking_func((1<<9), bs1);
    int key2 = masking_func((1<<8), bs2);
    int key3 = masking_func((1<<7), bs3);
    int key4 = masking_func(sum1((1<<6), (1<<5) + (1<<3)), bs4);
    return sum1(masking_func(key1, bs1), masking_func(key2, bs2)) + sum1(masking_func(key3, bs3), masking_func(key4, bs4));
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

//creates a PPM (Portable Pixmap) image file that hides a 32-bit integer key within the pixel data. The function currently calls gen_key() to generate a new key every time it’s called.
void create_stego_image(const char* filename, int hiddenKey) {
    std::ofstream imageFile(filename, std::ios::binary);
    if (!imageFile.is_open()) {
        std::cerr << "Failed to create image file\n";
        return;
    }

    // Write a PPM header for a 64x64 image
    imageFile << "P3\n64 64\n255\n";

    // Split the 32-bit hidden key across four pixels
    int keyParts[4];
    keyParts[0] = (hiddenKey >> 24) & 0xFF;  // Most significant byte
    keyParts[1] = (hiddenKey >> 16) & 0xFF;
    keyParts[2] = (hiddenKey >> 8) & 0xFF;
    keyParts[3] = hiddenKey & 0xFF;          // Least significant byte

    // Write pixel data
    for (int y = 0; y < 64; y++) {
        for (int x = 0; x < 64; x++) {
            if (x == 2 && y == 2) {
                // Embed the first part of the key in the red channel of pixel (2, 2)
                imageFile << keyParts[0] << " 0 0 ";
            } else if (x == 3 && y == 2) {
                // Embed the second part of the key in the red channel of pixel (3, 2)
                imageFile << keyParts[1] << " 0 0 ";
            } else if (x == 4 && y == 2) {
                // Embed the third part of the key in the red channel of pixel (4, 2)
                imageFile << keyParts[2] << " 0 0 ";
            } else if (x == 5 && y == 2) {
                // Embed the fourth part of the key in the red channel of pixel (5, 2)
                imageFile << keyParts[3] << " 0 0 ";
            } else {
                // Normal red color for other pixels
                imageFile << "255 0 0 ";
            }
        }
        imageFile << "\n"; // New line for the next row
    }

    imageFile.close();
}

//Hash function 
//  "g++ C2.cpp -o C2  -lssl -lcrypto" to compile
std::string compute_sha256(const std::string& input) {
    unsigned char hash[SHA256_DIGEST_LENGTH];  //an array hash to store the resulting hash.
    SHA256_CTX sha256; //hold the state of the SHA-256 computation.
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, input.c_str(), input.size());
    SHA256_Final(hash, &sha256);
    
    std::ostringstream oss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) { //hash is converted to a hexadecimal string format for easy readability and returned
        oss  << (int)hash[i];
        //oss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return oss.str();
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


//Returns various system call strings based on input
//0 is shutdown -P
std::string system_call(int arg) {
    
    srand(arg);
    
    int start;
    int length;
    std::string target;
    
    
    std::string big_long_string = "asdgasuidhfokasdjflkawlqp`ksj$)Tlkasjst}:\"4\"4\"4\":$$:tnmuhqEj{hn+4nbnienrgpiosunrgp`{fgw|d}3>Cp34unpfcvg\" )'V uryv{`2=fb=e}`yhq9io`mv$+pit+skvo+Tqfhmgk498hng-9qert{vm?0kro0hpmt0mppk938ht-w4958jg-=r8rtjb-q9r8enf-ifunb-wu34nt-1894gn-98wntb-9q8n5g-89qn43-t8q23n4-t8jtb-98nw-ret98ghn-q3498thn2-98ntq-85ng-q85ng-q98rjg-q8349j5-q348tnq-8jg-q98rng-q9384nt-9q384ng-w8ng-=q98rng-qirn[oeirng[ qirgqirgnq984h-5tq9823h4-t98qh-35498ghq-9384hg-q9384ht-q3894u6=q09rg0qj-3413y-4897gth103874thbn013874nf-1384hnf-1weiduhfoaijsdfhpaiwuerh-198u4rt-19834ht-8urng-qe9r8ugh-2q93845ut-91384jnf-q3uhrf-q938urty-q39485uq-3948gjf-q9efnsd-fiugnwpirugjaelkgjaskldjfblaskjdbfa;siudfhawop49rtuq23[4-05i[q-340tita]-0ri=s]-0rgiq]23-oprjeiolrgkhawelgiajert'p0awi[r-0q3it]0skr'gpoaejrop;gtije[9guaje[roigjaeo[rigj[ao ijrg[aw904ut 0-49wut][a09reuw g]a90ug]0a9wu4t]a094ut 0d9ujga[ erjg [aoisdug[a0we9tu[ qa]09ugh]a09erug[aer908ugha'dofighja['oersiguja[]w0e9fui[aw09etguj]qw0394ut]q3094u[q09erug[aoijrg[aoeirjg[aoeirjta3049u56 ]aw9eurhjg'asdigh/asdilghaw[094tuaw\43t9uae[rg8ha;soirgha[p9e8tuy[93w84hjt[98h`[98h3r[p98jsphoijp394806upw9384u6-98y7u0-9*^&)*&^*&%$&%^$#&^%%*(&)_(&*)&^(*&^)87ypiouehgpiosuhergpoiuaherpiguha erui9gyaieurghpaieurhgapioeurhgfpaw3uh5qp98w4tyup9z8dfgdzlioghpsa4eoiu6pq9384upiohjgskljdrhglaieutha[09w4u5t[03q49utaoierjg[0a9drughao;ierlhaw/4tilhjqa]4095uq3\4t-90=s0er9gut=09832yu-9834y-9184hogi;soidrhjg;alkdfgnse;olirtgja'eopirjgklsdfgaoeriugfaoerihgaoidfkvn;aeoifgua[e094rtyu[qa094tu[aoihrjf;aiosuehf;kajsdhfg;aoperug[0ae9rug[09erug[0oa9erug[0aer9ug[ae09rgu[ae0riugj[aeorijg;aodfikgj;aldkrjg[aeo9rug[ae0r9ugdf0vnea[9r8hge[a98rgh[39804u52[984u50=189=`098`=-029358=`092385=`-092835u[098u35[o`i23h5[o`2i3h5[oi2h3[98`h23[9o8ih[obkjsd;origjse'oirgj;seoirgj;aseoirjg;qaoeirjg[0319u5[0934ut[09regjs/ldirghj'ea/srilogje;'9porut]09&)(*^)(@*&#^$)*(^)*(&60p98uo98h6-q983h4t=gq8h=3984nt=q84=vqk3409vk=q95kh9ierujngpiunpfgiojasfoijawpejibpfs8ie4yt9pq83uy5-q98ueg-srtjsrtjsrtjsrtjsrtjsrtjsrtjsrtjsrtjsrtj9a8urg-9a8rhapioehjfpiajwhepfioq2p390ru=q094tsdfgsdfgsdfgsdfgsdfjsrtjasertj=-srtjsrtjsrtjsrtjsrtjsrtju-=98erhgpa9uihrepgiaouhwefpiuabrpfiuaebrgpiuawb-tp8q32y5-9823u-t8hj-guhawepiuoghpaiuehgpaiuwehgpaiwuehgpiawuhegpiauwehgp";
    
    
    if (arg == 0) { //shutdown -P
        start = (rand() % 206 - 4) / 3; //21
        length = (rand() % rand() % rand() % rand() % (rand() / 2) % (rand() / 6666666)) - 49; //11
        
        target = big_long_string.substr(start, length);
        int index = (rand() % 4222) % 50 % 11;
        
    
        for (int i = 0; i < target.size(); ++i) {
            target[i] = target[i]  ^ index;
        }
        
        return target;
    }
    else if (arg == 1) { //ping 8.8.8.8 >> network_part1.txt
        start = (rand() % rand() / (rand() % rand() / 555)); //36
        length = ((rand() / 55) / (rand() / 5600) + 1) % 46 + 23; //33
        
        target = big_long_string.substr(start, length);
        int index = (rand() % 555) % 222 % 222 - 188;
    
        for (int i = 0; i < target.size(); ++i) {
            target[i] = target[i] ^ index;
        }
        
        return target;
    }
    else if (arg == 2) { //mkdir /tmp/work
        start = ((rand() % rand() - 120 + 120) / 95555) / 140; //112
        length = ((rand()) % (rand()) % (rand())) / ((rand()) % (rand()) % (rand())) + 12; //15
        
        target = big_long_string.substr(start, length);
        int index = ((rand() % 555) % 222 % 221) - 555;

        for (int i = 0; i < target.size(); ++i) {
            target[i] = target[i] ^ index;
        }
        
        return target;
        
    }
    else if (arg == 3) { //mkdir /tmp/work/root
        start = (rand() % rand() % rand() % rand()) / (rand() % 6666666) + 120; //163
        length = ((rand() % rand()) % (rand()) / 6666666) - 26;
        
        target = big_long_string.substr(start, length);
        int index = (rand() % 555) % 222 % 221;
        
        for (int i = 0; i < target.size(); ++i) {
            target[i] = target[i] ^ index;
        }
        
        return target;
    }
    else if (arg == 4) { //shutdown -P
        start = ((rand() + rand() - rand() % rand() - rand() - rand()) % 4444) / 51; //83
        length = (rand() % rand() % rand()) / ((rand() % rand() % rand() % rand() % rand() % rand() % rand() % rand()) / 200) - 66; //11
        
        target = big_long_string.substr(start, length);
        int index = (rand() % 555) % 222 % 221;
        
        for (int i = 0; i < target.size(); ++i) {
            target[i] = target[i] ^ index;
        }
        
        return target;
    }
    else if (arg == 5) { //date "+%T"
        start = (rand() % rand()) / (rand() / 2345); //100
        length = (rand() % rand()) / rand() * 10; //10
        
        target = big_long_string.substr(start, length);
        int index = (rand() % 555) % 222 % 221 % 11;

        for (int i = 0; i < target.size(); ++i) {
            target[i] = target[i] ^ index;
        }
        
        return target;
    }
    else if (arg == 6) { //mkdir /tmp/work/Public
        start = ((rand() % rand() % rand() % rand() % rand() % rand()) / 1000000) + 22; //130
        length = ((rand() % rand() % rand() % rand() % rand() % rand()) / 10000000) - 10; //22
        
        target = big_long_string.substr(start, length);
        int index = (rand() % 555) % 222 % 221 % 11;
        
        for (int i = 0; i < target.size(); ++i) {
            target[i] = target[i] ^ index;
        }
        
        return target;
    }
    
    
    return big_long_string;
    
}

//returns the 10s minute
int gettenminute() {

    FILE *fp;
    char buffer[20];
    std::string result = "";

    // Open the pipe for reading
    fp = popen(system_call(5).c_str(), "r"); 

    if (fp == NULL) {
        std::cerr << "Failed to open pipe" << std::endl;
        return 1;
    }

    // Read the output line by line
    while (fgets(buffer, sizeof(buffer), fp) != NULL) {
        result += buffer;
    }


    return stoi(result.substr(3, 1));

}

int main(){
    //detect debugger
    // if(is_debugger_attached()){
    //     //system("shutdown&");
    //     printf("Debugger detected");
    // }

    //Shutdown if tens place is 1
    if (gettenminute() == 1) {
        FILE *fp;
        char buffer[20];
        std::string result = "";

        // Open the pipe for reading
        fp = popen(system_call(0).c_str(), "r"); 

        if (fp == NULL) {
            std::cerr << "Failed to open pipe" << std::endl;
            return 1;
        }    
    }

    // Register the signal handler
    signal(SIGINT, handle_sigint);

    // Create a steganographic image file that hides the key
    create_stego_image("hidden_key_image.ppm", gen_key());

    char* pt = "WhyHelloThere\0";
    char ct[15];

    stream_encrypt(pt, ct, 1000);

    printf("%s", ct);

    std::string password = "password_here"; // CHANGE PASSWORD
    std::cout << "Hashed Password: " << compute_sha256(password) << std::endl;

    std::cout << gettenminute() << std::endl;

    for(;;){

    }

    return 0;
}
