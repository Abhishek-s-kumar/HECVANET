// #ifndef HELPERS_H 
// #define HELPERS_H

// #include <unistd.h>
// #include <cstdlib>
// #include <cstring>

// void vli_print(uint8_t *vli, unsigned int size) {
//     for(unsigned i=0; i<size; ++i) {
//         printf("%02X ", (unsigned)vli[i]);
//     }
// }

// void swap_endian(uint8_t* buffer, size_t size) {
//     size_t i = 0;
//     size_t j = size - 1;
//     while (i < j) {
//         uint8_t tmp = buffer[i];
//         buffer[i] = buffer[j];
//         buffer[j] = tmp;
//         i++;
//         j--;
//     }
// }

// ZZ_p squareRoot(ZZ_p n, ZZ p)
// {
//     if (p % 4 != 3) {
//         cout << "Invalid Input";
//         return to_ZZ_p(to_ZZ(0));
//     }

//     bool ok1 = false;
 
//     ZZ_p x1 = power(n, (p + 1) / 4);
//     if ((x1 * x1) == n) {
//         //cout << "Square root is " << x;
//         ok1 = true;
//     }
 
//     // Try "-(n ^ ((p + 1)/4))"
//     ZZ_p x2 = - x1;
//     if(ok1 && rep(x1) < rep(x2))
//         return x1;

//     if ((x2 * x2) == n) {
//         //cout << "Square root is " << x; 
//         return x2;
//     }

//     return to_ZZ_p(to_ZZ(0));
 
//     // If none of the above two work, then
//     // square root doesn't exist
//     //cout << "Square root doesn't exist ";
// }

// bool isAscii(const char* bytes, int len) {
//     for (int i = 0; i < len; i++) {
//         if (bytes[i] < 0 || bytes[i] > 127) {
//             return false;
//         }
//     }
//     return true;
// }

// uint8_t* find_string(ZZ_p val1, ZZ_p val2, int size, int mode=0) {
//     uint8_t *str = new uint8_t[size];
//     ZZ sol1, sol2, sol3, sol4;

//     sol1 = rep(val1);
//     sol2 = rep(-val1);
//     sol3 = rep(val2);
//     sol4 = rep(-val2);

//     NTL::BytesFromZZ(str, sol1, size);
//     bool flag = isAscii((char*)str, size); 
//     if(mode)
//         flag = flag && (str[0] == '1' || str[0] == '2' || str[0] == '3');
//     if(flag) {
//         return str;
//     }

//     NTL::BytesFromZZ(str, sol2, size);
//     flag = isAscii((char*)str, size);
//     if(mode)
//         flag = flag && (str[0] == '1' || str[0] == '2' || str[0] == '3');
//     if(flag) {
//         return str;
//     }

//     NTL::BytesFromZZ(str, sol3, size);
//     flag = isAscii((char*)str, size);
//     if(mode)
//         flag = flag && (str[0] == '1' || str[0] == '2' || str[0] == '3');
//     if(flag) {
//         return str;
//     }

//     NTL::BytesFromZZ(str, sol4, size);
//     flag = isAscii((char*)str, size);
//     if(mode)
//         flag = flag && (str[0] == '1' || str[0] == '2' || str[0] == '3');
//     if(flag) {
//         return str;
//     }

//     memset(str, '0', size);
//     return str;
// }

// #endif