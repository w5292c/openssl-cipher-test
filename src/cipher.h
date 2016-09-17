#ifndef W5292C_CIPHER_H
#define W5292C_CIPHER_H

#include <string>

std::string mcode_encode(const std::string &key, const std::string &data);
std::string mcode_decode(const std::string &key, const std::string &data);

#endif /* W5292C_CIPHER_H */
