/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2016 Alexander Chumakov
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#include "cipher.h"

#include <assert.h>
#include <iostream>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>

static const uint8_t TheIVec[] = {
  0xa7, 0xc1, 0xcc, 0x0f, 0x8b, 0xe6, 0x80, 0xe4,
  0xe7, 0xab, 0x03, 0x11, 0xa1, 0xe4, 0x26, 0x12,
};

using namespace std;

string mcode_encode(const string &key, const string &data)
{
  /* Prepare the initial vector */
  uint8_t ivec[AES_BLOCK_SIZE];
  memcpy(ivec, TheIVec, AES_BLOCK_SIZE);

  /* Prepare the encoding key */
  int res;
  AES_KEY encodingKey;
  res = AES_set_encrypt_key((const uint8_t *)key.data(), 8*key.length(), &encodingKey);
  if (res) {
    cerr << "Error: cannot set encoding key, code: " << res << endl;
    return string();
  }

  /* Apply the ['\x80', N x '\x00'] padding */
  string paddedData = data;
  paddedData.append(1, '\x80');
  paddedData.append(AES_BLOCK_SIZE - (paddedData.length() % AES_BLOCK_SIZE), '\x00');

  /* Apply AES CBC encryption */
  const size_t paddedDataLength = paddedData.length();
  assert(0 == (paddedDataLength % AES_BLOCK_SIZE));
  uint8_t *const buffer = (uint8_t *)calloc(1, paddedDataLength);
  AES_cbc_encrypt((const uint8_t *)paddedData.data(), buffer, paddedDataLength, &encodingKey, ivec, AES_ENCRYPT);

  /* Prepare the result */
  const string result((const char *)buffer, paddedDataLength);
  free(buffer);

  return result;
}

string mcode_decode(const string &key, const string &data)
{
  const size_t dataLength = data.length();
  if (0 != (dataLength % AES_BLOCK_SIZE)) {
    cerr << "Error: input data is not block-length aligned, length: " << dataLength << endl;
    return string();
  }

  /* Prepare the initial vector */
  uint8_t ivec[AES_BLOCK_SIZE];
  memcpy(ivec, TheIVec, AES_BLOCK_SIZE);

  /* Prepare the encoding key */
  int res;
  AES_KEY decodingKey;
  res = AES_set_decrypt_key((const uint8_t *)key.data(), 8*key.length(), &decodingKey);
  if (res) {
    cerr << "Error: cannot set decoding key, code: " << res << endl;
    return string();
  }

  /* Apply the AES CBC decryption */
  uint8_t *const buffer = (uint8_t *)calloc(1, data.length());
  AES_cbc_encrypt((const uint8_t *)data.data(), buffer, dataLength, &decodingKey, ivec, AES_DECRYPT);

  /* Parse and remove the padding data */
  string result((const char *)buffer, dataLength);
  free(buffer);

  const size_t marker = result.find_last_of('\x80');
  const size_t padding = result.find_last_not_of('\x00');
  if (marker != padding || dataLength - padding > AES_BLOCK_SIZE + 1) {
    cerr << "Error: wrong padding info in the input data" << endl;
    return string();
  }
  result.resize(marker);

  return result;
}
