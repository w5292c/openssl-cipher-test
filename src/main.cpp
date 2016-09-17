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

#include <iostream>

#include <errno.h>
#include <stdio.h>
#include <assert.h>
#include <openssl/bn.h>

const char TheTestKey[] = {
  0x55, 0x8c, 0x50, 0xbd, 0xe3, 0x5c, 0x71, 0x52,
  0x2a, 0x0f, 0x26, 0xdc, 0x84, 0x00, 0xf4, 0xa9,
  0xe0, 0xa0, 0xac, 0x2a, 0xc6, 0xbf, 0x08, 0x28,
  0xbf, 0x21, 0xc4, 0x4e, 0x2e, 0xb7, 0x99, 0xbb,
};
const char TheTestText[] = "Hello! This is a test [\000] text [\n] that [\r] goes to my magic cipher and then resotres in the decoding method.";

using namespace std;

int main(int argc, char **argv)
{
  const std::string key(TheTestKey, sizeof (TheTestKey));
  cout << "Key length: " << key.length() << endl;

  const std::string text(TheTestText, sizeof (TheTestText));
  cout << "Original text length: " << text.length() << endl;

  const std::string &encoded = mcode_encode(key, text);
  cout << "Encoded data length: " << encoded.length() << endl;

  const std::string &decoded = mcode_decode(key, encoded);
  cout << "Decoded data length: " << decoded.length() << endl;

  cout << "Original text: [" << text << "]" << endl;
  cout << "Restored text: [" << decoded << "]" << endl;

  return 0;
}
