/*
 * Copyright 2011 Google Inc.
 * Copyright 2018 Andreas Schildbach
 *
 * From https://github.com/bitcoinj/bitcoinj/blob/master/core/src/main/java/org/bitcoinj/core/Base58.java
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Re-written in Kotlin by Pablo Baxter
 */

package com.frybits.atproto.crypto.utils

private val ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".toCharArray()
private val ENCODED_ZERO = ALPHABET[0]
private val INDEXES = IntArray(128).also { index ->
    ALPHABET.forEachIndexed { i, c ->
        index[c.code] = i
    }
}

/**
 * Encodes the given bytes as a base58 string (no checksum is appended).
 *
 * @param ByteArray the bytes to encode
 * @return the base58-encoded string
 */
internal fun ByteArray.encodeToBase58() : String {
    if (isEmpty()) {
        return ""
    }

    var zeros = 0
    while (zeros < size && get(zeros).toInt() == 0) {
        ++zeros
    }

    val inputCopy = copyOf()
    val encoded = CharArray(inputCopy.size * 2)
    var outputStart = encoded.size
    var inputStart = zeros
    while (inputStart < inputCopy.size) {
        encoded[--outputStart] = ALPHABET[divmod(inputCopy, inputStart, 256, 58).toInt()]
        if (inputCopy[inputStart] == 0.toByte()) {
            ++inputStart
        }
    }

    // Preserve exactly as many leading encoded zeros in output as there were leading zeros in input.
    while (outputStart < encoded.size && encoded[outputStart] == ENCODED_ZERO) {
        ++outputStart
    }
    while (--zeros >= 0) {
        encoded[--outputStart] = ENCODED_ZERO
    }

    return String(encoded, outputStart, encoded.size - outputStart);
}

/**
 * Decodes the given base58 string into the original data bytes.
 *
 * @param String the base58-encoded string to decode
 * @return the decoded data bytes
 */
internal fun String.decodeBase58() : ByteArray {
    if (isEmpty()) {
        return byteArrayOf()
    }

    val input58 = ByteArray(length)
    forEachIndexed { i, c ->
        val digit = if (c.code < 128) INDEXES[c.code] else -1
        require(digit >= 0) { String.format("Invalid character in Base58: 0x%04x", c) }
        input58[i] = digit.toByte()
    }
    var zeros = 0
    while (zeros < input58.size && input58[zeros].toInt() == 0) {
        ++zeros
    }
    val decoded = ByteArray(length)
    var outputStart = decoded.size
    var inputStart = zeros
    while (inputStart < input58.size) {
        decoded[--outputStart] = divmod(input58, inputStart, 58, 256)
        if (input58[inputStart] == 0.toByte()) {
            ++inputStart
        }
    }

    while (outputStart < decoded.size && decoded[outputStart].toInt() == 0) {
        ++outputStart;
    }

    return decoded.copyOfRange(outputStart - zeros, decoded.size)
}

/**
 * Divides a number, represented as an array of bytes each containing a single digit
 * in the specified base, by the given divisor. The given number is modified in-place
 * to contain the quotient, and the return value is the remainder.
 *
 * @param number the number to divide
 * @param firstDigit the index within the array of the first non-zero digit
 *        (this is used for optimization by skipping the leading zeros)
 * @param base the base in which the number's digits are represented (up to 256)
 * @param divisor the number to divide by (up to 256)
 * @return the remainder of the division operation
 */
private fun divmod(number: ByteArray, firstDigit: Int, base: Int, divisor: Int) : Byte {
    var remainder = 0
    var i = firstDigit
    while (i < number.size) {
        val digit = number[i].toInt() and 0xFF
        val temp = remainder * base + digit
        number[i] = (temp/divisor).toByte()
        remainder = temp % divisor
        ++i
    }
    return remainder.toByte()
}
