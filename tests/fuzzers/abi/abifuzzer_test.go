// Copyright 2020 The go-ehtereum Authors
// Copyright 2023 Terminos Network
// This file is part of the tos library.
//
// The tos library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The tos library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the tos library. If not, see <http://www.gnu.org/licenses/>.

package abi

import (
	"testing"
)

// TestReplicate can be used to replicate crashers from the fuzzing tests.
// Just replace testString with the data in .quoted
func TestReplicate(t *testing.T) {
	testString := "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00 \x00\x00\x00\x00\x00\x00\x00\x00" +
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
		"\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00000000000" +
		"00000000000000000000" +
		"00000000000000000000" +
		"00000001"

	data := []byte(testString)
	runFuzzer(data)
}

// TestGenerateCorpus can be used to add corpus for the fuzzer.
// Just replace corpusHex with the hexEncoded output you want to add to the fuzzer.
func TestGenerateCorpus(t *testing.T) {
	/*
		corpusHex := "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
		data := common.FromHex(corpusHex)
		checksum := sha1.Sum(data)
		outf := fmt.Sprintf("corpus/%x", checksum)
		if err := ioutil.WriteFile(outf, data, 0777); err != nil {
			panic(err)
		}
	*/
}
