/*###############################################################################################
#                                                                                              #
# iOS Keychain Decrypter                                                                       #
# inspired by https://github.com/n0fate/iChainbreaker                                          #
# and https://github.com/nabla-c0d3/iphone-dataprotection.keychainviewer/tree/master/Keychain  #
#                                                                                              #
# Copyright Matthieu Regnery 2020                                                              #
#                                                                                              #
# This program is free software: you can redistribute it and/or modify                         #
# it under the terms of the GNU General Public License as published by                         #
# the Free Software Foundation, either version 3 of the License, or                            #
# (at your option) any later version.                                                          #
#                                                                                              #
# This program is distributed in the hope that it will be useful,                              #
# but WITHOUT ANY WARRANTY; without even the implied warranty of                               #
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the                                #
# GNU General Public License for more details.                                                 #
#                                                                                              #
# You should have received a copy of the GNU General Public License                            #
# along with this program.  If not, see <https://www.gnu.org/licenses/>.                       #
###############################################################################################*/


#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include "IOKit.h"

#define kAppleKeyStoreInitUserClient 0
#define kAppleKeyStoreKeyUnwrap 11

CFStringRef keychain_protectionClassIdToString(uint32_t protection_class)
{
    static CFStringRef protectionClasses[] = {
        CFSTR("WhenUnlocked"),
        CFSTR("AfterFirstUnlock"),
        CFSTR("Always"),
        CFSTR("WhenUnlockedThisDeviceOnly"),
        CFSTR("AfterFirstUnlockThisDeviceOnly"),
        CFSTR("AlwaysThisDeviceOnly")
    };
    protection_class &= 0xF;

    if (protection_class >= 6 && protection_class <= 11)
        return protectionClasses[protection_class - 6];
    return CFStringCreateWithFormat(kCFAllocatorDefault, NULL, CFSTR("Unknown protection class %d"), protection_class);
}

int AppleKeyStoreKeyBagInit()
{
    uint64_t out = 0;
    uint32_t one = 1;
    return IOKit_call("AppleKeyStore",
                      kAppleKeyStoreInitUserClient,
                      NULL,
                      0,
                      NULL,
                      0,
                      &out,
                      &one,
                      NULL,
                      NULL);
}

IOReturn AppleKeyStore_keyUnwrap(uint32_t protection_class, const uint8_t* buffer, size_t bufferLen, uint8_t* out)
{
    size_t outputStructCnt = bufferLen+8;
    uint64_t input[2]={0, protection_class};
    
    return IOKit_call("AppleKeyStore",
                    kAppleKeyStoreKeyUnwrap,
                    input,
                    2,
                    buffer,
                    bufferLen,
                    NULL,
                    NULL,
                    out,
                    &outputStructCnt);
}

int main(int argc, char* argv[])
{
    AppleKeyStoreKeyBagInit();
    if (argc == 3) {
        uint32_t keylen = strlen(argv[1])/2;
        unsigned char wrappedKey [keylen];
        const char *pos = argv[1];

        uint32_t keyclass = atoi(argv[2]);

        for (size_t count = 0; count < keylen; count++) {
            sscanf(pos, "%2hhx", &wrappedKey[count]);
            pos += 2;
        }
        uint8_t unwrappedKey [48];
        AppleKeyStore_keyUnwrap(keyclass, &wrappedKey, 40, unwrappedKey);
        
        for(size_t count = 0; count < keylen; count++)
            printf("%02x", unwrappedKey[count]);
    }
    else{
        printf("Usage : keychain key keyclass");
    }

    return 0;
}

